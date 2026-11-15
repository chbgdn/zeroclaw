//! The MCP OAuth manager: one per process, shared by every connect path.
//!
//! Canonical state: the encrypted auth-profile store (`super::store`) holds
//! the durable grant; this type adds the live view (current tokens, validated
//! discovery, DCR client id) and the two operations the transport needs:
//! hand out a usable bearer, and react to a 401. Everything else — refresh
//! dedup, background-vs-interactive posture, fail-closed storage — lives
//! here so transports stay thin.
//!
//! Posture recap (design note §12, binding):
//! - background (non-interactive) never binds a callback port and never
//!   launches a browser: a missing grant is an actionable error, and the
//!   transport's fail-open skip keeps the server list alive.
//! - exactly one refresh attempt per caller-visible operation; a rotated
//!   token observed concurrently short-circuits the refresh.
//! - 5xx/429 never clears the stored grant even if the body carried
//!   `invalid_grant`; `invalid_client`/`unauthorized_client` from a
//!   CONFIGURED client id is permanent, not a browser loop.

use anyhow::{Context, Result, bail};
use parking_lot::Mutex;
use reqwest::Url;
use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use zeroclaw_config::schema::McpServerConfig;

use super::browser::{BrowserLauncher, SystemBrowserLauncher};
use super::discovery::{OAuthDiscovery, discover_oauth};
use super::listener::{
    CALLBACK_WAIT_TIMEOUT, CallbackFlow, CallbackVerdict, LoopbackListener, classify_callback_url,
};
use super::pkce::{Pkce, new_state};
use super::policy::OAuthClientFactory;
use super::refresh::RefreshCoordinator;
use super::registration::register_client;
use super::resource::CanonicalResource;
use super::store::McpTokenStore;
use super::tokens::{TokenErrorKind, TokenSet, bearer_header_value, exchange_code, refresh_tokens};

/// A token set with fewer than this many seconds of life left is refreshed
/// before it is handed to a request, so a request cannot be racing expiry.
const REFRESH_SKEW: Duration = Duration::from_secs(60);

/// A live grant: tokens plus the client identity and the ISSUER that
/// obtained them (S3-4: the plan's credential cache is bound to resource
/// AND issuer — a grant minted by AS "A" must never be redeemed at AS "B").
#[derive(Clone)]
struct Grant {
    tokens: TokenSet,
    client_id: String,
    issuer: Url,
}

impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grant")
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer.as_str())
            .field("expires_at", &self.tokens.expires_at)
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.tokens.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// Per-canonical-resource live state. Keyed by the canonical RFC 8707
/// resource: two configured servers sharing a resource share tokens, and a
/// server rename (same URL) keeps working while a URL change starts fresh.
struct ServerState {
    canonical: CanonicalResource,
    factory: OAuthClientFactory,
    config: McpServerConfig,
    discovery: tokio::sync::RwLock<Option<OAuthDiscovery>>,
    grant: tokio::sync::RwLock<Option<Grant>>,
    loaded_from_store: tokio::sync::OnceCell<()>,
}

/// The per-process OAuth manager. Cheap to share (`Arc`); construct once in
/// runtime assembly and hand it to every `connect_all` path.
pub struct McpOAuthManager {
    store: McpTokenStore,
    launcher: Arc<dyn BrowserLauncher>,
    states: Mutex<HashMap<String, Arc<ServerState>>>,
    refresh: RefreshCoordinator,
    /// One-shot paste feed consumed by the next `authorize` (see
    /// [`McpOAuthManager::paste_feed`]); `None` means the stdin fallback
    /// arms only for the explicit admin sign-in (`allow_stdin_paste`) and
    /// only when stdin is a terminal - agent turns never read stdin.
    paste_rx: Mutex<Option<mpsc::Receiver<String>>>,
}

impl std::fmt::Debug for McpOAuthManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpOAuthManager")
            .field("tracked_resources", &self.states.lock().len())
            .finish_non_exhaustive()
    }
}

impl McpOAuthManager {
    /// Construct the shared manager from live config: the state dir and
    /// encryption posture come from the same canonical resolvers the
    /// provider auth stack uses (`state_dir_from_config`, `secrets.encrypt`
    ///), so one encrypted store serves every credential in the process.
    pub fn from_config(config: &zeroclaw_config::schema::Config) -> Result<Self> {
        let state_dir = zeroclaw_providers::auth::state_dir_from_config(config);
        Self::new(&state_dir, config.secrets.encrypt)
    }

    /// Construct the shared manager. Fails closed when encryption is off
    /// (via [`McpTokenStore::new`]).
    pub fn new(state_dir: &Path, encrypt_secrets: bool) -> Result<Self> {
        Self::with_launcher(state_dir, encrypt_secrets, Arc::new(SystemBrowserLauncher))
    }

    /// Test/embedder seam: substitute the browser launcher.
    pub fn with_launcher(
        state_dir: &Path,
        encrypt_secrets: bool,
        launcher: Arc<dyn BrowserLauncher>,
    ) -> Result<Self> {
        Ok(Self {
            store: McpTokenStore::new(state_dir, encrypt_secrets)?,
            launcher,
            states: Mutex::new(HashMap::new()),
            refresh: RefreshCoordinator::new(),
            paste_rx: Mutex::new(None),
        })
    }

    /// Test/embedder seam: route pasted redirect URLs into the next
    /// `authorize` from memory instead of process stdin (design §13.1).
    /// One-shot: the first authorize takes the receiver; lines sent after
    /// it closes are simply dropped.
    pub fn paste_feed(&self) -> mpsc::Sender<String> {
        let (tx, rx) = mpsc::channel(8);
        *self.paste_rx.lock() = Some(rx);
        tx
    }

    fn state_for(&self, config: &McpServerConfig) -> Result<Arc<ServerState>> {
        let raw_url = config
            .url
            .as_deref()
            .context("OAuth MCP servers must have a url")?;
        let canonical = CanonicalResource::from_configured(
            &Url::parse(raw_url).with_context(|| format!("MCP url {raw_url:?} is unparseable"))?,
        )
        .context("MCP url is not a valid canonical OAuth resource")?;
        let mut states = self.states.lock();
        if let Some(state) = states.get(canonical.resource()) {
            return Ok(Arc::clone(state));
        }
        let state = Arc::new(ServerState {
            canonical,
            factory: OAuthClientFactory::new(config),
            config: config.clone(),
            discovery: tokio::sync::RwLock::new(None),
            grant: tokio::sync::RwLock::new(None),
            loaded_from_store: tokio::sync::OnceCell::new(),
        });
        states.insert(state.canonical.resource().to_string(), Arc::clone(&state));
        Ok(state)
    }

    /// Idempotent: one store load + at most one discovery pass per process
    /// (a discovery failure is retryable; it is not cached).
    async fn ready(&self, state: &Arc<ServerState>, www_authenticate: Option<&str>) -> Result<()> {
        state
            .loaded_from_store
            .get_or_try_init(|| async {
                match self.store.load_authorization(&state.canonical).await {
                    Ok(Some(authorization)) => {
                        // S3-4: keep the stored issuer in the live grant so
                        // `ready` can bind it to discovery before any token
                        // leaves the process.
                        *state.grant.write().await = Some(Grant {
                            tokens: authorization.tokens,
                            client_id: authorization.client_id,
                            issuer: authorization.issuer,
                        });
                    }
                    Ok(None) => {}
                    Err(err) => {
                        // A broken credential file must not permanently poison
                        // the process: warn and behave as "needs authorization".
                        ::zeroclaw_log::record!(
                            WARN,
                            ::zeroclaw_log::Event::new(
                                module_path!(),
                                ::zeroclaw_log::Action::Reject
                            )
                            .with_attrs(::serde_json::json!({
                                "mcp_oauth": "store-load",
                                "resource": state.canonical.resource(),
                            })),
                            &format!(
                                "MCP OAuth store load failed; treating as unauthorized: {err:#}"
                            )
                        );
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
            .await?;

        if state.discovery.read().await.is_none() {
            let discovered =
                discover_oauth(&state.factory, &state.canonical, www_authenticate).await?;
            *state.discovery.write().await = Some(discovered);
        }

        // S3-4: bind the loaded grant to the discovered issuer before any
        // token leaves this process. If the protected-resource metadata now
        // names a different authorization server, the stored refresh token
        // belongs to the OLD party; redeeming it at the new token endpoint
        // is credential disclosure. Drop the grant (logged) and the normal
        // flow re-authorizes against the new AS.
        let discovery = state
            .discovery
            .read()
            .await
            .clone()
            .context("OAuth discovery vanished unexpectedly")?;
        let stale_issuer = {
            let grant = state.grant.read().await;
            match grant.as_ref() {
                Some(grant)
                    if !super::metadata::issuer_matches(
                        &grant.issuer,
                        &discovery.auth_server.issuer,
                    ) =>
                {
                    Some(grant.issuer.clone())
                }
                _ => None,
            }
        };
        if let Some(stale) = stale_issuer {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "mcp_oauth": "issuer-drift",
                        "resource": state.canonical.resource(),
                        "stored_issuer": stale.as_str(),
                        "discovered_issuer": discovery.auth_server.issuer.as_str(),
                    })),
                "MCP OAuth stored grant was minted by a different authorization server \
                 than discovery now names; dropping it, a fresh sign-in is required"
            );
            self.drop_grant(state).await;
        }
        Ok(())
    }

    /// Hand out a usable `Authorization` header value for `config`.
    /// `www_authenticate` is the captured `WWW-Authenticate` header from a
    /// discovery-triggering 401, if any (it can name the PRM document URL).
    /// `interactive` decides whether a missing grant may run the browser
    /// flow or must fail actionably.
    pub async fn bearer_for(
        &self,
        config: &McpServerConfig,
        www_authenticate: Option<&str>,
        interactive: bool,
    ) -> Result<String> {
        let state = self.state_for(config)?;
        self.ready(&state, www_authenticate).await?;

        // Proactive expiry refresh, deduplicated per resource.
        if let Some(token) = self.refresh_if_expiring(&state).await? {
            return Ok(bearer_header_value(&token));
        }

        // No live grant: run the FIRST authorization under the same
        // per-resource single-flight the refreshes use, so N concurrent
        // first connects share one browser sign-in, one loopback port, and
        // one DCR registration instead of each opening their own. No §12
        // nesting: `authorize` never re-enters `run_exclusive`.
        self.refresh
            .run_exclusive(state.canonical.resource(), async {
                // Re-check inside the section: the predecessor may have
                // just completed the very sign-in we came to run.
                if let Some(grant) = state.grant.read().await.as_ref() {
                    return Ok(bearer_header_value(&grant.tokens.access_token));
                }
                self.authorize(&state, interactive, false).await
            })
            .await
    }

    /// React to a 401 the transport just observed. `used_token` is the
    /// bearer the failed request carried. Returns the bearer to RETRY with
    /// (safe methods only — the caller enforces the method allowlist).
    ///
    /// Concurrency: if a concurrent caller already rotated the token, this
    /// returns the fresh one without touching the token endpoint (the
    /// request that 401'd had the stale copy).
    pub async fn on_unauthorized(
        &self,
        config: &McpServerConfig,
        www_authenticate: Option<&str>,
        used_token: &str,
        interactive: bool,
    ) -> Result<String> {
        let state = self.state_for(config)?;
        self.ready(&state, www_authenticate).await?;
        // Callers carry the Authorization header VALUE; accept both the
        // bare token and the `Bearer <token>` form so a format difference
        // can never masquerade as "someone else already rotated".
        let used_token = used_token
            .strip_prefix("Bearer ")
            .or_else(|| used_token.strip_prefix("bearer "))
            .unwrap_or(used_token);

        {
            let grant = state.grant.read().await;
            if let Some(grant) = grant.as_ref()
                && grant.tokens.access_token != used_token
            {
                // A concurrent caller already rotated the token.
                return Ok(bearer_header_value(&grant.tokens.access_token));
            }
        }

        self.refresh
            .run_exclusive(state.canonical.resource(), async {
                // Re-check inside the section: the predecessor may have
                // rotated or cleared exactly what we came to fix.
                {
                    let grant = state.grant.read().await;
                    if let Some(grant) = grant.as_ref() {
                        if grant.tokens.access_token != used_token {
                            return Ok(bearer_header_value(&grant.tokens.access_token));
                        }
                    } else {
                        return self.authorize(&state, interactive, false).await;
                    }
                }
                let (refresh_token, client_id) = {
                    let grant = state.grant.read().await;
                    match grant.as_ref() {
                        Some(grant) => (
                            grant.tokens.refresh_token.clone().filter(|t| !t.is_empty()),
                            grant.client_id.clone(),
                        ),
                        None => {
                            // The grant vanished between the check above and
                            // this read (possible since 401 paths may clear
                            // it): treat as "needs sign-in", exactly as the
                            // in-section re-check would have.
                            return self.authorize(&state, interactive, false).await;
                        }
                    }
                };
                let discovery = state
                    .discovery
                    .read()
                    .await
                    .clone()
                    .context("OAuth discovery vanished unexpectedly")?;
                let Some(refresh_token) = refresh_token else {
                    // No refresh token at all: the grant is spent; redo the
                    // authorization (or fail actionably in background mode).
                    return self
                        .reauthorize_after_grant_death(&state, interactive)
                        .await;
                };
                let token_client = state
                    .factory
                    .client_for(&discovery.auth_server.token_endpoint)
                    .await?;
                match refresh_tokens(
                    &token_client,
                    &discovery.auth_server,
                    &state.canonical,
                    &client_id,
                    &refresh_token,
                )
                .await
                {
                    Ok((tokens, _)) => {
                        let tokens = self.retain_refresh_token(&state, tokens).await;
                        let access = tokens.access_token.clone();
                        let issuer = discovery.auth_server.issuer.clone();
                        // S3-5 order: the LIVE grant is the truth for this
                        // process; install it first, then try to persist.
                        // ASes that rotate the refresh token make the old
                        // one dead — losing the disk write must not strand
                        // the process on a dead token (that forces a
                        // browser sign-in the live state could avoid).
                        let store_copy = tokens.clone();
                        *state.grant.write().await = Some(Grant {
                            tokens,
                            client_id: client_id.clone(),
                            issuer,
                        });
                        if let Err(err) =
                            self.store
                                .save_refreshed_tokens(&state.canonical, store_copy)
                                .await
                        {
                            ::zeroclaw_log::record!(
                                WARN,
                                ::zeroclaw_log::Event::new(
                                    module_path!(),
                                    ::zeroclaw_log::Action::Retry
                                )
                                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                .with_attrs(::serde_json::json!({
                                    "mcp_oauth": "store-rotate",
                                    "resource": state.canonical.resource(),
                                })),
                                &format!(
                                    "MCP OAuth refreshed the live grant but could not persist it; \
                                     a restart may need to re-authorize: {err:#}"
                                )
                            );
                        }
                        Ok(bearer_header_value(&access))
                    }
                    Err(err) => {
                        let kind = err
                            .downcast_ref::<super::tokens::TokenEndpointError>()
                            .map(|e| (e.kind, e.status));
                        match kind {
                            Some((kind, status)) if status < 500 && status != 429 => match kind {
                                TokenErrorKind::ReauthorizationRequired => {
                                    // Design §12 configured-id downgrade:
                                    // when the client the token endpoint
                                    // just rejected IS the operator's
                                    // configured `oauth_client_id`, a new
                                    // sign-in would reproduce the same
                                    // rejection (revoked, purged, or a typo
                                    // in config) — so this is a caller-side
                                    // Permanent: keep the grant intact and
                                    // send the operator to the config,
                                    // never to a browser on every call.
                                    let code: Option<String> = err
                                        .downcast_ref::<super::tokens::TokenEndpointError>()
                                        .and_then(|e| e.code.clone());
                                    if matches!(
                                        code.as_deref(),
                                        Some("invalid_client") | Some("unauthorized_client")
                                    ) && state.config.oauth_client_id.as_deref()
                                        == Some(client_id.as_str())
                                    {
                                        return Err(err.context(format!(
                                            "MCP server `{}`: the authorization server rejected the configured oauth_client_id `{client_id}` with `{}`; update the server configuration, a new sign-in cannot fix it",
                                            state.config.name,
                                            code.as_deref().unwrap_or_default()
                                        )));
                                    }
                                    // Grant death: drop it from state and
                                    // store, then redo the flow (browser) or
                                    // surface the structured refresh error
                                    // with an actionable context in the
                                    // background.
                                    self.drop_grant(&state).await;
                                    if interactive {
                                        self.authorize(&state, true, false).await
                                    } else {
                                        Err(err.context(format!(
                                            "MCP server `{}`: the stored OAuth sign-in was rejected by the authorization server; reconnect from an interactive ZeroClaw to sign in again",
                                            state.config.name
                                        )))
                                    }
                                }
                                TokenErrorKind::Permanent => bail!(
                                    "MCP OAuth token refresh for {} failed permanently: {err:#}",
                                    state.canonical.resource()
                                ),
                                TokenErrorKind::Transient => Err(err),
                            },
                            // Design §12: transient server states never
                            // clear the grant — the 5xx/429-with-
                            // invalid_grant shape keeps the grant standing
                            // and surfaces the structured error as-is.
                            _ => Err(err),
                        }
                    }
                }
            })
            .await
    }

    /// A refresh response that omits (or empties, normalized in tokens.rs)
    /// `refresh_token` leaves the previous one valid (RFC 6749 §6, review
    /// S2-2): keep the live grant's value instead of stranding the grant at
    /// the next browser flow.
    async fn retain_refresh_token(
        &self,
        state: &Arc<ServerState>,
        mut tokens: super::tokens::TokenSet,
    ) -> super::tokens::TokenSet {
        if tokens.refresh_token.is_none() {
            tokens.refresh_token = state
                .grant
                .read()
                .await
                .as_ref()
                .and_then(|grant| grant.tokens.refresh_token.clone());
        }
        tokens
    }

    /// Clear the live grant and the stored profile (warn-only on store
    /// failure: the live "needs sign-in" verdict is what callers act on).
    async fn drop_grant(&self, state: &Arc<ServerState>) {
        *state.grant.write().await = None;
        if let Err(err) = self.store.clear(&state.canonical).await {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_attrs(::serde_json::json!({
                        "mcp_oauth": "store-clear",
                        "resource": state.canonical.resource(),
                    })),
                &format!("MCP OAuth could not clear a dead grant: {err:#}")
            );
        }
    }

    /// Grant death with no token-endpoint error to preserve (a refresh token
    /// that vanished): drop the grant, then re-authorize interactively or
    /// fail actionably in background mode.
    async fn reauthorize_after_grant_death(
        &self,
        state: &Arc<ServerState>,
        interactive: bool,
    ) -> Result<String> {
        self.drop_grant(state).await;
        self.authorize(state, interactive, false).await
    }

    /// Refresh before expiry under the coordinator (double-checked). Returns
    /// `Some(access_token)` when it produced a fresh token.
    async fn refresh_if_expiring(&self, state: &Arc<ServerState>) -> Result<Option<String>> {
        let expiring = {
            let grant = state.grant.read().await;
            grant
                .as_ref()
                .is_some_and(|g| g.tokens.is_expiring_within(REFRESH_SKEW))
        };
        if !expiring {
            return Ok(None);
        }
        self.refresh
            .run_exclusive(state.canonical.resource(), async {
                // Double check: a concurrent refresh may already have fixed
                // the expiry we observed outside the lock.
                let (refresh_token, client_id) = {
                    let grant = state.grant.read().await;
                    let Some(grant) = grant.as_ref() else {
                        return Ok(None);
                    };
                    if !grant.tokens.is_expiring_within(REFRESH_SKEW) {
                        return Ok(None);
                    }
                    let Some(refresh_token) = grant.tokens.refresh_token.clone() else {
                        // Expiring with no way to renew: the 401 path (or
                        // re-authorization) owns that case.
                        return Ok(None);
                    };
                    (refresh_token, grant.client_id.clone())
                };
                let Some(discovery) = state.discovery.read().await.clone() else {
                    return Ok(None);
                };
                let token_client = state
                    .factory
                    .client_for(&discovery.auth_server.token_endpoint)
                    .await?;
                match refresh_tokens(
                    &token_client,
                    &discovery.auth_server,
                    &state.canonical,
                    &client_id,
                    &refresh_token,
                )
                .await
                {
                    Ok((tokens, _)) => {
                        let tokens = self.retain_refresh_token(state, tokens).await;
                        let access = tokens.access_token.clone();
                        let issuer = discovery.auth_server.issuer.clone();
                        // S3-5 order (mirrors the 401 path): live first,
                        // persist second, warn on persist failure.
                        let store_copy = tokens.clone();
                        *state.grant.write().await = Some(Grant {
                            tokens,
                            client_id: client_id.clone(),
                            issuer,
                        });
                        if let Err(err) = self
                            .store
                            .save_refreshed_tokens(&state.canonical, store_copy)
                            .await
                        {
                            ::zeroclaw_log::record!(
                                WARN,
                                ::zeroclaw_log::Event::new(
                                    module_path!(),
                                    ::zeroclaw_log::Action::Retry
                                )
                                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                .with_attrs(::serde_json::json!({
                                    "mcp_oauth": "store-rotate",
                                    "resource": state.canonical.resource(),
                                })),
                                &format!(
                                    "MCP OAuth refreshed the live grant but could not persist it; \
                                     a restart may need to re-authorize: {err:#}"
                                )
                            );
                        }
                        Ok(Some(access))
                    }
                    Err(err) => {
                        // A proactive refresh failing is not fatal: hand out
                        // the still-valid-ish token and let the 401 path
                        // react with full information. Transient or not, the
                        // grant stands until a 4xx says otherwise.
                        ::zeroclaw_log::record!(
                            WARN,
                            ::zeroclaw_log::Event::new(
                                module_path!(),
                                ::zeroclaw_log::Action::Retry
                            )
                            .with_attrs(::serde_json::json!({
                                "mcp_oauth": "proactive-refresh",
                                "resource": state.canonical.resource(),
                            })),
                            &format!(
                                "MCP OAuth proactive refresh failed; using current token: {err:#}"
                            )
                        );
                        Ok(None)
                    }
                }
            })
            .await
    }

    /// The paste-path decision, factored out so the matrix is pinned by a
    /// unit test without faking a terminal: an injected feed is always
    /// live (it owns no stdin); process stdin is read only for the
    /// explicit admin command AND only when it is a terminal.
    fn stdin_paste_path(
        allow_stdin_paste: bool,
        feed_present: bool,
        stdin_is_terminal: bool,
    ) -> bool {
        feed_present || (allow_stdin_paste && stdin_is_terminal)
    }

    /// The authorization half: browser flow in interactive mode, actionable
    /// error in background mode. Caller must hold no transport locks here —
    /// this can take minutes.
    async fn authorize(
        &self,
        state: &Arc<ServerState>,
        interactive: bool,
        allow_stdin_paste: bool,
    ) -> Result<String> {
        if !interactive {
            bail!(
                "MCP server `{}` requires an OAuth sign-in that must be started from an \
                 interactive session (the background runtime never opens a browser); connect \
                 once from an interactive ZeroClaw to authorize {}",
                state.config.name,
                state.canonical.resource()
            );
        }
        let discovery = state
            .discovery
            .read()
            .await
            .clone()
            .context("OAuth discovery is required before authorization")?;

        // Bind the callback port before anything that needs its URI (DCR and
        // the authorization URL), and never release it until one callback
        // has been consumed or the wait timed out.
        let listener = LoopbackListener::bind().await?;
        let redirect_uri = listener.redirect_uri();
        let pkce = Pkce::generate();
        let state_param = new_state();

        let client_id = match state.config.oauth_client_id.as_deref() {
            Some(id) => id.to_string(),
            None => {
                let Some(endpoint) = discovery.auth_server.registration_endpoint.as_ref() else {
                    bail!(
                        "MCP server `{}`: no `oauth_client_id` is configured and the \
                         authorization server {} does not advertise dynamic registration",
                        state.config.name,
                        discovery.auth_server.issuer
                    );
                };
                let reg_client = state.factory.client_for(endpoint).await?;
                let registered = register_client(
                    &reg_client,
                    endpoint,
                    &redirect_uri,
                    state.config.oauth_scopes.as_deref(),
                )
                .await
                .with_context(|| {
                    format!(
                        "MCP server `{}`: dynamic registration failed",
                        state.config.name
                    )
                })?;
                registered.client_id
            }
        };

        let authorize_url = build_authorization_url(
            &discovery,
            &state.canonical,
            &client_id,
            &redirect_uri,
            &pkce,
            &state_param,
            state.config.oauth_scopes.as_deref(),
        )?;

        // The URL is always printed: exactly what the operator can paste.
        eprintln!(
            "MCP OAuth: open this URL to sign in to `{}`:\n  {}",
            state.config.name, authorize_url
        );
        ::zeroclaw_log::record!(
            INFO,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(
                ::serde_json::json!({
                    "mcp_oauth": "browser-flow",
                    "mcp_server": &state.config.name,
                    "resource": state.canonical.resource(),
                    "authorize_url": authorize_url.as_str(),
                })
            ),
            "MCP OAuth browser sign-in started"
        );
        if let Err(err) = self.launcher.launch(&authorize_url) {
            // Advisory only: the printed URL is the fallback by design.
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_attrs(::serde_json::json!({"mcp_oauth": "browser-launch"})),
                &format!("MCP OAuth could not launch a browser; using the printed URL: {err:#}")
            );
        }

        let flow = CallbackFlow {
            state: state_param,
            issuer: discovery.auth_server.issuer.as_str().to_string(),
            require_iss: discovery.auth_server.require_iss,
            pkce: pkce.clone(),
        };

        // Manual-paste fallback (design §13.1): an operator whose browser
        // cannot reach this machine's loopback port (ZeroClaw in a
        // container, browser elsewhere, tunnel rewrites) pastes the final
        // address-bar URL instead. The verdict uses `classify_callback_url`
        // - the listener's own rules, same order, same everything: the
        // pasted text carries no more authority than a socket callback
        // would have. The token exchange below keeps posting the ORIGINAL
        // `redirect_uri` the code was minted with (RFC 6749 §4.1.3), so a
        // host:port rewrite in the paste is irrelevant.
        //
        // The PROCESS-STDIN paste path is deliberately confined to the
        // explicit admin command (`allow_stdin_paste`: `zeroclaw mcp
        // signin`, whose process exits when the flow ends). Agent-turn
        // sign-ins must not spawn the stdin reader: it blocks inside a
        // read holding the process-wide stdin lock, and once the flow
        // completes by callback it would consume - and discard - the
        // operator's NEXT typed line, which in the REPL is their first
        // message to the agent, not a stray Enter. The injected feed
        // (`paste_feed`) owns no stdin and stays available to every
        // caller (tests, embedders).
        let paste_rx = self.paste_rx.lock().take();
        let paste_active = Self::stdin_paste_path(
            allow_stdin_paste,
            paste_rx.is_some(),
            std::io::stdin().is_terminal(),
        );
        if paste_active {
            eprintln!(
                "MCP OAuth: if the browser cannot reach this machine, paste its final URL here and press Enter."
            );
        }
        let paste_wait = {
            let flow = flow.clone();
            async move {
                let mut rx = match paste_rx {
                    Some(rx) => rx,
                    None => {
                        if !paste_active {
                            // No paste path here: never swallow piped
                            // stdin, never busy-loop; the browser wait
                            // decides alone.
                            return std::future::pending::<Result<String>>().await;
                        }
                        let (tx, rx) = mpsc::channel(8);
                        super::paste::spawn_stdin_reader(tx);
                        rx
                    }
                };
                while let Some(line) = rx.recv().await {
                    let candidate = line.trim().trim_matches('"').trim_matches('\'');
                    if candidate.is_empty() {
                        continue;
                    }
                    let Ok(url) = Url::parse(candidate) else {
                        eprintln!(
                            "MCP OAuth: that paste is not a full URL; still waiting for the sign-in."
                        );
                        continue;
                    };
                    match classify_callback_url(&url, &flow) {
                        CallbackVerdict::Code(code) => return Ok(code),
                        CallbackVerdict::IdpError(err) => {
                            // Same wording the listener uses for the same
                            // verdict, so operators see one error shape.
                            bail!("the identity provider denied the sign-in: {err}")
                        }
                        CallbackVerdict::IssuerMismatch(err) => bail!("{err}"),
                        CallbackVerdict::NotVerdict => {
                            eprintln!(
                                "MCP OAuth: pasted URL does not match this sign-in (state, path, or no code); still waiting."
                            );
                        }
                    }
                }
                // Paste source exhausted (stdin closed): stay silent and
                // let the browser wait be the only remaining verdict.
                std::future::pending::<Result<String>>().await
            }
        };
        let code =
            tokio::time::timeout(CALLBACK_WAIT_TIMEOUT + Duration::from_secs(5), async move {
                tokio::select! {
                    listened = listener.wait_for_code(&flow, CALLBACK_WAIT_TIMEOUT) => listened,
                    pasted = paste_wait => pasted,
                }
            })
            .await
            .map_err(|_| {
                anyhow::Error::msg(
                    "MCP OAuth browser sign-in did not complete before the outer deadline",
                )
            })??;

        let token_client = state
            .factory
            .client_for(&discovery.auth_server.token_endpoint)
            .await?;
        let tokens = exchange_code(
            &token_client,
            &discovery.auth_server,
            &state.canonical,
            &client_id,
            &redirect_uri,
            &code,
            &pkce.verifier,
        )
        .await
        .with_context(|| format!("MCP server `{}`: token exchange failed", state.config.name))?;

        self.store
            .save_authorization(
                &state.canonical,
                &client_id,
                &discovery.auth_server.issuer,
                tokens.clone(),
            )
            .await?;
        let access = tokens.access_token.clone();
        *state.grant.write().await = Some(Grant {
            tokens,
            client_id: client_id.clone(),
            issuer: discovery.auth_server.issuer.clone(),
        });
        Ok(bearer_header_value(&access))
    }
}

/// The cheap, cloneable handle a remote transport holds: manager + the
/// server config it belongs to + the interactive posture frozen at connect
/// time. Transports never learn tokens directly; they ask for a header
/// value and report 401s back.
#[derive(Clone)]
pub struct TransportOAuth {
    manager: Arc<McpOAuthManager>,
    config: McpServerConfig,
    interactive: bool,
}

impl std::fmt::Debug for TransportOAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportOAuth")
            .field("mcp_server", &self.config.name)
            .field("interactive", &self.interactive)
            .finish_non_exhaustive()
    }
}

impl TransportOAuth {
    pub fn new(manager: Arc<McpOAuthManager>, config: McpServerConfig, interactive: bool) -> Self {
        Self {
            manager,
            config,
            interactive,
        }
    }

    /// Current usable `Authorization` header value (refreshes proactively
    /// near expiry; authorizes on first use).
    pub async fn bearer(&self, www_authenticate: Option<&str>) -> Result<String> {
        self.manager
            .bearer_for(&self.config, www_authenticate, self.interactive)
            .await
    }

    /// The request that carried `used_token` just got a 401; returns the
    /// header value to retry with (safe methods only — the caller decides).
    pub async fn on_unauthorized(
        &self,
        www_authenticate: Option<&str>,
        used_token: &str,
    ) -> Result<String> {
        self.manager
            .on_unauthorized(&self.config, www_authenticate, used_token, self.interactive)
            .await
    }
}

/// Assemble the authorization request URL (RFC 6749 §4.1.1 + RFC 7636 +
/// RFC 8707). The endpoint arrives without query (slice 1 gate), so
/// `query_pairs_mut` starts from empty.
fn build_authorization_url(
    discovery: &OAuthDiscovery,
    canonical: &CanonicalResource,
    client_id: &str,
    redirect_uri: &str,
    pkce: &Pkce,
    state_param: &str,
    scopes: Option<&[String]>,
) -> Result<Url> {
    let mut url = discovery.auth_server.authorization_endpoint.clone();
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state_param)
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", canonical.resource());
        if let Some(scopes) = scopes
            && !scopes.is_empty()
        {
            query.append_pair("scope", &scopes.join(" "));
        }
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_oauth::tokens::TokenEndpointError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A launcher that plays the browser: parses the `state` and
    /// `redirect_uri` out of the authorization URL and delivers a callback
    /// to the real listener, exactly as a browser would.
    struct AutoCallbackLauncher {
        code: &'static str,
        fail: bool,
        /// Counts `launch` invocations so dedup guarantees (concurrent
        /// first-connects) can be pinned, not just asserted by token state.
        launches: AtomicUsize,
    }

    impl BrowserLauncher for AutoCallbackLauncher {
        fn launch(&self, url: &Url) -> Result<()> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                bail!("simulated launcher failure");
            }
            spawn_callback_delivery(url, self.code, Duration::ZERO);
            Ok(())
        }
    }

    /// Plays the browser half of the flow: parses `state` and
    /// `redirect_uri` out of the authorization URL and, after `delay`,
    /// delivers a callback to the real listener over a raw socket from a
    /// helper thread (`launch` must never block the flow, and no blocking
    /// HTTP client is a test dependency here).
    fn spawn_callback_delivery(url: &Url, code: &str, delay: Duration) {
        let redirect = url
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .map(|(_, v)| v.into_owned())
            .expect("redirect_uri present");
        let state = url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .expect("state present");
        let code = code.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            let Ok(target) = Url::parse(&format!("{redirect}?code={code}&state={state}")) else {
                return;
            };
            let Some(host) = target.host_str().map(str::to_string) else {
                return;
            };
            let Some(port) = target.port_or_known_default() else {
                return;
            };
            let path = match target.query() {
                Some(q) => format!("{}?{q}", target.path()),
                None => target.path().to_string(),
            };
            if let Ok(mut stream) = std::net::TcpStream::connect((host.as_str(), port)) {
                use std::io::Write;
                let _ = write!(
                    stream,
                    "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                );
            }
        });
    }

    /// A launcher that delivers the callback `delay` after being asked to
    /// open the browser: simulates a human who takes real wall-clock time
    /// in front of the consent screen.
    struct SlowHumanLauncher {
        code: &'static str,
        delay: Duration,
    }

    impl BrowserLauncher for SlowHumanLauncher {
        fn launch(&self, url: &Url) -> Result<()> {
            spawn_callback_delivery(url, self.code, self.delay);
            Ok(())
        }
    }

    struct Stub {
        store: McpServerConfig,
        mcp: MockServer,
        as_: MockServer,
        tmp: TempDir,
    }

    async fn stub(
        register_body: Option<serde_json::Value>,
        token_bodies: Vec<(u16, serde_json::Value)>,
    ) -> Stub {
        stub_with(register_body, token_bodies, Vec::new()).await
    }

    /// `stub` plus per-token-step extra latency (review S3-3: the test for
    /// "no write permit is held across a slow token round-trip").
    async fn stub_with(
        register_body: Option<serde_json::Value>,
        token_bodies: Vec<(u16, serde_json::Value)>,
        token_extra_delay: Vec<u64>,
    ) -> Stub {
        let mcp = MockServer::start().await;
        let as_ = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-protected-resource/mcp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "resource": format!("{}/mcp", mcp.uri()),
                "authorization_servers": [as_.uri()],
                "bearer_methods_supported": ["header"],
            })))
            .mount(&mcp)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": as_.uri(),
                "authorization_endpoint": format!("{}/authorize", as_.uri()),
                "token_endpoint": format!("{}/token", as_.uri()),
                "registration_endpoint": format!("{}/register", as_.uri()),
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
            })))
            .mount(&as_)
            .await;
        if let Some(body) = register_body {
            Mock::given(method("POST"))
                .and(path("/register"))
                .respond_with(ResponseTemplate::new(201).set_body_json(body))
                .mount(&as_)
                .await;
        }
        {
            struct Sequenced {
                steps: Vec<(u16, serde_json::Value)>,
                extra_delay: Vec<u64>,
                next: AtomicUsize,
            }
            impl wiremock::Respond for Sequenced {
                fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
                    let step = self.next.fetch_add(1, Ordering::SeqCst);
                    // Past the end: repeat the last step so tests that
                    // over-call assert on request counts, not panics.
                    let (status, body) = self
                        .steps
                        .get(step)
                        .or_else(|| self.steps.last())
                        .expect("at least one token step");
                    let delay = self
                        .extra_delay
                        .get(step)
                        .or_else(|| {
                            (!self.extra_delay.is_empty())
                                .then_some(self.extra_delay.last())
                                .flatten()
                        })
                        .copied()
                        .unwrap_or(0);
                    ResponseTemplate::new(*status)
                        .set_delay(Duration::from_millis(delay))
                        .set_body_json(body.clone())
                }
            }
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(Sequenced {
                    steps: token_bodies,
                    extra_delay: token_extra_delay,
                    next: AtomicUsize::new(0),
                })
                .mount(&as_)
                .await;
        }
        let tmp = TempDir::new().expect("tmp");
        let store = McpServerConfig {
            name: "mgr-test".to_string(),
            transport: zeroclaw_config::schema::McpTransport::Http,
            url: Some(format!("{}/mcp", mcp.uri())),
            oauth: true,
            oauth_scopes: Some(vec!["mcp:tools".to_string()]),
            ..Default::default()
        };
        Stub {
            store,
            mcp,
            as_,
            tmp,
        }
    }

    fn manager_with(stub: &Stub, launcher: Arc<dyn BrowserLauncher>) -> McpOAuthManager {
        McpOAuthManager::with_launcher(stub.tmp.path(), true, launcher).expect("manager")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn interactive_flow_stores_and_returns_bearer() {
        let stub = stub(
            Some(serde_json::json!({"client_id": "dyn-cid"})),
            vec![(
                200,
                serde_json::json!({"access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600, "token_type": "Bearer"}),
            )],
        )
        .await;
        let manager = manager_with(
            &stub,
            Arc::new(AutoCallbackLauncher {
                code: "the-code",
                fail: false,
                launches: AtomicUsize::new(0),
            }),
        );
        let bearer = manager
            .bearer_for(&stub.store, None, true)
            .await
            .expect("interactive flow");
        assert_eq!(bearer, "Bearer at-1");

        // Authorization URL reached the launcher with the right shape.
        // DCR was used, and the grant persisted encrypted under the store.
        let canonical = CanonicalResource::from_configured(
            &Url::parse(&format!("{}/mcp", stub.mcp.uri())).expect("url"),
        )
        .expect("canonical");
        let loaded = manager
            .store
            .load_authorization(&canonical)
            .await
            .expect("load")
            .expect("stored");
        assert_eq!(loaded.client_id, "dyn-cid");
        assert_eq!(loaded.tokens.access_token, "at-1");

        let requests = stub.as_.received_requests().await.expect("received");
        let token_body = requests
            .iter()
            .find(|r| r.url.path() == "/token")
            .map(|r| String::from_utf8(r.body.clone()).expect("utf8"))
            .expect("token request");
        assert!(token_body.contains("code=the-code"));
        assert!(token_body.contains("code_verifier="));
        assert!(
            token_body.contains(&format!("resource={}", urlencoded(canonical.resource()))),
            "token exchange must carry the RFC 8707 resource parameter"
        );
    }

    #[test]
    fn stdin_paste_path_matrix() {
        // The decision `authorize` actually makes, pinned without faking a
        // terminal: an injected feed is always live; process stdin is read
        // ONLY for the admin sign-in (`force_signin` passes
        // `allow_stdin_paste = true`; every agent-turn path passes false)
        // and only when stdin is really a terminal.
        assert!(McpOAuthManager::stdin_paste_path(false, true, false));
        assert!(McpOAuthManager::stdin_paste_path(true, true, true));
        assert!(McpOAuthManager::stdin_paste_path(true, false, true));
        assert!(
            !McpOAuthManager::stdin_paste_path(false, false, true),
            "agent turn on a TTY must not start the stdin reader"
        );
        assert!(
            !McpOAuthManager::stdin_paste_path(true, false, false),
            "admin sign-in without a terminal must not start the reader"
        );
        assert!(!McpOAuthManager::stdin_paste_path(false, false, false));
    }

    /// The container story end to end: the browser never reaches the
    /// listener (it lives on another machine), so the final URLs arrive on
    /// the paste channel instead, with `host:port` rewritten by whatever
    /// tunnel the operator used. Each line template may mention `{state}`
    /// and `{redirect}`, taken from the real authorization URL.
    struct PastingLauncher {
        lines: &'static [&'static str],
        paste: std::sync::Mutex<Option<mpsc::Sender<String>>>,
        redirect: std::sync::Mutex<Option<String>>,
    }

    impl PastingLauncher {
        fn new(lines: &'static [&'static str]) -> Arc<Self> {
            Arc::new(Self {
                lines,
                paste: std::sync::Mutex::new(None),
                redirect: std::sync::Mutex::new(None),
            })
        }
        fn with_feed(self: &Arc<Self>, tx: mpsc::Sender<String>) {
            *self.paste.lock().expect("lock") = Some(tx);
        }
        fn seen_redirect(&self) -> Option<String> {
            self.redirect.lock().expect("lock").clone()
        }
    }

    impl BrowserLauncher for PastingLauncher {
        fn launch(&self, url: &Url) -> Result<()> {
            let state = url
                .query_pairs()
                .find(|(k, _)| k == "state")
                .map(|(_, v)| v.into_owned())
                .expect("state");
            let redirect = url
                .query_pairs()
                .find(|(k, _)| k == "redirect_uri")
                .map(|(_, v)| v.into_owned())
                .expect("redirect_uri");
            *self.redirect.lock().expect("lock") = Some(redirect.clone());
            let tx = self
                .paste
                .lock()
                .expect("lock")
                .clone()
                .expect("paste feed must be installed before the flow starts");
            // Send off-thread: `launch` runs on a runtime worker (blocking
            // sends would panic there), and a real operator types the
            // paste long after the browser opened anyway.
            let lines: Vec<String> = self
                .lines
                .iter()
                .map(|t| {
                    t.replace("{state}", &state)
                        .replace("{redirect}", &redirect)
                })
                .collect();
            std::thread::spawn(move || {
                for line in lines {
                    if tx.blocking_send(line).is_err() {
                        return;
                    }
                }
            });
            Ok(())
        }
    }

    fn paste_stub_tokens() -> Vec<(u16, serde_json::Value)> {
        vec![(
            200,
            serde_json::json!({"access_token": "at-paste", "expires_in": 3600, "token_type": "Bearer"}),
        )]
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pasted_redirect_with_rewritten_host_completes_the_flow() {
        // Design §13.1: an address-bar URL whose host:port the tunnel
        // rewrote completes the sign-in, and the token exchange still
        // posts the ORIGINAL bound redirect_uri (RFC 6749 §4.1.3), never
        // the rewrite.
        let stub = stub(
            Some(serde_json::json!({"client_id": "dyn-cid"})),
            paste_stub_tokens(),
        )
        .await;
        let launcher =
            PastingLauncher::new(&["http://localhost:9999/callback?code=pasted-1&state={state}"]);
        let manager = manager_with(&stub, launcher.clone());
        launcher.with_feed(manager.paste_feed());
        let bearer = manager
            .bearer_for(&stub.store, None, true)
            .await
            .expect("pasted sign-in");
        assert_eq!(bearer, "Bearer at-paste");

        let original = launcher
            .seen_redirect()
            .expect("launcher saw the authorize URL");
        assert!(
            original.starts_with("http://127.0.0.1:"),
            "the bound redirect was: {original}"
        );
        let requests = stub.as_.received_requests().await.expect("received");
        let token_body = requests
            .iter()
            .find(|r| r.url.path() == "/token")
            .map(|r| String::from_utf8(r.body.clone()).expect("utf8"))
            .expect("token POST");
        assert!(token_body.contains("code=pasted-1"));
        assert!(
            token_body.contains(&format!("redirect_uri={}", urlencoded(&original))),
            "the exchange must post the original bound redirect_uri, got: {token_body}"
        );
        assert!(
            !token_body.contains("localhost%3A9999"),
            "the pasted host:port rewrite must not leak into the exchange"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pasted_garbage_and_foreign_state_rearm_then_the_real_paste_wins() {
        // A mis-paste must not end the flow: it is reported and the
        // listener keeps waiting, exactly like a foreign socket request.
        let stub = stub(
            Some(serde_json::json!({"client_id": "dyn-cid"})),
            paste_stub_tokens(),
        )
        .await;
        let launcher = PastingLauncher::new(&[
            "this is not a url",
            "http://localhost:9999/callback?code=nope&state=foreign-state",
            "http://localhost:9999/callback?code=yes&state={state}",
        ]);
        let manager = manager_with(&stub, launcher.clone());
        launcher.with_feed(manager.paste_feed());
        let bearer = manager
            .bearer_for(&stub.store, None, true)
            .await
            .expect("sign-in survives mis-pastes");
        assert_eq!(bearer, "Bearer at-paste");
        let requests = stub.as_.received_requests().await.expect("received");
        let token_body = requests
            .iter()
            .find(|r| r.url.path() == "/token")
            .map(|r| String::from_utf8(r.body.clone()).expect("utf8"))
            .expect("token POST");
        assert!(
            token_body.contains("code=yes") && !token_body.contains("code=nope"),
            "only the matching paste may be exchanged: {token_body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pasted_idp_error_fails_the_flow_like_the_listener_would() {
        let stub = stub(
            Some(serde_json::json!({"client_id": "dyn-cid"})),
            paste_stub_tokens(),
        )
        .await;
        let launcher = PastingLauncher::new(&[
            "http://localhost:9999/callback?error=access_denied&error_description=nope&state={state}",
        ]);
        let manager = manager_with(&stub, launcher.clone());
        launcher.with_feed(manager.paste_feed());
        let err = manager
            .bearer_for(&stub.store, None, true)
            .await
            .expect_err("a pasted denial is a flow failure");
        assert!(
            err.to_string().contains("access_denied (nope)"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pasted_issuer_mismatch_fails_the_flow() {
        let stub = stub(
            Some(serde_json::json!({"client_id": "dyn-cid"})),
            paste_stub_tokens(),
        )
        .await;
        let launcher = PastingLauncher::new(&[
            "http://localhost:9999/callback?code=c&iss=https://evil.example&state={state}",
        ]);
        let manager = manager_with(&stub, launcher.clone());
        launcher.with_feed(manager.paste_feed());
        let err = manager
            .bearer_for(&stub.store, None, true)
            .await
            .expect_err("a pasted mixed-up issuer is a flow failure");
        assert!(err.to_string().contains("issuer"), "got: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn closed_paste_feed_leaves_the_browser_callback_in_charge() {
        // An exhausted paste source (stdin closed / feed dropped) must
        // neither fail the flow nor busy-loop: the browser callback
        // remains the sole verdict, exactly as before this feature.
        let stub = stub(Some(serde_json::json!({"client_id": "dyn-cid"})), vec![(
            200,
            serde_json::json!({"access_token": "at-1", "expires_in": 3600, "token_type": "Bearer"}),
        )])
        .await;
        let manager = manager_with(
            &stub,
            Arc::new(AutoCallbackLauncher {
                code: "via-browser",
                fail: false,
                launches: AtomicUsize::new(0),
            }),
        );
        let tx = manager.paste_feed();
        drop(tx);
        let bearer = manager
            .bearer_for(&stub.store, None, true)
            .await
            .expect("browser callback still completes the flow");
        assert_eq!(bearer, "Bearer at-1");
    }

    fn urlencoded(s: &str) -> String {
        // Mirrors `form_urlencoded` exactly: alphanumerics plus `*-._` are
        // literal, everything else percent-encoded (spaces would be `+`).
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn configured_client_id_skips_registration() {
        let mut stub = stub(None, vec![(200, serde_json::json!({"access_token": "at"}))]).await;
        stub.store.oauth_client_id = Some("static-cid".to_string());
        // A launcher that reports failure AFTER delivering the callback:
        // the printed-URL fallback keeps the flow alive when the browser
        // open itself fails, and this pins that end to end.
        let manager = {
            struct DeliveringFail;
            impl BrowserLauncher for DeliveringFail {
                fn launch(&self, url: &Url) -> Result<()> {
                    AutoCallbackLauncher {
                        code: "c2",
                        fail: false,
                        launches: AtomicUsize::new(0),
                    }
                    .launch(url)
                    .expect("deliver");
                    bail!("simulated open failure after delivery");
                }
            }
            McpOAuthManager::with_launcher(stub.tmp.path(), true, Arc::new(DeliveringFail))
                .expect("m")
        };
        let bearer = manager
            .bearer_for(&stub.store, None, true)
            .await
            .expect("flow");
        assert_eq!(bearer, "Bearer at");
        let requests = stub.as_.received_requests().await.expect("received");
        assert!(
            !requests.iter().any(|r| r.url.path() == "/register"),
            "configured client id must not register"
        );
        let _ = manager;
    }

    #[tokio::test]
    async fn background_mode_without_grant_fails_actionably_and_binds_nothing() {
        let stub = stub(Some(serde_json::json!({"client_id": "x"})), vec![]).await;
        struct Never;
        impl BrowserLauncher for Never {
            fn launch(&self, _url: &Url) -> Result<()> {
                panic!("background mode must never launch a browser");
            }
        }
        let manager =
            McpOAuthManager::with_launcher(stub.tmp.path(), true, Arc::new(Never)).expect("m");
        let err = manager
            .bearer_for(&stub.store, None, false)
            .await
            .expect_err("background needs an interactive first sign-in");
        assert!(err.to_string().contains("interactive"), "got: {err}");
        // And the error carries the server name for actionability.
        assert!(err.to_string().contains("mgr-test"), "got: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn on_unauthorized_rotates_once_and_concurrent_rotation_short_circuits() {
        let stub = stub(
            Some(serde_json::json!({"client_id": "dyn-cid"})),
            vec![
                (
                    200,
                    serde_json::json!({"access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600, "token_type": "Bearer"}),
                ),
                (
                    200,
                    serde_json::json!({"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600, "token_type": "Bearer"}),
                ),
            ],
        )
        .await;
        let manager = Arc::new(manager_with(
            &stub,
            Arc::new(AutoCallbackLauncher {
                code: "c",
                fail: false,
                launches: AtomicUsize::new(0),
            }),
        ));
        let first = manager
            .bearer_for(&stub.store, None, true)
            .await
            .expect("flow");
        assert_eq!(first, "Bearer at-1");

        // Two concurrent 401s carrying at-1: exactly one token-endpoint
        // refresh runs (wiremock serves both refreshes, but the second
        // caller must observe the rotated token and return it directly —
        // total token requests stay at two: exchange + one refresh).
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let manager = Arc::clone(&manager);
            let config = stub.store.clone();
            tasks.push(zeroclaw_spawn::spawn!(async move {
                manager
                    .on_unauthorized(&config, None, "at-1", true)
                    .await
                    .expect("refresh")
            }));
        }
        let mut got = Vec::new();
        for t in tasks {
            got.push(t.await.expect("task"));
        }
        assert!(
            got.iter().all(|b| b == "Bearer at-2"),
            "both callers must end with the rotated token: {got:?}"
        );
        let requests = stub.as_.received_requests().await.expect("received");
        let token_calls = requests.iter().filter(|r| r.url.path() == "/token").count();
        assert_eq!(
            token_calls, 2,
            "exchange + exactly one refresh: {token_calls}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn invalid_grant_on_refresh_clears_grant_and_background_fails_actionably() {
        let stub = stub(
            Some(serde_json::json!({"client_id": "dyn-cid"})),
            vec![
                (
                    200,
                    serde_json::json!({"access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600, "token_type": "Bearer"}),
                ),
                (400, serde_json::json!({"error": "invalid_grant"})),
            ],
        )
        .await;
        let manager = manager_with(
            &stub,
            Arc::new(AutoCallbackLauncher {
                code: "c",
                fail: false,
                launches: AtomicUsize::new(0),
            }),
        );
        manager
            .bearer_for(&stub.store, None, true)
            .await
            .expect("flow");
        let err = manager
            .on_unauthorized(&stub.store, None, "at-1", false)
            .await
            .expect_err("invalid_grant must fail in background");
        let structured = err
            .downcast_ref::<TokenEndpointError>()
            .expect("structured refresh error survives into the 401 error chain");
        assert_eq!(structured.kind, TokenErrorKind::ReauthorizationRequired);
        // Grant was cleared from the live state and the store.
        let canonical = CanonicalResource::from_configured(
            &Url::parse(&format!("{}/mcp", stub.mcp.uri())).expect("url"),
        )
        .expect("canonical");
        assert!(
            manager
                .store
                .load_authorization(&canonical)
                .await
                .expect("load")
                .is_none(),
            "invalid_grant must clear the stored grant"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn token_endpoint_5xx_never_clears_the_grant() {
        let stub = stub(
            Some(serde_json::json!({"client_id": "dyn-cid"})),
            vec![
                (
                    200,
                    serde_json::json!({"access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600, "token_type": "Bearer"}),
                ),
                // Even carrying invalid_grant, a 5xx is transient per design §12.
                (503, serde_json::json!({"error": "invalid_grant"})),
            ],
        )
        .await;
        let manager = manager_with(
            &stub,
            Arc::new(AutoCallbackLauncher {
                code: "c",
                fail: false,
                launches: AtomicUsize::new(0),
            }),
        );
        manager
            .bearer_for(&stub.store, None, true)
            .await
            .expect("flow");
        let err = manager
            .on_unauthorized(&stub.store, None, "at-1", false)
            .await
            .expect_err("5xx must surface as an error");
        assert!(err.to_string().contains("HTTP 503"), "got: {err:#}");
        let canonical = CanonicalResource::from_configured(
            &Url::parse(&format!("{}/mcp", stub.mcp.uri())).expect("url"),
        )
        .expect("canonical");
        assert!(
            manager
                .store
                .load_authorization(&canonical)
                .await
                .expect("load")
                .is_some(),
            "a 5xx must never clear the stored grant"
        );
    }

    #[test]
    fn authorization_url_carries_every_rfc_param() {
        let discovery = OAuthDiscovery {
            canonical: CanonicalResource::from_configured(&Url::parse("https://h/mcp").expect("u"))
                .expect("c"),
            protected_resource_url: Url::parse(
                "https://h/.well-known/oauth-protected-resource/mcp",
            )
            .expect("u"),
            auth_server: super::super::metadata::ValidatedAs {
                issuer: Url::parse("https://a.example").expect("u"),
                authorization_endpoint: Url::parse("https://a.example/authorize").expect("u"),
                token_endpoint: Url::parse("https://a.example/token").expect("u"),
                registration_endpoint: None,
                scopes_supported: None,
                require_iss: false,
            },
        };
        let url = build_authorization_url(
            &discovery,
            &CanonicalResource::from_configured(&Url::parse("https://h/mcp").expect("u"))
                .expect("c"),
            "cid",
            "http://127.0.0.1:9/callback",
            &Pkce::from_verifier("v"),
            "st-1",
            Some(&["a".to_string(), "b".to_string()]),
        )
        .expect("built");
        let pairs: HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(pairs.get("response_type").map(|s| s.as_ref()), Some("code"));
        assert_eq!(pairs.get("client_id").map(|s| s.as_ref()), Some("cid"));
        assert_eq!(
            pairs.get("redirect_uri").map(|s| s.as_ref()),
            Some("http://127.0.0.1:9/callback")
        );
        assert_eq!(pairs.get("state").map(|s| s.as_ref()), Some("st-1"));
        assert_eq!(
            pairs.get("code_challenge_method").map(|s| s.as_ref()),
            Some("S256")
        );
        assert_eq!(pairs.get("scope").map(|s| s.as_ref()), Some("a b"));
        assert_eq!(
            pairs.get("resource").map(|s| s.as_ref()),
            Some("https://h/mcp")
        );
    }

    // ── Transport integration: bearer injection + 401 semantics ──────────

    /// Wiremock MCP endpoint sequencer: 401s for `denials` first, then
    /// well-formed JSON-RPC successes.
    struct McpEndpoint {
        denials: usize,
        hits: AtomicUsize,
    }

    impl wiremock::Respond for McpEndpoint {
        fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
            let hit = self.hits.fetch_add(1, Ordering::SeqCst);
            if hit < self.denials {
                ResponseTemplate::new(401).insert_header(
                    "www-authenticate",
                    "Bearer realm=\"mcp\", error=\"invalid_token\"",
                )
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 7,
                    "result": {},
                }))
            }
        }
    }

    async fn transport_with_live_grant(
        denials: usize,
        refresh_steps: Vec<(u16, serde_json::Value)>,
    ) -> (
        Arc<McpOAuthManager>,
        Stub,
        Arc<crate::mcp_transport::HttpTransport>,
    ) {
        let stub = stub(Some(serde_json::json!({"client_id": "cid"})), refresh_steps).await;
        let responder = McpEndpoint {
            denials,
            hits: AtomicUsize::new(0),
        };
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/mcp"))
            .respond_with(responder)
            .mount(&stub.mcp)
            .await;
        let manager = Arc::new(
            McpOAuthManager::with_launcher(
                stub.tmp.path(),
                true,
                Arc::new(AutoCallbackLauncher {
                    code: "c",
                    fail: false,
                    launches: AtomicUsize::new(0),
                }),
            )
            .expect("manager"),
        );
        manager
            .store
            .save_authorization(
                &CanonicalResource::from_configured(
                    &Url::parse(&format!("{}/mcp", stub.mcp.uri())).expect("url"),
                )
                .expect("canonical"),
                "cid",
                &Url::parse(&stub.as_.uri()).expect("issuer"),
                TokenSet {
                    access_token: "at-live".to_string(),
                    refresh_token: Some("rt-live".to_string()),
                    id_token: None,
                    expires_at: None,
                    token_type: Some("Bearer".to_string()),
                    scope: None,
                },
            )
            .await
            .expect("seed grant");
        let transport = Arc::new(
            crate::mcp_transport::HttpTransport::new_with_oauth(
                &stub.store,
                Some(TransportOAuth::new(
                    Arc::clone(&manager),
                    stub.store.clone(),
                    false,
                )),
            )
            .expect("transport"),
        );
        (manager, stub, transport)
    }

    /// POSTs that reached the MCP endpoint itself (PRM discovery is a GET
    /// on the same mock server and must not count as a request attempt).
    async fn mcp_posts(stub: &Stub) -> usize {
        stub.mcp
            .received_requests()
            .await
            .expect("received")
            .iter()
            .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/mcp")
            .count()
    }

    async fn send(
        transport: &Arc<crate::mcp_transport::HttpTransport>,
        method: &str,
    ) -> Result<crate::mcp_protocol::JsonRpcResponse> {
        let request = crate::mcp_protocol::JsonRpcRequest::new(7, method, serde_json::json!({}));
        let lifecycle = crate::mcp_transport::McpRequestLifecycle::uncoordinated(0);
        crate::mcp_transport::SharedMcpTransportConn::send_and_recv(
            transport.as_ref(),
            &request,
            &lifecycle,
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn safe_method_401_refreshes_once_and_replays_exactly_once() {
        let (_manager, stub, transport) = transport_with_live_grant(
            1,
            vec![(
                200,
                serde_json::json!({"access_token": "at-2", "refresh_token": "rt-2", "token_type": "Bearer", "expires_in": 3600}),
            )],
        )
        .await;
        let response = send(&transport, "tools/list").await.expect("retried ok");
        assert_eq!(response.id, Some(serde_json::json!(7)));
        let requests = stub.as_.received_requests().await.expect("received");
        let token_calls = requests.iter().filter(|r| r.url.path() == "/token").count();
        assert_eq!(token_calls, 1, "exactly one refresh: {token_calls}");
        let mcp_requests = stub.mcp.received_requests().await.expect("received");
        let authed: Vec<String> = mcp_requests
            .iter()
            .filter_map(|r| {
                r.headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap_or_default().to_string())
            })
            .collect();
        assert_eq!(
            authed,
            vec!["Bearer at-live".to_string(), "Bearer at-2".to_string()],
            "first attempt stale, replay refreshed, nothing more"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tools_call_401_is_never_replayed_but_still_refreshes_state() {
        let (_manager, stub, transport) = transport_with_live_grant(
            1,
            vec![(
                200,
                serde_json::json!({"access_token": "at-2", "refresh_token": "rt-2", "token_type": "Bearer", "expires_in": 3600}),
            )],
        )
        .await;
        let err = send(&transport, "tools/call")
            .await
            .expect_err("401 surfaces");
        assert!(err.to_string().contains("HTTP 401"), "got: {err}");
        assert_eq!(
            mcp_posts(&stub).await,
            1,
            "state-changing call must not replay"
        );
        let as_requests = stub.as_.received_requests().await.expect("received");
        assert_eq!(
            as_requests
                .iter()
                .filter(|r| r.url.path() == "/token")
                .count(),
            1,
            "the grant is refreshed for the NEXT call"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn second_consecutive_401_is_terminal() {
        let (_manager, stub, transport) = transport_with_live_grant(
            2,
            vec![(
                200,
                serde_json::json!({"access_token": "at-2", "refresh_token": "rt-2", "token_type": "Bearer", "expires_in": 3600}),
            )],
        )
        .await;
        let err = send(&transport, "tools/list")
            .await
            .expect_err("two 401s terminal");
        assert!(err.to_string().contains("HTTP 401"), "got: {err}");
        assert_eq!(
            mcp_posts(&stub).await,
            2,
            "one refresh + one replay, then stop"
        );
    }

    // ── Reviewer-round pins: §12 configured-id, dedup, SSE legs ──────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn configured_client_id_rejection_is_permanent_and_keeps_the_grant() {
        // Design §12: the token endpoint rejects OUR configured client id.
        // A browser sign-in would redeem under the very same id, so this
        // must NOT become grant death + browser churn.
        let stub = stub(
            Some(serde_json::json!({"client_id": "dyn-cid"})),
            vec![(400, serde_json::json!({"error": "invalid_client"}))],
        )
        .await;
        let launcher = Arc::new(AutoCallbackLauncher {
            code: "c",
            fail: false,
            launches: AtomicUsize::new(0),
        });
        let manager = McpOAuthManager::with_launcher(
            stub.tmp.path(),
            true,
            Arc::clone(&launcher) as Arc<dyn BrowserLauncher>,
        )
        .expect("manager");
        let mut config = stub.store.clone();
        config.oauth_client_id = Some("cid".to_string());
        let canonical = CanonicalResource::from_configured(
            &Url::parse(config.url.as_deref().expect("url")).expect("canonical"),
        )
        .expect("canonical");
        manager
            .store
            .save_authorization(
                &canonical,
                "cid",
                &Url::parse(&stub.as_.uri()).expect("issuer"),
                TokenSet {
                    access_token: "at-live".to_string(),
                    refresh_token: Some("rt-live".to_string()),
                    id_token: None,
                    expires_at: None,
                    token_type: Some("Bearer".to_string()),
                    scope: None,
                },
            )
            .await
            .expect("seed grant");

        let err = manager
            .on_unauthorized(&config, None, "Bearer at-live", true)
            .await
            .expect_err("configured-id rejection is a caller-side Permanent");
        let text = err.to_string();
        assert!(
            text.contains("configured oauth_client_id") && text.contains("invalid_client"),
            "got: {text}"
        );
        assert!(
            err.downcast_ref::<crate::mcp_oauth::tokens::TokenEndpointError>()
                .is_some(),
            "the structured token error must survive the context layer"
        );
        assert_eq!(
            launcher.launches.load(Ordering::SeqCst),
            0,
            "a config-level rejection must never open a browser, even interactive"
        );
        assert!(
            manager
                .store
                .load_authorization(&canonical)
                .await
                .expect("load")
                .is_some(),
            "a caller-side Permanent leaves the durable grant untouched"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_connects_share_one_browser_signin() {
        let stub = stub(
            Some(serde_json::json!({"client_id": "dyn-cid"})),
            vec![(
                200,
                serde_json::json!({"access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600, "token_type": "Bearer"}),
            )],
        )
        .await;
        let launcher = Arc::new(AutoCallbackLauncher {
            code: "c",
            fail: false,
            launches: AtomicUsize::new(0),
        });
        let manager = Arc::new(
            McpOAuthManager::with_launcher(
                stub.tmp.path(),
                true,
                Arc::clone(&launcher) as Arc<dyn BrowserLauncher>,
            )
            .expect("manager"),
        );
        let (ra, rb) = tokio::join!(
            manager.bearer_for(&stub.store, None, true),
            manager.bearer_for(&stub.store, None, true),
        );
        assert_eq!(ra.expect("first bearer"), "Bearer at-1");
        assert_eq!(rb.expect("second bearer"), "Bearer at-1");
        assert_eq!(
            launcher.launches.load(Ordering::SeqCst),
            1,
            "one browser sign-in, one loopback port, one registration for N concurrent connects"
        );
        let requests = stub.as_.received_requests().await.expect("received");
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/register")
                .count(),
            1,
            "the loser of the race must not re-register the client"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/token")
                .count(),
            1,
            "exactly one code exchange"
        );
    }

    struct SseGetGate {
        denials: usize,
        hits: AtomicUsize,
    }

    impl wiremock::Respond for SseGetGate {
        fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
            let hit = self.hits.fetch_add(1, Ordering::SeqCst);
            if hit < self.denials {
                ResponseTemplate::new(401).insert_header(
                    "www-authenticate",
                    "Bearer realm=\"mcp\", error=\"invalid_token\"",
                )
            } else {
                ResponseTemplate::new(405)
            }
        }
    }

    async fn sse_transport_with_get<R>(
        get_responder: R,
        denials: usize,
        refresh_steps: Vec<(u16, serde_json::Value)>,
    ) -> (
        Arc<McpOAuthManager>,
        Stub,
        Arc<crate::mcp_transport::SseTransport>,
    )
    where
        R: wiremock::Respond + Send + Sync + 'static,
    {
        let stub = stub_with(
            Some(serde_json::json!({"client_id": "cid"})),
            refresh_steps,
            Vec::new(),
        )
        .await;
        // GET on the SSE URL answers 405 (no stream) unless the caller
        // brings its own GET behavior: the transport falls back to the
        // derived message endpoint, which is the POST leg the tests below
        // pin. Advertised-endpoint tests seed the bookkeeping directly
        // (`set_advertised_endpoint_for_test`) instead of racing a stream
        // reader whose wiremock body EOFs immediately.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/mcp"))
            .respond_with(get_responder)
            .mount(&stub.mcp)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/mcp"))
            .respond_with(McpEndpoint {
                denials,
                hits: AtomicUsize::new(0),
            })
            .mount(&stub.mcp)
            .await;
        let manager = Arc::new(
            McpOAuthManager::with_launcher(
                stub.tmp.path(),
                true,
                Arc::new(AutoCallbackLauncher {
                    code: "c",
                    fail: false,
                    launches: AtomicUsize::new(0),
                }),
            )
            .expect("manager"),
        );
        manager
            .store
            .save_authorization(
                &CanonicalResource::from_configured(
                    &Url::parse(&format!("{}/mcp", stub.mcp.uri())).expect("url"),
                )
                .expect("canonical"),
                "cid",
                &Url::parse(&stub.as_.uri()).expect("issuer"),
                TokenSet {
                    access_token: "at-live".to_string(),
                    refresh_token: Some("rt-live".to_string()),
                    id_token: None,
                    expires_at: None,
                    token_type: Some("Bearer".to_string()),
                    scope: None,
                },
            )
            .await
            .expect("seed grant");
        let mut sse_config = stub.store.clone();
        sse_config.transport = zeroclaw_config::schema::McpTransport::Sse;
        let transport = Arc::new(
            crate::mcp_transport::SseTransport::new_with_oauth(
                &sse_config,
                Some(TransportOAuth::new(
                    Arc::clone(&manager),
                    sse_config.clone(),
                    false,
                )),
            )
            .expect("transport"),
        );
        (manager, stub, transport)
    }

    async fn sse_transport_with_live_grant(
        denials: usize,
        refresh_steps: Vec<(u16, serde_json::Value)>,
    ) -> (
        Arc<McpOAuthManager>,
        Stub,
        Arc<crate::mcp_transport::SseTransport>,
    ) {
        sse_transport_with_get(wiremock::ResponseTemplate::new(405), denials, refresh_steps).await
    }

    async fn send_sse(
        transport: &Arc<crate::mcp_transport::SseTransport>,
        lifecycle: &crate::mcp_transport::McpRequestLifecycle,
    ) -> Result<crate::mcp_protocol::JsonRpcResponse> {
        let request =
            crate::mcp_protocol::JsonRpcRequest::new(7, "tools/call", serde_json::json!({}));
        crate::mcp_transport::SharedMcpTransportConn::send_and_recv(
            transport.as_ref(),
            &request,
            lifecycle,
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sse_post_401_completes_the_lifecycle_refreshes_once_and_never_replays() {
        let (_manager, stub, transport) = sse_transport_with_live_grant(
            1,
            vec![(
                200,
                serde_json::json!({"access_token": "at-2", "refresh_token": "rt-2", "token_type": "Bearer", "expires_in": 3600}),
            )],
        )
        .await;
        let lifecycle = crate::mcp_transport::McpRequestLifecycle::uncoordinated(0);
        let err = send_sse(&transport, &lifecycle)
            .await
            .expect_err("SSE POST 401 surfaces, no replay");
        assert!(err.to_string().contains("401"), "got: {err}");
        assert_eq!(
            mcp_posts(&stub).await,
            1,
            "the POST leg is never replayed (pending-stream bookkeeping)"
        );
        let as_requests = stub.as_.received_requests().await.expect("received");
        assert_eq!(
            as_requests
                .iter()
                .filter(|r| r.url.path() == "/token")
                .count(),
            1,
            "best-effort refresh still runs for the NEXT attempt"
        );
        assert_eq!(
            lifecycle.outcome_unknown_epoch(),
            None,
            "a 401 proves the bearer was rejected before the message ran: \
             the write outcome is KNOWN (the one exception to SSE outcome-unknown)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sse_get_stream_carries_the_bearer_from_connect_onward() {
        let (_manager, stub, transport) = sse_transport_with_live_grant(0, vec![]).await;
        let lifecycle = crate::mcp_transport::McpRequestLifecycle::uncoordinated(0);
        let response = send_sse(&transport, &lifecycle)
            .await
            .expect("connect GET + derived POST succeed");
        assert_eq!(response.id, Some(serde_json::json!(7)));
        let gets: Vec<String> = stub
            .mcp
            .received_requests()
            .await
            .expect("received")
            .iter()
            .filter(|r| r.method.as_str() == "GET" && r.url.path() == "/mcp")
            .map(|r| {
                r.headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap_or_default().to_string())
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(
            gets,
            vec!["Bearer at-live".to_string()],
            "the stream GET is authenticated from the first connect (every restart re-reads the grant)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sse_get_401_refreshes_once_and_the_next_connect_carries_the_new_bearer() {
        // Phase-4 matrix: 401 on the STREAM leg. The stream is pre-write
        // and restartable, so the 401 must (a) fail this connect honestly,
        // (b) refresh the grant best-effort, and (c) the very next connect
        // must re-read the handle and present the ROTATED bearer — proof
        // the same auth handle survives a transport restart.
        let (_manager, stub, transport) = sse_transport_with_get(
            SseGetGate {
                denials: 1,
                hits: AtomicUsize::new(0),
            },
            0,
            vec![(
                200,
                serde_json::json!({"access_token": "at-2", "refresh_token": "rt-2", "token_type": "Bearer", "expires_in": 3600}),
            )],
        )
        .await;
        let lifecycle = crate::mcp_transport::McpRequestLifecycle::uncoordinated(0);
        let err = send_sse(&transport, &lifecycle)
            .await
            .expect_err("a 401 stream attempt fails the connect");
        assert!(err.to_string().contains("401"), "got: {err}");
        async fn token_calls(stub: &Stub) -> usize {
            stub.as_
                .received_requests()
                .await
                .expect("received")
                .iter()
                .filter(|r| r.url.path() == "/token")
                .count()
        }
        assert_eq!(
            token_calls(&stub).await,
            1,
            "the stream 401 refreshed the grant for the next attempt"
        );
        // Reconnect: same transport object (same handle), new attempt.
        let lifecycle = crate::mcp_transport::McpRequestLifecycle::uncoordinated(1);
        let response = send_sse(&transport, &lifecycle)
            .await
            .expect("the next connect presents the rotated bearer");
        assert_eq!(response.id, Some(serde_json::json!(7)));
        assert_eq!(
            token_calls(&stub).await,
            1,
            "the rotated grant is live: no second refresh"
        );
        let (gets, posts): (Vec<String>, Vec<String>) = {
            let all = stub.mcp.received_requests().await.expect("received");
            let get = |r: &wiremock::Request| {
                r.headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap_or_default().to_string())
                    .unwrap_or_default()
            };
            (
                all.iter()
                    .filter(|r| r.method.as_str() == "GET" && r.url.path() == "/mcp")
                    .map(get)
                    .collect(),
                all.iter()
                    .filter(|r| r.method.as_str() == "POST")
                    .map(get)
                    .collect(),
            )
        };
        assert_eq!(
            gets,
            vec!["Bearer at-live".to_string(), "Bearer at-2".to_string()],
            "connect #1 presented the live token, connect #2 the rotated one"
        );
        assert_eq!(
            posts,
            vec!["Bearer at-2".to_string()],
            "the message POST on the restarted transport uses the rotated grant too"
        );
    }

    #[tokio::test]
    async fn sse_advertised_endpoint_off_origin_is_rejected_before_the_bearer_leaves() {
        // Review S3-1: a hostile/compromised MCP server advertises the SSE
        // `endpoint` event on another origin; the bearer must never ride
        // there. The bookkeeping is pre-seeded (no stream race), and port 9
        // (discard) is deliberately unlistened: if the transport tried, the
        // stub would report an extra POST and the request itself would show.
        let (_manager, stub, transport) = sse_transport_with_live_grant(0, vec![]).await;
        transport
            .set_advertised_endpoint_for_test("http://127.0.0.1:9/collect")
            .await;
        let lifecycle = crate::mcp_transport::McpRequestLifecycle::uncoordinated(0);
        let err = send_sse(&transport, &lifecycle)
            .await
            .expect_err("off-origin advertised endpoint is refused");
        assert!(
            err.to_string().contains("share the configured MCP origin"),
            "got: {err}"
        );
        let posts = stub
            .mcp
            .received_requests()
            .await
            .expect("received")
            .iter()
            .filter(|r| r.method.as_str() == "POST")
            .count();
        assert_eq!(
            posts, 0,
            "the refused send must not POST anywhere with the bearer"
        );
    }

    #[tokio::test]
    async fn sse_advertised_endpoint_on_origin_is_adopted_and_authenticated() {
        // The check is an origin gate, not a ban: the server advertising its
        // own origin (the normal legacy-SSE shape) keeps working, bearer in
        // hand.
        let (_manager, stub, transport) = sse_transport_with_live_grant(0, vec![]).await;
        transport
            .set_advertised_endpoint_for_test(&format!("{}/mcp", stub.mcp.uri()))
            .await;
        let lifecycle = crate::mcp_transport::McpRequestLifecycle::uncoordinated(0);
        let response = send_sse(&transport, &lifecycle)
            .await
            .expect("advertised same-origin endpoint is adopted");
        assert_eq!(response.id, Some(serde_json::json!(7)));
        let authenticated_posts = stub
            .mcp
            .received_requests()
            .await
            .expect("received")
            .iter()
            .filter(|r| {
                r.method.as_str() == "POST"
                    && r.url.path() == "/mcp"
                    && r.headers
                        .get("authorization")
                        .is_some_and(|v| v.to_str().unwrap_or_default() == "Bearer at-live")
            })
            .count();
        assert_eq!(authenticated_posts, 1, "the POST carried the live bearer");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sse_post_does_not_hold_the_write_permit_across_the_bearer_fetch() {
        // Review S3-3: `bearer()` can cost a token round-trip (here: a
        // 600 ms slow refresh of the expired seed grant, taken proactively
        // before the write). That must NOT happen while the lifecycle's
        // epoch gate is read-held, or a recovery barrier — the write side
        // of the same gate — queues behind network latency.
        let gate: Arc<tokio::sync::RwLock<u64>> = Arc::new(tokio::sync::RwLock::new(0));
        let stub = stub_with(
            Some(serde_json::json!({"client_id": "cid"})),
            vec![(
                200,
                serde_json::json!({"access_token": "at-2", "token_type": "Bearer", "expires_in": 3600}),
            )],
            vec![600],
        )
        .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/mcp"))
            .respond_with(wiremock::ResponseTemplate::new(405))
            .mount(&stub.mcp)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/mcp"))
            .respond_with(McpEndpoint {
                denials: 0,
                hits: AtomicUsize::new(0),
            })
            .mount(&stub.mcp)
            .await;
        let manager = Arc::new(
            McpOAuthManager::with_launcher(
                stub.tmp.path(),
                true,
                Arc::new(AutoCallbackLauncher {
                    code: "c",
                    fail: false,
                    launches: AtomicUsize::new(0),
                }),
            )
            .expect("manager"),
        );
        manager
            .store
            .save_authorization(
                &CanonicalResource::from_configured(
                    &Url::parse(&format!("{}/mcp", stub.mcp.uri())).expect("url"),
                )
                .expect("canonical"),
                "cid",
                &Url::parse(&stub.as_.uri()).expect("issuer"),
                TokenSet {
                    access_token: "at-expired".to_string(),
                    refresh_token: Some("rt-live".to_string()),
                    id_token: None,
                    // Expired: `bearer()` proactively refreshes (the slow
                    // 600 ms token leg) before the transport writes.
                    expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
                    token_type: Some("Bearer".to_string()),
                    scope: None,
                },
            )
            .await
            .expect("seed grant");
        let mut sse_config = stub.store.clone();
        sse_config.transport = zeroclaw_config::schema::McpTransport::Sse;
        let transport = Arc::new(
            crate::mcp_transport::SseTransport::new_with_oauth(
                &sse_config,
                Some(TransportOAuth::new(
                    Arc::clone(&manager),
                    sse_config.clone(),
                    false,
                )),
            )
            .expect("transport"),
        );
        let lifecycle =
            crate::mcp_transport::McpRequestLifecycle::coordinated(Arc::clone(&gate), None);
        let send = zeroclaw_spawn::spawn!(async move {
            let request =
                crate::mcp_protocol::JsonRpcRequest::new(7, "tools/call", serde_json::json!({}));
            crate::mcp_transport::SharedMcpTransportConn::send_and_recv(
                transport.as_ref(),
                &request,
                &lifecycle,
            )
            .await
        });
        // Mid-flight: the bearer is still crossing the 600 ms token leg.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let barrier = tokio::time::timeout(Duration::from_millis(150), gate.write())
            .await
            .expect("a recovery barrier (epoch gate WRITE) must not queue behind the bearer fetch");
        drop(barrier);
        let response = send.await.expect("task").expect("send succeeds");
        assert_eq!(response.id, Some(serde_json::json!(7)));
    }

    #[test]
    fn sse_post_401_marks_completed_even_without_oauth() {
        // The lifecycle exception is about the PROOF a 401 gives
        // (bearer rejected at the door), not about OAuth being wired: a
        // plain 401 on a non-OAuth SSE server must also land
        // outcome-known, while every other non-success stays unknown
        // (pinned by `sse_post_404_is_not_replayed_to_derived_endpoint`).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/sse"))
                .respond_with(wiremock::ResponseTemplate::new(405))
                .mount(&server)
                .await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::path("/sse"))
                .respond_with(wiremock::ResponseTemplate::new(401))
                .mount(&server)
                .await;
            let config = zeroclaw_config::schema::McpServerConfig {
                name: "sse-plain-401".to_string(),
                transport: zeroclaw_config::schema::McpTransport::Sse,
                url: Some(format!("{}/sse", server.uri())),
                ..Default::default()
            };
            let transport = crate::mcp_transport::SseTransport::new(&config).expect("transport");
            let request =
                crate::mcp_protocol::JsonRpcRequest::new(7, "tools/call", serde_json::json!({}));
            let lifecycle = crate::mcp_transport::McpRequestLifecycle::uncoordinated(0);
            let err = crate::mcp_transport::SharedMcpTransportConn::send_and_recv(
                &transport, &request, &lifecycle,
            )
            .await
            .expect_err("401 surfaces");
            assert!(err.to_string().contains("401"), "got: {err}");
            assert_eq!(lifecycle.outcome_unknown_epoch(), None);
            let posts = server
                .received_requests()
                .await
                .expect("received")
                .iter()
                .filter(|r| r.method.as_str() == "POST")
                .count();
            assert_eq!(posts, 1, "no replay without OAuth either");
        });
    }

    #[test]
    fn grant_debug_redacts_tokens() {
        let grant = Grant {
            tokens: TokenSet {
                access_token: "topsecret".to_string(),
                refresh_token: Some("rtopsecret".to_string()),
                id_token: None,
                expires_at: None,
                token_type: Some("Bearer".to_string()),
                scope: None,
            },
            client_id: "cid".to_string(),
            issuer: Url::parse("https://auth.example").expect("u"),
        };
        let shown = format!("{grant:?}");
        assert!(!shown.contains("topsecret"), "Debug leaked tokens: {shown}");
    }

    fn seed_grant(
        manager: &Arc<McpOAuthManager>,
        stub: &Stub,
        issuer: &Url,
        access: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> impl std::future::Future<Output = ()> + 'static {
        let manager = Arc::clone(manager);
        let canonical = CanonicalResource::from_configured(
            &Url::parse(&format!("{}/mcp", stub.mcp.uri())).expect("canonical"),
        )
        .expect("canonical");
        let issuer = issuer.clone();
        let access = access.to_string();
        async move {
            manager
                .store
                .save_authorization(
                    &canonical,
                    "cid",
                    &issuer,
                    TokenSet {
                        access_token: access,
                        refresh_token: Some("rt-live".to_string()),
                        id_token: None,
                        expires_at,
                        token_type: Some("Bearer".to_string()),
                        scope: None,
                    },
                )
                .await
                .expect("seed grant");
        }
    }

    #[tokio::test]
    async fn issuer_drift_drops_the_grant_and_never_redeems_it_at_the_new_as() {
        // Review S3-4 acceptance: a stored grant minted by issuer A must not
        // be redeemed at issuer B (credential disclosure); the drift check
        // drops it and the flow asks for a fresh sign-in instead — and NO
        // request ever reaches the new AS's token endpoint.
        let stub = stub(Some(serde_json::json!({"client_id": "cid"})), vec![]).await;
        let manager = Arc::new(manager_with(
            &stub,
            Arc::new(AutoCallbackLauncher {
                code: "c",
                fail: false,
                launches: AtomicUsize::new(0),
            }),
        ));
        seed_grant(
            &manager,
            &stub,
            &Url::parse("https://issuer-a.example").expect("url"),
            "at-live",
            None,
        )
        .await;
        let err = manager
            .bearer_for(&stub.store, None, false)
            .await
            .expect_err("drifted grant must not be redeemed");
        assert!(
            err.to_string().contains("requires an OAuth sign-in"),
            "got: {err}"
        );
        let canonical = CanonicalResource::from_configured(
            &Url::parse(&format!("{}/mcp", stub.mcp.uri())).expect("url"),
        )
        .expect("canonical");
        assert!(
            manager
                .store
                .load_authorization(&canonical)
                .await
                .expect("load")
                .is_none(),
            "the drifted grant must be cleared from the store"
        );
        let token_calls = stub
            .as_
            .received_requests()
            .await
            .expect("received")
            .iter()
            .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/token")
            .count();
        assert_eq!(token_calls, 0, "no token leg may reach the new AS");
    }

    #[tokio::test]
    async fn issuer_trailing_slash_is_not_drift() {
        // The drift compare keeps `issuer_matches` semantics: trailing-slash
        // spellings of the SAME issuer must not force a pointless sign-out.
        let stub = stub(Some(serde_json::json!({"client_id": "cid"})), vec![]).await;
        let manager = Arc::new(manager_with(
            &stub,
            Arc::new(AutoCallbackLauncher {
                code: "c",
                fail: false,
                launches: AtomicUsize::new(0),
            }),
        ));
        let stored = Url::parse(&format!("{}/", stub.as_.uri())).expect("url");
        seed_grant(&manager, &stub, &stored, "at-live", None).await;
        let bearer = manager
            .bearer_for(&stub.store, None, false)
            .await
            .expect("same issuer, one trailing slash: the live grant stands");
        assert_eq!(bearer, "Bearer at-live");
        let canonical = CanonicalResource::from_configured(
            &Url::parse(&format!("{}/mcp", stub.mcp.uri())).expect("url"),
        )
        .expect("canonical");
        assert!(
            manager
                .store
                .load_authorization(&canonical)
                .await
                .expect("load")
                .is_some(),
            "no drift: the grant must not be dropped"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refreshed_bearer_survives_an_unwritable_store() {
        // Review S3-5 acceptance: the token endpoint rotated the grant (the
        // old refresh token is now DEAD) and the disk write fails — the
        // process must still run on the NEW bearer, not strand the operator
        // on a dead token until a browser sign-in.
        use std::os::unix::fs::PermissionsExt;
        // The store's lock needs fresh-create rights, so a read-only
        // directory would break LOAD as well. The sequence isolates SAVE:
        // call #1 (writable) consumes the load-once probe; then chmod 500
        // makes the lock file creation — and therefore every write — fail
        // while reads still work, exactly the "rotated in memory, dead on
        // disk" shape the WARN path exists for.
        let stub = stub_with(
            Some(serde_json::json!({"client_id": "cid"})),
            vec![(
                200,
                serde_json::json!({"access_token": "at-2", "token_type": "Bearer", "expires_in": 3600}),
            )],
            Vec::new(),
        )
        .await;
        let manager = Arc::new(manager_with(
            &stub,
            Arc::new(AutoCallbackLauncher {
                code: "c",
                fail: false,
                launches: AtomicUsize::new(0),
            }),
        ));
        seed_grant(
            &manager,
            &stub,
            &Url::parse(&stub.as_.uri()).expect("url"),
            "at-live",
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
        .await;
        // #1: healthy load, live grant, no refresh.
        let first = manager
            .bearer_for(&stub.store, None, false)
            .await
            .expect("healthy first call");
        assert_eq!(first, "Bearer at-live");
        // Break persistence (reads still fine, the load already happened).
        std::fs::set_permissions(stub.tmp.path(), std::fs::Permissions::from_mode(0o500))
            .expect("chmod store read-only");
        // #2: 401-driven rotation with an unwritable store.
        let rotated = manager
            .on_unauthorized(&stub.store, None, "Bearer at-live", false)
            .await
            .unwrap_or_else(|err| panic!("full error chain: {err:#}"));
        std::fs::set_permissions(stub.tmp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod store back");
        assert_eq!(
            rotated, "Bearer at-2",
            "a failed store write must not fail the rotated grant"
        );
        // Pin that the SAVE actually failed: a root environment with
        // CAP_DAC_OVERRIDE would silently succeed and pass this test
        // without ever touching the WARN path.
        let persisted = manager
            .store
            .load_authorization(
                &CanonicalResource::from_configured(
                    &Url::parse(&format!("{}/mcp", stub.mcp.uri())).expect("url"),
                )
                .expect("canonical"),
            )
            .await
            .expect("readable again")
            .expect("the stale grant is still what survived on disk");
        assert_eq!(
            persisted.tokens.access_token, "at-live",
            "the rotated token never reached the disk — the WARN path ran"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slow_first_sign_in_survives_the_initialize_handshake_timeout() {
        // Live incident regression against a real authorization server: the
        // interactive sign-in wait ran inside the `initialize` send and so
        // inside the client handshake's 30s receive budget. A human slower
        // than that budget had the wait canceled: the loopback listener was
        // dropped mid-browser-flow and the callback hit a dead port. The
        // transport now prepares credentials (`prepare_auth`) before the
        // request-budgeted handshake, so sign-in keeps its own, human-paced
        // callback budget.
        let s = stub(
            Some(serde_json::json!({"client_id": "cid-slow"})),
            vec![(
                200,
                serde_json::json!({
                    "access_token": "at-slow",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "rt-slow",
                    "scope": "mcp:tools",
                }),
            )],
        )
        .await;
        // MCP JSON-RPC side: every POST must already carry the freshly
        // obtained bearer — an unauthenticated handshake POST means the
        // sign-in-before-first-request ordering regressed.
        for (rpc_method, response) in [
            (
                "initialize",
                wiremock::ResponseTemplate::new(200)
                    .insert_header("Mcp-Session-Id", "sess-slow")
                    .set_body_json(serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
            ),
            (
                "tools/list",
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {"tools": [{"name": "slow_tool", "description": "d",
                                          "inputSchema": {"type": "object"}}]}
                })),
            ),
        ] {
            Mock::given(method("POST"))
                .and(path("/mcp"))
                .and(wiremock::matchers::body_partial_json(serde_json::json!(
                    {"method": rpc_method}
                )))
                .and(wiremock::matchers::header(
                    "authorization",
                    "Bearer at-slow",
                ))
                .respond_with(response)
                .mount(&s.mcp)
                .await;
        }
        Mock::given(method("POST"))
            .and(path("/mcp"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!(
                {"method": "notifications/initialized"}
            )))
            .respond_with(wiremock::ResponseTemplate::new(202))
            .mount(&s.mcp)
            .await;

        // 35s is strictly greater than `mcp_client::RECV_TIMEOUT_SECS` (30):
        // before the fix, the handshake timed out long before the simulated
        // human delivered the callback.
        let launcher = Arc::new(SlowHumanLauncher {
            code: "code-slow",
            delay: Duration::from_secs(35),
        });
        let manager = Arc::new(manager_with(&s, launcher));
        let oauth = TransportOAuth::new(manager, s.store.clone(), true);

        let started = std::time::Instant::now();
        let server = crate::mcp_client::McpServer::connect_with_oauth(s.store.clone(), Some(oauth))
            .await
            .expect("a 35s interactive sign-in must not be canceled by the handshake timeout");
        assert!(
            started.elapsed() >= Duration::from_secs(33),
            "the launcher delay never applied — the test would not exercise the timeout"
        );
        assert_eq!(
            s.mcp
                .received_requests()
                .await
                .expect("received")
                .iter()
                .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/mcp")
                .count(),
            3,
            "the full authenticated connect sequence (initialize + notification + \
             tools/list) ran over /mcp"
        );
        let _ = &server;
        assert_eq!(
            s.as_
                .received_requests()
                .await
                .expect("received")
                .iter()
                .filter(|r| r.url.path() == "/token")
                .count(),
            1,
            "exactly one token exchange across the whole connect"
        );
    }
}
