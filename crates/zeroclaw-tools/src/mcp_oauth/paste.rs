//! Manual-paste fallback for the browser-flow callback (design §13.1).
//!
//! When the browser cannot reach ZeroClaw's loopback listener (ZeroClaw in
//! a container, the operator's browser on another machine, an SSH tunnel
//! that rewrote `host:port`), the flow still ends somewhere visible: the
//! final URL in the browser's address bar. The operator pastes that URL
//! into the terminal, and `classify_callback_url` grades it with exactly
//! the rules the socket callback would have gotten — the pasted text
//! carries no more authority than the callback itself, and the token
//! exchange keeps posting the ORIGINAL `redirect_uri` the code was minted
//! with (RFC 6749 §4.1.3), so the address-bar rewrite is irrelevant.
//!
//! Process stdin is read ONLY for the explicit admin command
//! (`zeroclaw mcp signin`; see the `allow_stdin_paste` note in
//! `manager::authorize`), whose process exits once the flow ends - so
//! the reader never races another stdin owner for a line. Agent-turn
//! sign-ins never touch stdin and stay browser + listener only. The
//! injected paste feed (`McpOAuthManager::paste_feed`) owns no stdin
//! and remains available to every caller.

use tokio::sync::mpsc;

/// Forward terminal lines to the waiting flow until the flow stops
/// listening, stdin hits EOF, or a read fails. On its own thread because
/// `Stdin::lines` is a blocking read the async runtime must not host.
/// When the receiver drops (flow finished by browser callback, timeout,
/// or cancellation) the reader notices on the NEXT line: a blocking
/// stdin read cannot be preempted portably, and that line is consumed
/// and discarded. This path is enabled only for the admin sign-in
/// command, whose process exits at exactly that moment, so no other
/// component is waiting on that stdin.
pub(crate) fn spawn_stdin_reader(tx: mpsc::Sender<String>) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let mut lines = stdin.lock().lines();
        loop {
            match lines.next() {
                Some(Ok(line)) => {
                    if tx.blocking_send(line).is_err() {
                        return;
                    }
                }
                // EOF, or a read error the stream cannot recover from
                // line-by-line: stop rather than spin on phantom lines.
                Some(Err(_)) | None => return,
            }
        }
    });
}
