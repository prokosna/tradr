//! Own tests for WI-M0-008c's step 3: the loopback listener that hands
//! `parse_callback` a real request line read off a socket. Each case binds
//! a fresh listener on port 0, so none depends on another having run, and
//! none waits on wall-clock time -- the client thread writes its request
//! line as soon as it connects.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use tradr_oidc::{OidcError, serve_one_callback};

const STATE: &str = "loopback-test-state";

fn bound_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").expect("binding a loopback listener on port 0 must succeed")
}

// Connects to `port`, writes `request_line`, then reads the response to
// completion so the server's write finishes before this connection closes.
fn send_request_line(port: u16, request_line: &str) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .expect("connecting to the just-bound loopback listener must succeed");
    stream
        .write_all(request_line.as_bytes())
        .expect("writing the request line must succeed");

    let mut response = Vec::new();
    if let Err(e) = stream.read_to_end(&mut response) {
        panic!("reading the server's response failed: {e}");
    }
}

#[test]
fn a_well_formed_callback_yields_its_code() {
    let listener = bound_listener();
    let port = listener
        .local_addr()
        .expect("a bound listener has a local address")
        .port();

    let client = std::thread::spawn(move || {
        send_request_line(
            port,
            "GET /callback?code=abc123&state=loopback-test-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
    });

    let result = serve_one_callback(&listener, STATE);
    client.join().expect("the client thread must not panic");

    assert_eq!(result, Ok("abc123".to_string()));
}

#[test]
fn a_callback_with_the_wrong_state_is_refused() {
    let listener = bound_listener();
    let port = listener
        .local_addr()
        .expect("a bound listener has a local address")
        .port();

    let client = std::thread::spawn(move || {
        send_request_line(
            port,
            "GET /callback?code=abc123&state=someone-elses-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
    });

    let result = serve_one_callback(&listener, STATE);
    client.join().expect("the client thread must not panic");

    assert_eq!(result, Err(OidcError::StateMismatch));
}

#[test]
fn a_request_line_with_no_query_string_is_refused() {
    let listener = bound_listener();
    let port = listener
        .local_addr()
        .expect("a bound listener has a local address")
        .port();

    let client = std::thread::spawn(move || {
        send_request_line(port, "GET /callback HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    });

    let result = serve_one_callback(&listener, STATE);
    client.join().expect("the client thread must not panic");

    assert_eq!(result, Err(OidcError::StateMismatch));
}
