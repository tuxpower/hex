//! PKCE OAuth 2.0 flow for Google Calendar and Microsoft Outlook.
//!
//! No additional crates: PKCE challenge uses `sha2` + `getrandom`; the token
//! exchange and refresh use `ureq`; the redirect listener uses
//! `std::net::TcpListener`; URL encoding uses `url::form_urlencoded`.
//!
//! Entry points:
//! - [`start_connect`]: opens the browser and returns a [`PendingConnect`]
//!   whose [`PendingConnect::finish`] blocks until the redirect arrives.
//! - [`refresh_access_token`]: exchanges a saved refresh token for a new
//!   access token.
//! - [`fetch_events`]: reads calendar events for the next 48 hours.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use url::form_urlencoded;

use crate::app_settings::{OAuthCalendarAccount, OAuthCalendarProvider};

// ── OAuth endpoints ──────────────────────────────────────────────────────────

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v3/userinfo";
const GOOGLE_EVENTS_URL: &str =
    "https://www.googleapis.com/calendar/v3/calendars/primary/events";
const GOOGLE_CLIENT_ID: &str =
    "935823084237-hexapp.apps.googleusercontent.com";
const GOOGLE_SCOPES: &str =
    "https://www.googleapis.com/auth/calendar.events.readonly \
     https://www.googleapis.com/auth/userinfo.email";

const MICROSOFT_AUTH_URL: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const MICROSOFT_TOKEN_URL: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const MICROSOFT_GRAPH_ME_URL: &str = "https://graph.microsoft.com/v1.0/me";
const MICROSOFT_EVENTS_URL: &str =
    "https://graph.microsoft.com/v1.0/me/calendarView";
const MICROSOFT_CLIENT_ID: &str = "b9f7e8d1-4c2a-4f3e-8a1b-0c5d6e7f8a9b";
const MICROSOFT_SCOPES: &str =
    "offline_access https://graph.microsoft.com/Calendars.Read \
     https://graph.microsoft.com/User.Read";

// Redirect port range: 49152–49252 (first-fit, local loopback only).
const PORT_MIN: u16 = 49152;
const PORT_MAX: u16 = 49252;

// ── PKCE helpers ─────────────────────────────────────────────────────────────

/// 32-byte random verifier encoded as base64url (no padding).
pub(crate) fn pkce_verifier() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("getrandom");
    base64url_encode(&buf)
}

/// SHA-256 of the verifier, base64url-encoded (S256 method).
pub(crate) fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64url_encode(&digest)
}

/// Base64url encoding without padding, as RFC 7636 requires.
pub(crate) fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = (bytes[i] as u32) << 16 | (bytes[i + 1] as u32) << 8 | bytes[i + 2] as u32;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        1 => {
            let n = (bytes[i] as u32) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let n = (bytes[i] as u32) << 16 | (bytes[i + 1] as u32) << 8;
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => {}
    }
    out
}

// ── Token exchange ────────────────────────────────────────────────────────────

#[derive(Debug)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    /// Seconds until expiry (from the `expires_in` field).
    expires_in: u64,
}

impl TokenResponse {
    fn expires_at(&self) -> u64 {
        unix_now() + self.expires_in.saturating_sub(60)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_token_response(body: &str) -> Result<TokenResponse, String> {
    let obj: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("token JSON: {e}"))?;
    if let Some(err) = obj.get("error").and_then(|v| v.as_str()) {
        let desc = obj
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or(err);
        return Err(format!("OAuth error: {desc}"));
    }
    Ok(TokenResponse {
        access_token: obj
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or("missing access_token")?
            .to_owned(),
        refresh_token: obj
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        expires_in: obj
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600),
    })
}

// ── Pending connect ───────────────────────────────────────────────────────────

/// An in-progress OAuth connect: the redirect listener is already bound.
/// Call [`finish`](PendingConnect::finish) on a background thread to block
/// until the browser delivers the code.
pub struct PendingConnect {
    provider: OAuthCalendarProvider,
    listener: TcpListener,
    redirect_uri: String,
    verifier: String,
    state: String,
}

/// Open the browser at the provider's authorization URL, bind a local redirect
/// listener, and return a [`PendingConnect`] ready to receive the code.
pub fn start_connect(provider: OAuthCalendarProvider) -> Result<PendingConnect, String> {
    // Bind the listener before opening the browser so the port is ready.
    let (listener, port) = bind_redirect_listener()?;
    let redirect_uri = format!("http://127.0.0.1:{port}/oauth");

    let verifier = pkce_verifier();
    let challenge = pkce_challenge(&verifier);

    // One-time state token to prevent CSRF.
    let mut state_buf = [0u8; 16];
    getrandom::fill(&mut state_buf).expect("getrandom");
    let state = base64url_encode(&state_buf);

    let url = match provider {
        OAuthCalendarProvider::Google => {
            let params = form_urlencoded::Serializer::new(String::new())
                .append_pair("client_id", GOOGLE_CLIENT_ID)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", GOOGLE_SCOPES)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("state", &state)
                .append_pair("access_type", "offline")
                .append_pair("prompt", "consent")
                .finish();
            format!("{GOOGLE_AUTH_URL}?{params}")
        }
        OAuthCalendarProvider::Microsoft => {
            let params = form_urlencoded::Serializer::new(String::new())
                .append_pair("client_id", MICROSOFT_CLIENT_ID)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", MICROSOFT_SCOPES)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("state", &state)
                .finish();
            format!("{MICROSOFT_AUTH_URL}?{params}")
        }
    };

    open_browser(&url)?;

    Ok(PendingConnect {
        provider,
        listener,
        redirect_uri,
        verifier,
        state,
    })
}

impl PendingConnect {
    /// Block until the browser delivers the authorization code, then exchange
    /// it for tokens and read the account email.
    pub fn finish(self) -> Result<OAuthCalendarAccount, String> {
        let code = self.wait_for_code()?;
        let tokens = exchange_code(
            self.provider,
            &code,
            &self.redirect_uri,
            &self.verifier,
        )?;
        let email = fetch_email(self.provider, &tokens.access_token)?;
        Ok(OAuthCalendarAccount {
            provider: self.provider,
            email,
            access_token: tokens.access_token,
            refresh_token: tokens
                .refresh_token
                .ok_or("provider did not return a refresh token")?,
            expires_at: tokens.expires_at(),
        })
    }

    fn wait_for_code(&self) -> Result<String, String> {
        self.listener
            .set_nonblocking(false)
            .map_err(|e| format!("listener: {e}"))?;
        // Accept one connection; the browser sends one GET to /oauth?code=…
        let (mut stream, _) = self
            .listener
            .accept()
            .map_err(|e| format!("accept: {e}"))?;

        // Read the first line of the HTTP request in a block so the borrow
        // on stream ends before we write the response.
        let request_line = {
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|e| format!("read: {e}"))?;
            line
        };

        // Respond with a minimal HTML page so the browser shows something.
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
            <html><body><h2>Hex: calendar connected.</h2>\
            <p>You can close this tab.</p></body></html>";
        let _ = stream.write_all(response.as_bytes());

        // Parse ?code= and ?state= from "GET /oauth?… HTTP/1.1"
        let path = request_line
            .split_whitespace()
            .nth(1)
            .ok_or("bad HTTP request")?;
        let query = path.splitn(2, '?').nth(1).unwrap_or("");
        let mut code = None;
        let mut returned_state = None;
        for (k, v) in form_urlencoded::parse(query.as_bytes()) {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => returned_state = Some(v.into_owned()),
                "error" => return Err(format!("OAuth denied: {v}")),
                _ => {}
            }
        }
        if returned_state.as_deref() != Some(&self.state) {
            return Err("OAuth state mismatch (possible CSRF)".into());
        }
        code.ok_or_else(|| "no code in redirect".into())
    }
}

fn exchange_code(
    provider: OAuthCalendarProvider,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<TokenResponse, String> {
    let (token_url, client_id) = token_endpoint(provider);
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("client_id", client_id)
        .append_pair("code_verifier", verifier)
        .finish();
    post_form(token_url, &body)
}

/// Exchange a saved refresh token for a new access token; updates `account`
/// in place on success.
pub fn refresh_access_token(account: &mut OAuthCalendarAccount) -> Result<(), String> {
    let (token_url, client_id) = token_endpoint(account.provider);
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("refresh_token", &account.refresh_token)
        .append_pair("client_id", client_id)
        .finish();
    let tokens = post_form(token_url, &body)?;
    account.access_token = tokens.access_token;
    account.expires_at = tokens.expires_at();
    if let Some(new_refresh) = tokens.refresh_token {
        account.refresh_token = new_refresh;
    }
    Ok(())
}

/// Ensure `account.access_token` is fresh; refreshes if within 60 s of expiry.
pub fn ensure_fresh(account: &mut OAuthCalendarAccount) -> Result<(), String> {
    if account.expires_at > unix_now() {
        return Ok(());
    }
    refresh_access_token(account)
}

fn token_endpoint(provider: OAuthCalendarProvider) -> (&'static str, &'static str) {
    match provider {
        OAuthCalendarProvider::Google => (GOOGLE_TOKEN_URL, GOOGLE_CLIENT_ID),
        OAuthCalendarProvider::Microsoft => (MICROSOFT_TOKEN_URL, MICROSOFT_CLIENT_ID),
    }
}

fn post_form(url: &str, body: &str) -> Result<TokenResponse, String> {
    let agent = crate::net::agent(url, |c| c);
    let mut response = agent
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .map_err(|e| format!("POST {url}: {e}"))?;
    let text = response
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("read body: {e}"))?;
    parse_token_response(&text)
}

// ── Account info ──────────────────────────────────────────────────────────────

fn fetch_email(provider: OAuthCalendarProvider, access_token: &str) -> Result<String, String> {
    let url = match provider {
        OAuthCalendarProvider::Google => GOOGLE_USERINFO_URL,
        OAuthCalendarProvider::Microsoft => MICROSOFT_GRAPH_ME_URL,
    };
    let body = get_json(url, access_token)?;
    let obj: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("userinfo JSON: {e}"))?;
    // Google: { "email": "…" }  Microsoft: { "mail": "…" or "userPrincipalName": "…" }
    obj.get("email")
        .or_else(|| obj.get("mail"))
        .or_else(|| obj.get("userPrincipalName"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "could not read email from provider".into())
}

// ── Calendar events ───────────────────────────────────────────────────────────

/// A single calendar event returned by the provider.
#[derive(Debug)]
pub struct OAuthEvent {
    pub title: String,
    /// RFC 3339 start time.
    pub start: String,
    /// RFC 3339 end time.
    pub end: String,
    pub location: Option<String>,
}

/// Read the next 48 hours of calendar events from `account`, refreshing its
/// token if needed.
pub fn fetch_events(
    account: &mut OAuthCalendarAccount,
) -> Result<Vec<OAuthEvent>, String> {
    ensure_fresh(account)?;
    match account.provider {
        OAuthCalendarProvider::Google => fetch_google_events(account),
        OAuthCalendarProvider::Microsoft => fetch_microsoft_events(account),
    }
}

fn fetch_google_events(account: &OAuthCalendarAccount) -> Result<Vec<OAuthEvent>, String> {
    let now = chrono_now_rfc3339();
    let then = chrono_plus_48h_rfc3339();
    let params = form_urlencoded::Serializer::new(String::new())
        .append_pair("timeMin", &now)
        .append_pair("timeMax", &then)
        .append_pair("singleEvents", "true")
        .append_pair("orderBy", "startTime")
        .append_pair("maxResults", "50")
        .finish();
    let url = format!("{GOOGLE_EVENTS_URL}?{params}");
    let body = get_json(&url, &account.access_token)?;
    parse_google_events(&body)
}

fn parse_google_events(body: &str) -> Result<Vec<OAuthEvent>, String> {
    let obj: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("events JSON: {e}"))?;
    let items = obj.get("items").and_then(|v| v.as_array()).ok_or("no items")?;
    let mut events = Vec::new();
    for item in items {
        let title = item
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("(no title)")
            .to_owned();
        let start = item
            .pointer("/start/dateTime")
            .or_else(|| item.pointer("/start/date"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let end = item
            .pointer("/end/dateTime")
            .or_else(|| item.pointer("/end/date"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let location = item
            .get("location")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        events.push(OAuthEvent { title, start, end, location });
    }
    Ok(events)
}

fn fetch_microsoft_events(account: &OAuthCalendarAccount) -> Result<Vec<OAuthEvent>, String> {
    let now = chrono_now_rfc3339();
    let then = chrono_plus_48h_rfc3339();
    let params = form_urlencoded::Serializer::new(String::new())
        .append_pair("startDateTime", &now)
        .append_pair("endDateTime", &then)
        .append_pair("$top", "50")
        .append_pair("$orderby", "start/dateTime")
        .finish();
    let url = format!("{MICROSOFT_EVENTS_URL}?{params}");
    let body = get_json(&url, &account.access_token)?;
    parse_microsoft_events(&body)
}

fn parse_microsoft_events(body: &str) -> Result<Vec<OAuthEvent>, String> {
    let obj: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("events JSON: {e}"))?;
    let items = obj
        .get("value")
        .and_then(|v| v.as_array())
        .ok_or("no value array")?;
    let mut events = Vec::new();
    for item in items {
        let title = item
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or("(no title)")
            .to_owned();
        let start = item
            .pointer("/start/dateTime")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let end = item
            .pointer("/end/dateTime")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let location = item
            .get("location")
            .and_then(|loc| loc.get("displayName"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        events.push(OAuthEvent { title, start, end, location });
    }
    Ok(events)
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn get_json(url: &str, bearer: &str) -> Result<String, String> {
    let agent = crate::net::agent(url, |c| c);
    let mut response = agent
        .get(url)
        .header("Authorization", &format!("Bearer {bearer}"))
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    response
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("read body: {e}"))
}

fn bind_redirect_listener() -> Result<(TcpListener, u16), String> {
    for port in PORT_MIN..=PORT_MAX {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            return Ok((listener, port));
        }
    }
    Err(format!(
        "no port available in {PORT_MIN}–{PORT_MAX} for the OAuth redirect"
    ))
}

fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .map_err(|e| format!("open: {e}"))?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map_err(|e| format!("xdg-open: {e}"))?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", "", url])
            .spawn()
            .map_err(|e| format!("cmd /c start: {e}"))?;
    }
    Ok(())
}

/// RFC 3339 timestamp for now (UTC, no sub-second precision).
fn chrono_now_rfc3339() -> String {
    let secs = unix_now();
    unix_secs_to_rfc3339(secs)
}

/// RFC 3339 timestamp 48 hours from now.
fn chrono_plus_48h_rfc3339() -> String {
    unix_secs_to_rfc3339(unix_now() + 48 * 3600)
}

fn unix_secs_to_rfc3339(secs: u64) -> String {
    // Simple implementation: no chrono dependency, just arithmetic.
    // Good for Unix timestamps from 2001-09-09 to 2038+.
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Days since 1970-01-01.
    let mut y = 1970u64;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let leap = is_leap(y);
    let months = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 0u64;
    for dm in months {
        if days < dm {
            break;
        }
        days -= dm;
        mo += 1;
    }
    (y, mo + 1, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_encode_known_vectors() {
        // RFC 4648 §10 test vectors, standard alphabet → base64url without padding.
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn pkce_verifier_is_43_or_44_chars_base64url() {
        let v = pkce_verifier();
        // 32 bytes → ceil(32*4/3) = 43 base64url chars (no padding).
        assert_eq!(v.len(), 43);
        assert!(v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn pkce_challenge_is_valid_sha256_base64url() {
        let v = pkce_verifier();
        let c = pkce_challenge(&v);
        // SHA-256 is 32 bytes → 43 base64url chars.
        assert_eq!(c.len(), 43);
        assert!(c.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn pkce_verifier_and_challenge_differ() {
        let v = pkce_verifier();
        let c = pkce_challenge(&v);
        assert_ne!(v, c);
    }

    #[test]
    fn unix_secs_to_rfc3339_epoch() {
        assert_eq!(unix_secs_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn unix_secs_to_rfc3339_known() {
        // 2024-01-15T12:30:45Z  →  1705319445
        assert_eq!(unix_secs_to_rfc3339(1705319445), "2024-01-15T12:30:45Z");
    }

    #[test]
    fn parse_google_events_empty() {
        let body = r#"{"kind":"calendar#events","items":[]}"#;
        let events = parse_google_events(body).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_google_events_one() {
        let body = r#"{
            "items": [{
                "summary": "Stand-up",
                "start": {"dateTime": "2024-01-15T09:00:00Z"},
                "end":   {"dateTime": "2024-01-15T09:15:00Z"},
                "location": "Zoom"
            }]
        }"#;
        let events = parse_google_events(body).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].title, "Stand-up");
        assert_eq!(events[0].start, "2024-01-15T09:00:00Z");
        assert_eq!(events[0].location.as_deref(), Some("Zoom"));
    }

    #[test]
    fn parse_microsoft_events_one() {
        let body = r#"{
            "value": [{
                "subject": "1:1",
                "start": {"dateTime": "2024-01-15T14:00:00"},
                "end":   {"dateTime": "2024-01-15T14:30:00"},
                "location": {"displayName": "Teams"}
            }]
        }"#;
        let events = parse_microsoft_events(body).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].title, "1:1");
        assert_eq!(events[0].location.as_deref(), Some("Teams"));
    }

    #[test]
    fn parse_token_response_success() {
        let body = r#"{
            "access_token": "at",
            "refresh_token": "rt",
            "expires_in": 3600
        }"#;
        let t = parse_token_response(body).unwrap();
        assert_eq!(t.access_token, "at");
        assert_eq!(t.refresh_token.as_deref(), Some("rt"));
        assert_eq!(t.expires_in, 3600);
    }

    #[test]
    fn parse_token_response_error() {
        let body = r#"{"error":"invalid_grant","error_description":"Token has been expired"}"#;
        let err = parse_token_response(body).unwrap_err();
        assert!(err.contains("Token has been expired"));
    }
}
