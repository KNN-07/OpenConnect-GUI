//! GlobalProtect completion decoding, not a second VPN authentication client.
//!
//! Protocol semantics adapted from GPL-3.0 GlobalProtect-openconnect, commit
//! 9e4f45997ebee452c58d7d3066dcfc175d65ef82, crates/gpapi/src/auth.rs and
//! utils/base64.rs (https://github.com/yuezk/GlobalProtect-openconnect).
//! Unlike its regex parser, this parser never includes remote payloads in errors.
//! The caller must authenticate the completion origin/phase and confirm the account.

use base64::{Engine, engine::general_purpose::STANDARD};
use ocvpn_model::{Error, ErrorCode, Result};
use quick_xml::{Reader, events::Event};
use zeroize::Zeroizing;

const MAX_INPUT: usize = 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_EVENTS: usize = 32_768;
const FIELDS: [&[u8]; 4] = [
    b"saml-auth-status",
    b"saml-username",
    b"prelogin-cookie",
    b"portal-userauthcookie",
];

/// Sensitive completion data; deliberately has no Debug or serialization implementation.
pub struct GpCompletion {
    pub username: Zeroizing<String>,
    pub cookie_name: String,
    pub cookie: Zeroizing<String>,
}

fn malformed() -> Error {
    Error::new(
        ErrorCode::InvalidInput,
        "Invalid or excessive GlobalProtect completion data",
    )
}

fn unsupported_cas() -> Error {
    Error::new(
        ErrorCode::UnsupportedAuthentication,
        "GlobalProtect CAS token completion is not supported by the pinned OpenConnect SSO detector; use embedded authentication",
    )
}

/// Decode only the GP custom scheme and standard padded base64 used by GP.
/// Slash prefixes are accepted as in the reference, but never interpreted as a URL.
pub fn decode_callback(input: &str) -> Result<Zeroizing<String>> {
    if input.len() > MAX_INPUT {
        return Err(malformed());
    }
    let payload = input
        .strip_prefix("globalprotectcallback:")
        .ok_or_else(malformed)?
        .trim_start_matches('/');
    if payload.starts_with("cas-as") {
        return Err(unsupported_cas());
    }
    if payload.is_empty() {
        return Err(malformed());
    }
    // decode_vec writes into a zeroizing allocation even when decoding fails partway.
    let mut decoded = Zeroizing::new(Vec::with_capacity(payload.len() / 4 * 3 + 3));
    STANDARD
        .decode_vec(payload, &mut decoded)
        .map_err(|_| malformed())?;
    let text = std::str::from_utf8(&decoded).map_err(|_| malformed())?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Parse completion HTML or XML, including GP's XML-inside-comment representation.
/// Only predefined XML escapes and numeric character references are allowed;
/// DTDs, custom entities, nested credential markup and duplicate fields are rejected.
pub fn parse_completion(input: &str) -> Result<GpCompletion> {
    parse_completion_if_present(input)?.ok_or_else(|| {
        Error::new(
            ErrorCode::AuthenticationRejected,
            "GlobalProtect did not report successful SAML authentication",
        )
    })
}

/// Ordinary login documents are not completion failures. Partial or contradictory
/// completion fields still fail rather than being merged across navigations.
pub fn parse_completion_if_present(input: &str) -> Result<Option<GpCompletion>> {
    if input.is_empty() || input.len() > MAX_INPUT || input.chars().any(|c| !xml_char(c)) {
        return Err(malformed());
    }
    if input.trim_start().starts_with("cas-as") {
        return Err(unsupported_cas());
    }
    let mut fields: [Option<Zeroizing<String>>; 4] = Default::default();
    let mut events = 0;
    parse_fragment(input, &mut fields, &mut events, 0)?;
    if fields.iter().all(Option::is_none) {
        return Ok(None);
    }
    if fields[0].as_deref().map(|s| s.as_str()) != Some("1") {
        return Err(Error::new(
            ErrorCode::AuthenticationRejected,
            "GlobalProtect did not report successful SAML authentication",
        ));
    }
    let username = fields[1]
        .take()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(malformed)?;
    let (cookie_name, cookie) = match (fields[2].take(), fields[3].take()) {
        (Some(cookie), None) => ("prelogin-cookie", cookie),
        (None, Some(cookie)) => ("portal-userauthcookie", cookie),
        _ => return Err(malformed()),
    };
    // These become native header values: never permit header injection or NUL.
    if cookie.trim().is_empty() || username.chars().chain(cookie.chars()).any(char::is_control) {
        return Err(malformed());
    }
    Ok(Some(GpCompletion {
        username,
        cookie_name: cookie_name.to_owned(),
        cookie,
    }))
}

fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

fn html_void(name: &[u8]) -> bool {
    [
        b"area".as_slice(),
        b"base",
        b"br",
        b"col",
        b"embed",
        b"hr",
        b"img",
        b"input",
        b"link",
        b"meta",
        b"param",
        b"source",
        b"track",
        b"wbr",
    ]
    .iter()
    .any(|item| name.eq_ignore_ascii_case(item))
}

fn parse_fragment(
    input: &str,
    fields: &mut [Option<Zeroizing<String>>; 4],
    events: &mut usize,
    outer_depth: usize,
) -> Result<()> {
    let mut reader = Reader::from_str(input);
    // Match ourselves to support HTML void tags without copying element names.
    reader.config_mut().check_end_names = false;
    reader.config_mut().allow_unmatched_ends = true;
    reader.config_mut().check_comments = true;
    let mut stack: Vec<(&[u8], usize)> = Vec::new();
    let mut active: Option<usize> = None;
    let mut suppressed: Option<usize> = None;
    loop {
        *events += 1;
        if *events > MAX_EVENTS {
            return Err(malformed());
        }
        match reader.read_event().map_err(|_| malformed())? {
            Event::Start(tag) | Event::Empty(tag) => {
                // The reader position identifies '/>' without a second parse or allocation.
                let end = reader.buffer_position() as usize;
                let empty = input.as_bytes()[..end].ends_with(b"/>");
                let name_len = tag.name().as_ref().len();
                let content_end = end - if empty { 2 } else { 1 };
                let raw = &input.as_bytes()[content_end - tag.as_ref().len()..content_end];
                let name = &raw[..name_len];
                if outer_depth + stack.len() + 1 > MAX_DEPTH || active.is_some() {
                    return Err(malformed());
                }
                // Attributes are not completion fields, but must not carry entity declarations/references.
                for attr in tag.attributes() {
                    let attr = attr.map_err(|_| malformed())?;
                    validate_attribute(&attr.value)?;
                }
                if suppressed.is_none() {
                    if name.eq_ignore_ascii_case(b"script")
                        || name.eq_ignore_ascii_case(b"style")
                        || name.eq_ignore_ascii_case(b"template")
                        || name.eq_ignore_ascii_case(b"textarea")
                    {
                        if !empty {
                            suppressed = Some(stack.len() + 1);
                        }
                    } else if name == b"cas-as" || name == b"token" {
                        return Err(unsupported_cas());
                    } else if let Some(index) = FIELDS.iter().position(|field| *field == name) {
                        if fields[index].is_some() || !tag.attributes_raw().is_empty() {
                            return Err(malformed());
                        }
                        // Reserve once: growing a secret String could leave an unwiped old allocation.
                        fields[index] = Some(Zeroizing::new(String::with_capacity(input.len())));
                        if !empty {
                            active = Some(index);
                        }
                    }
                }
                if !empty && !html_void(name) {
                    stack.push((raw, name_len));
                }
            }
            Event::End(tag) => {
                let (raw, len) = stack.pop().ok_or_else(malformed)?;
                if &raw[..len] != tag.name().as_ref() {
                    return Err(malformed());
                }
                active = None;
                if suppressed == Some(stack.len() + 1) {
                    suppressed = None;
                }
            }
            Event::Text(text) => {
                if let Some(index) = active {
                    let value = std::str::from_utf8(text.as_ref()).map_err(|_| malformed())?;
                    fields[index]
                        .as_mut()
                        .ok_or_else(malformed)?
                        .push_str(value);
                }
            }
            Event::CData(text) => {
                if let Some(index) = active {
                    fields[index]
                        .as_mut()
                        .ok_or_else(malformed)?
                        .push_str(std::str::from_utf8(text.as_ref()).map_err(|_| malformed())?);
                }
            }
            Event::GeneralRef(reference) => {
                let ch = match reference.resolve_char_ref().map_err(|_| malformed())? {
                    Some(ch) if xml_char(ch) => ch,
                    Some(_) => return Err(malformed()),
                    None => match reference.as_ref() {
                        b"amp" => '&',
                        b"lt" => '<',
                        b"gt" => '>',
                        b"apos" => '\'',
                        b"quot" => '"',
                        _ => return Err(malformed()),
                    },
                };
                if let Some(index) = active {
                    fields[index].as_mut().ok_or_else(malformed)?.push(ch);
                }
            }
            Event::Comment(comment) => {
                if active.is_some() {
                    return Err(malformed());
                }
                if suppressed.is_none() {
                    let text = std::str::from_utf8(comment.as_ref()).map_err(|_| malformed())?;
                    if text.contains('<') {
                        parse_fragment(text, fields, events, outer_depth + stack.len() + 1)?;
                    }
                }
            }
            Event::DocType(_) | Event::Decl(_) | Event::PI(_) => return Err(malformed()),
            Event::Eof => {
                if !stack.is_empty() {
                    return Err(malformed());
                }
                return Ok(());
            }
        }
    }
}

fn validate_attribute(value: &[u8]) -> Result<()> {
    let mut rest = std::str::from_utf8(value).map_err(|_| malformed())?;
    if rest.contains('<') {
        return Err(malformed());
    }
    while let Some(start) = rest.find('&') {
        rest = &rest[start + 1..];
        let end = rest.find(';').ok_or_else(malformed)?;
        let reference = quick_xml::events::BytesRef::new(&rest[..end]);
        match reference.resolve_char_ref().map_err(|_| malformed())? {
            Some(ch) if xml_char(ch) => {}
            None if matches!(&rest[..end], "amp" | "lt" | "gt" | "apos" | "quot") => {}
            _ => return Err(malformed()),
        }
        rest = &rest[end + 1..];
    }
    Ok(())
}
