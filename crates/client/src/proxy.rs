use ocvpn_model::{Error, Result, validate_proxy};
use url::Url;
use zeroize::Zeroizing;

/// Userinfo is private input, never part of a persisted Profile or public DTO.
pub struct ProxyInput {
    pub endpoint: Url,
    pub credentials: Option<Zeroizing<String>>,
}

/// Accept only the same endpoint schemes that Profile::validate accepts.
/// The caller must retain credentials for this session or explicitly opt into keyring storage.
pub fn parse_proxy(input: &str) -> Result<ProxyInput> {
    if input.len() > 65536 || input.chars().any(char::is_control) {
        return Err(Error::invalid(
            "Proxy URL exceeds its limit or contains control characters",
        ));
    }
    let (scheme, remainder) = input
        .split_once("://")
        .ok_or_else(|| Error::invalid("Proxy requires an explicit URL scheme"))?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let (endpoint, credentials) = if let Some((userinfo, host)) = authority.rsplit_once('@') {
        // Strip userinfo before Url allocates its backing string. Only the
        // zeroizing keyring/session payload owns a copy of those secret bytes.
        let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        let credentials = Zeroizing::new(
            serde_json::to_string(&[username, password])
                .map_err(|_| Error::invalid("Cannot encode proxy credentials"))?,
        );
        let sanitized = format!("{scheme}://{host}{}", &remainder[authority_end..]);
        let endpoint = Url::parse(&sanitized).map_err(|_| Error::invalid("Invalid proxy URL"))?;
        (endpoint, Some(credentials))
    } else {
        (
            Url::parse(input).map_err(|_| Error::invalid("Invalid proxy URL"))?,
            None,
        )
    };
    validate_proxy(&endpoint)?;
    Ok(ProxyInput {
        endpoint,
        credentials,
    })
}
