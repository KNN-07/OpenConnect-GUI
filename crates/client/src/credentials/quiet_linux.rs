//! Same Secret Service attributes as keyring 3.6.3, with no Unlock/Prompt calls.
use super::{SERVICE, unavailable};
use dbus_secret_service::{EncryptionType, SecretService};
use ocvpn_model::Result;
use std::collections::HashMap;
use zeroize::Zeroizing;

fn service() -> Result<SecretService> {
    SecretService::connect_with_max_prompt_timeout(EncryptionType::Dh, 0).map_err(|_| unavailable())
}
fn attributes(account: &str) -> HashMap<&str, &str> {
    HashMap::from([
        ("service", SERVICE),
        ("username", account),
        ("target", "default"),
    ])
}
pub(super) fn read(account: &str) -> Result<Option<Zeroizing<String>>> {
    let service = service()?;
    let found = service
        .search_items(attributes(account))
        .map_err(|_| unavailable())?;
    if !found.locked.is_empty() || found.unlocked.len() > 1 {
        return Err(unavailable());
    }
    let Some(item) = found.unlocked.first() else {
        return Ok(None);
    };
    // GetSecret itself never unlocks; a concurrent lock fails without prompting.
    let bytes = Zeroizing::new(item.get_secret().map_err(|_| unavailable())?);
    let text = std::str::from_utf8(&bytes).map_err(|_| unavailable())?;
    Ok(Some(Zeroizing::new(text.to_owned())))
}
pub(super) fn write(account: &str, value: &str) -> Result<()> {
    let service = service()?;
    let found = service
        .search_items(attributes(account))
        .map_err(|_| unavailable())?;
    if !found.locked.is_empty() || found.unlocked.len() > 1 {
        return Err(unavailable());
    }
    if let Some(item) = found.unlocked.first() {
        return item
            .set_secret(value.as_bytes(), "text/plain")
            .map_err(|_| unavailable());
    }
    let collection = service
        .get_default_collection()
        .map_err(|_| unavailable())?;
    if collection.is_locked().map_err(|_| unavailable())? {
        return Err(unavailable());
    }
    // dbus-secret-service's pinned zero-timeout contract rejects a required
    // prompt before calling Prompt.Prompt. An unlocked collection can therefore
    // create an encrypted item without imposing interactive first provisioning.
    collection
        .create_item(
            SERVICE,
            attributes(account),
            value.as_bytes(),
            true,
            "text/plain",
        )
        .map(|_| ())
        .map_err(|_| unavailable())
}
