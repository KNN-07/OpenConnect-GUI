use ocvpn_model::*;
use ts_rs::TS;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bindings");
    ProfileExport::export_all_to(&directory)?;
    ProfileDocument::export_all_to(&directory)?;
    SettingsDocument::export_all_to(&directory)?;
    PinsDocument::export_all_to(&directory)?;
    SettingsRead::export_all_to(&directory)?;
    Settings::export_all_to(&directory)?;
    CertificatePin::export_all_to(&directory)?;
    AuthPrompt::export_all_to(&directory)?;
    CertificatePrompt::export_all_to(&directory)?;
    CertificateDecision::export_all_to(&directory)?;
    BrowserPrompt::export_all_to(&directory)?;
    Snapshot::export_all_to(&directory)?;
    Capabilities::export_all_to(&directory)?;
    LogRecord::export_all_to(&directory)?;
    DoctorReport::export_all_to(&directory)?;
    ServiceStatus::export_all_to(&directory)?;
    ServiceAction::export_all_to(&directory)?;
    LicenseText::export_all_to(&directory)?;
    Ok(())
}
