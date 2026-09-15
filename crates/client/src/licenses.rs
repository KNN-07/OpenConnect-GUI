use ocvpn_model::{Error, ErrorCode, LicenseText, Result};
use std::{fs, io::Read, path::Path};
fn failed() -> Error {
    Error::new(
        ErrorCode::EngineUnavailable,
        "The protected license inventory is unavailable; repair the native package",
    )
}
fn collect(
    root: &Path,
    directory: &Path,
    depth: usize,
    remaining: &mut usize,
    output: &mut Vec<LicenseText>,
) -> Result<()> {
    if depth > 8 {
        return Err(failed());
    }
    for entry in fs::read_dir(directory).map_err(|_| failed())? {
        let entry = entry.map_err(|_| failed())?;
        let kind = entry.file_type().map_err(|_| failed())?;
        let path = entry.path();
        if kind.is_symlink() {
            return Err(failed());
        }
        if kind.is_dir() {
            collect(root, &path, depth + 1, remaining, output)?;
        } else if kind.is_file() {
            if output.len() >= 2048 {
                return Err(failed());
            }
            ocvpn_engine::validate_installed_file(&path)?;
            let file = fs::File::open(&path).map_err(|_| failed())?;
            let size = usize::try_from(file.metadata().map_err(|_| failed())?.len())
                .map_err(|_| failed())?;
            if size > 2 * 1024 * 1024 || size > *remaining {
                return Err(failed());
            }
            let mut text = String::new();
            file.take((size + 1) as u64)
                .read_to_string(&mut text)
                .map_err(|_| failed())?;
            if text.len() != size {
                return Err(failed());
            }
            *remaining -= size;
            output.push(LicenseText {
                name: path
                    .strip_prefix(root)
                    .map_err(|_| failed())?
                    .to_string_lossy()
                    .replace('\\', "/"),
                text,
            });
        } else {
            return Err(failed());
        }
    }
    Ok(())
}
pub async fn licenses() -> Result<Vec<LicenseText>> {
    tokio::task::spawn_blocking(|| {
        let root = ocvpn_engine::installed_native_directory()?.join("share/licenses");
        let mut output = Vec::new();
        collect(&root, &root, 0, &mut (32 * 1024 * 1024), &mut output)?;
        output.sort_by(|a, b| a.name.cmp(&b.name));
        if output.is_empty() {
            return Err(failed());
        }
        Ok(output)
    })
    .await
    .map_err(|_| failed())?
}
