use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or("usage: discover ABSOLUTE_TRUSTED_NATIVE_BUILD_ROOT")?,
    );
    if args.next().is_some() {
        return Err("expected exactly one native build root".into());
    }
    // This development-only executable explicitly accepts native code chosen by
    // its operator. No installed application calls this unsafe entrypoint.
    let engine = unsafe { ocvpn_engine::Engine::load_for_development(&root)? };
    println!("{}", serde_json::to_string_pretty(&engine.capabilities()?)?);
    Ok(())
}
