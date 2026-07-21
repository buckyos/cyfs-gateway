const WINDOWS_MAIN_STACK_SIZE: usize = 4 * 1024 * 1024;

pub fn configure_windows_main_stack() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        return;
    }

    let binary_name = std::env::var("CARGO_PKG_NAME").expect("CARGO_PKG_NAME is set by Cargo");
    match std::env::var("CARGO_CFG_TARGET_ENV")
        .unwrap_or_default()
        .as_str()
    {
        "msvc" => {
            println!("cargo:rustc-link-arg-bin={binary_name}=/STACK:{WINDOWS_MAIN_STACK_SIZE}")
        }
        "gnu" => {
            println!("cargo:rustc-link-arg-bin={binary_name}=-Wl,--stack,{WINDOWS_MAIN_STACK_SIZE}")
        }
        _ => {}
    }
}
