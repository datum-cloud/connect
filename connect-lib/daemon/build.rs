use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=DATUM_CONNECT_RELEASE_VERSION");
    let version = env::var("DATUM_CONNECT_RELEASE_VERSION")
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_owned());
    println!("cargo:rustc-env=DATUM_CONNECT_RELEASE_VERSION={version}");
}
