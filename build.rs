use std::env;

fn main() {
    // Allow embedding a default auth key at compile time
    if let Ok(key) = env::var("HECATE_DEFAULT_AUTH_KEY") {
        println!("cargo:rustc-env=HECATE_EMBEDDED_AUTH_KEY={key}");
    }

    // Allow embedding a server address at compile time
    if let Ok(server) = env::var("HECATE_DEFAULT_SERVER") {
        println!("cargo:rustc-env=HECATE_EMBEDDED_SERVER={server}");
    }
}
