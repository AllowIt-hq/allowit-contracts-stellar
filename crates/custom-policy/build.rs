//! Bind the contract to the exact bytes of its authored policy source.
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};
fn main() {
    let source = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("policy/policy.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    let digest = Sha256::digest(fs::read(&source).unwrap());
    let bytes: Vec<String> = digest.iter().map(u8::to_string).collect();
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("source_hash.rs"),
        format!("[{}]", bytes.join(", ")),
    )
    .unwrap();
}
