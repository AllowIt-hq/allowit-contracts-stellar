use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};
fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let root = Path::new(&manifest).parent().unwrap().parent().unwrap();
    let mut h = Sha256::new();
    h.update(b"allowit-policy-source-v1\0");
    for name in ["policy.rs", "policy_api.rs"] {
        let path = root.join("policy").join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = fs::read(path).unwrap();
        h.update(name.as_bytes());
        h.update([0]);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
    let path = root.join("policy/source_hash.rs");
    println!("cargo:rerun-if-changed={}", path.display());
    let source = fs::read_to_string(path).unwrap();
    let array = source
        .split('=')
        .nth(1)
        .unwrap()
        .split('[')
        .nth(1)
        .unwrap()
        .split(']')
        .next()
        .unwrap();
    let actual: Vec<u8> = array
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().parse().unwrap())
        .collect();
    assert_eq!(
        actual.as_slice(),
        h.finalize().as_slice(),
        "Stale portable policy bundle hash; run scripts/check-policy.py --write"
    );
}
