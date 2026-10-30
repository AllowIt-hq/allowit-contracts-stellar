#![no_std]
//! Bespoke policy compiled verbatim from `policy/policy.rs` into the shared custody mixins.
use allowit::{AllowitEnv, Rule};
use allowit_policy_wallet::{Error, Policy};
use soroban_sdk::{BytesN, Env, Vec};

/// Authored policy source, compiled unchanged as a module. The offchain server compiles the same file.
#[path = "../policy/policy.rs"]
mod policy;

/// SHA-256 of the exact `policy/policy.rs` bytes, computed by `build.rs`.
pub const SOURCE_HASH: [u8; 32] = include!(concat!(env!("OUT_DIR"), "/source_hash.rs"));
/// The only native operation this policy admits, enforced through `ARGUMENT_SCHEMA_HASH`.
pub const ADMITTED_OPERATION: &str = "stellar::sep41_transfer";
/// SHA-256 of the admitted SEP-41 transfer argument schema descriptor.
pub const ARGUMENT_SCHEMA_HASH: [u8; 32] = [
    216, 0, 105, 227, 91, 242, 126, 112, 2, 254, 161, 21, 191, 170, 167, 44, 147, 71, 240, 150,
    126, 226, 36, 246, 86, 136, 223, 200, 250, 20, 126, 139,
];

pub struct Custom;
impl Policy for Custom {
    const KIND: &'static str = "custom_policy";
    fn source_digest(env: &Env) -> Option<BytesN<32>> {
        Some(BytesN::from_array(env, &SOURCE_HASH))
    }
    fn argument_schema_digest(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &ARGUMENT_SCHEMA_HASH)
    }
    /// Run the complete authored policy. An unset Grant field denies.
    fn check(_env: &Env, ctx: &AllowitEnv, _rules: &Vec<Rule>) -> Result<(), Error> {
        Ok(policy::execute(ctx)?)
    }
}
allowit_policy_wallet::policy_wallet!(CustomPolicy, Custom);

#[cfg(test)]
mod tests;
