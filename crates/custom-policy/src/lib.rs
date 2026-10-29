#![no_std]
//! Bespoke compiled policy using the same custody and owner-operation mixins as the fixed engines.
use allowit_policy_wallet::{Error, LocalPolicyHost, Policy, context};
use allowit_wallet_protocol::{EngineRequest, EngineState, Grant, Spent};
use soroban_sdk::{BytesN, Env, Symbol, Vec};
#[rustfmt::skip]
#[allow(unused_braces,dead_code)]
mod generated_policy;
pub struct Custom;
impl Policy for Custom {
    const KIND: &'static str = "custom_policy";
    fn source_digest(env: &Env) -> Option<BytesN<32>> {
        Some(BytesN::from_array(env, &generated_policy::SOURCE_HASH))
    }
    fn validate(_env: &Env, rules: &Vec<Symbol>, _grant: &Grant) -> Result<(), Error> {
        if rules.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidGrant)
        }
    }
    fn check(
        _env: &Env,
        request: EngineRequest,
        state: EngineState,
        _rules: &Vec<Symbol>,
    ) -> Result<Spent, Error> {
        generated_policy::execute(
            &context(&request),
            &state.grant,
            &state,
            &LocalPolicyHost(request),
        )
        .map_err(|_| Error::PolicyDenied)
    }
}
allowit_policy_wallet::policy_wallet!(CustomPolicy, Custom);
