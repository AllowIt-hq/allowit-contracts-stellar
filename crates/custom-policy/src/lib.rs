#![no_std]
//! Bespoke compiled policy using the same custody and owner-operation mixins as the fixed engines.
use allowit_policy_wallet::{Error, LocalPolicyHost, Policy, context_for_operation};
use allowit_wallet_protocol::{EngineRequest, EngineState, Grant, Spent};
use soroban_sdk::{BytesN, Env, String, Symbol, Vec};
#[rustfmt::skip]
#[allow(unused_braces,dead_code)]
mod generated_policy;
pub struct Custom;
impl Policy for Custom {
    const KIND: &'static str = "custom_policy";
    fn source_digest(env: &Env) -> Option<BytesN<32>> {
        Some(BytesN::from_array(env, &generated_policy::SOURCE_HASH))
    }
    fn argument_schema_digest(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &generated_policy::ARGUMENT_SCHEMA_HASH)
    }
    fn admits_schema(env: &Env, digest: &BytesN<32>) -> bool {
        *digest == Self::argument_schema_digest(env)
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
        Self::check_operation(
            _env,
            request,
            state,
            _rules,
            &String::from_str(_env, "stellar::sep41_transfer"),
        )
    }
    fn check_operation(
        _env: &Env,
        request: EngineRequest,
        state: EngineState,
        _rules: &Vec<Symbol>,
        operation: &String,
    ) -> Result<Spent, Error> {
        generated_policy::execute(
            &context_for_operation(&request, operation),
            &state.grant,
            &state,
            &LocalPolicyHost(request),
        )
        .map_err(|_| Error::PolicyDenied)
    }
}
allowit_policy_wallet::policy_wallet!(CustomPolicy, Custom);
