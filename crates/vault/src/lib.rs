#![no_std]
use soroban_sdk::{
    Address, BytesN, Env, Executable, Symbol, TryFromVal, Vec,
    address_payload::AddressPayload,
    auth::{Context, CustomAccountInterface},
    contract, contractclient, contracterror, contractimpl, contracttype,
    crypto::Hash,
    token,
    xdr::ToXdr,
};
#[path = "../../../policy/policy.rs"]
mod policy;
#[path = "../../../policy/policy_api.rs"]
pub mod policy_api;

#[contractclient(name = "PolicyClient")]
pub trait PolicyInterface {
    fn evaluate(env: Env, context: policy_api::Context) -> u64;
    fn validate_daily_limit(env: Env, value: u64);
    fn source_hash(env: Env) -> BytesN<32>;
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub owner: Address,
    pub executor: Address,
    pub authority: Address,
    pub asset: Address,
    pub policy: Address,
    pub policy_source: BytesN<32>,
    pub policy_wasm: BytesN<32>,
    pub daily_limit: u64,
    pub spent: u64,
    pub spent_day: u64,
    pub nonce: u64,
    pub revision: u64,
    pub approved: bool,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    UnsupportedMethod = 100,
    StaleRequest = 101,
    Overflow = 102,
    UnsupportedAsset = 103,
    NotApproved = 104,
    SourceChanged = 105,
    InsufficientFunds = 106,
    ZeroAmount = 107,
    BadRecipient = 108,
    InvalidDecision = 109,
    InvalidAuthorization = 110,
    Expired = 111,
    UnsupportedContext = 112,
}

/// Per-payment approval carried by a standard Soroban contract-account auth entry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentAuthorization {
    pub nonce: u64,
    pub revision: u64,
    pub expires_at: u64,
    pub request_hash: BytesN<32>,
    pub executor_signature: BytesN<64>,
    pub authority_signature: BytesN<64>,
}

#[contract]
pub struct Vault;

fn state(env: &Env) -> State {
    env.storage().instance().extend_ttl(100_000, 200_000);
    env.storage().instance().get(&0u32).unwrap()
}
fn store(env: &Env, value: &State) {
    env.storage().instance().set(&0u32, value);
    env.storage().instance().extend_ttl(100_000, 200_000);
}
fn validate(
    env: &Env,
    policy: &Address,
    wasm: &BytesN<32>,
    source: &BytesN<32>,
    value: u64,
) -> Result<(), Error> {
    policy_api::validate_daily_limit(value).map_err(|_| Error::InvalidDecision)?;
    if policy.executable() != Some(Executable::Wasm(wasm.clone())) {
        return Err(Error::SourceChanged);
    }
    if PolicyClient::new(env, policy).source_hash() != *source {
        return Err(Error::SourceChanged);
    }
    Ok(())
}
fn native_amount(value: u64) -> i128 {
    i128::from(value) * 10
}
fn changed(s: &mut State) -> Result<(), Error> {
    s.revision = s.revision.checked_add(1).ok_or(Error::Overflow)?;
    Ok(())
}
fn signer_key(address: &Address) -> Result<BytesN<32>, Error> {
    match address.to_payload() {
        Some(AddressPayload::AccountIdPublicKeyEd25519(key)) => Ok(key),
        _ => Err(Error::InvalidAuthorization),
    }
}
fn payment_digest(
    env: &Env,
    vault: &Address,
    payload: &BytesN<32>,
    auth: &PaymentAuthorization,
) -> BytesN<32> {
    env.crypto()
        .sha256(
            &(
                Symbol::new(env, "allowit_x402_v1"),
                vault.clone(),
                payload.clone(),
                auth.nonce,
                auth.revision,
                auth.expires_at,
                auth.request_hash.clone(),
            )
                .to_xdr(env),
        )
        .to_bytes()
}
/// Shared numeric enforcement for both exact dual-signer transfers and x402 auth.
fn charge(
    env: &Env,
    s: &mut State,
    recipient: &Address,
    amount: u64,
    nonce: u64,
    revision: u64,
) -> Result<(), Error> {
    if !s.approved {
        return Err(Error::NotApproved);
    }
    if s.nonce != nonce || s.revision != revision {
        return Err(Error::StaleRequest);
    }
    if amount == 0 {
        return Err(Error::ZeroAmount);
    }
    if *recipient == env.current_contract_address() {
        return Err(Error::BadRecipient);
    }
    let now = env.ledger().timestamp();
    let day = now / 86_400;
    if day < s.spent_day {
        return Err(Error::InvalidDecision);
    }
    let expected = (if day == s.spent_day { s.spent } else { 0 })
        .checked_add(amount)
        .ok_or(Error::Overflow)?;
    validate(
        env,
        &s.policy,
        &s.policy_wasm,
        &s.policy_source,
        s.daily_limit,
    )?;
    let next = PolicyClient::new(env, &s.policy).evaluate(&policy_api::Context {
        approved: s.approved,
        amount,
        daily_limit: s.daily_limit,
        spent: s.spent,
        spent_day: s.spent_day,
        now,
    });
    if next != expected || next > s.daily_limit {
        return Err(Error::InvalidDecision);
    }
    s.nonce = s.nonce.checked_add(1).ok_or(Error::Overflow)?;
    s.spent = next;
    s.spent_day = day;
    store(env, s);
    Ok(())
}
#[contractimpl]
impl Vault {
    pub fn __constructor(
        env: Env,
        owner: Address,
        executor: Address,
        authority: Address,
        asset: Address,
        policy: Address,
        policy_source: BytesN<32>,
        policy_wasm: BytesN<32>,
        daily_limit: u64,
    ) {
        owner.require_auth();
        if owner == executor
            || owner == authority
            || executor == authority
            || signer_key(&executor).is_err()
            || signer_key(&authority).is_err()
        {
            soroban_sdk::panic_with_error!(&env, Error::InvalidAuthorization);
        }
        if asset.executable() != Some(Executable::StellarAsset)
            || token::Client::new(&env, &asset).decimals() != 7
        {
            soroban_sdk::panic_with_error!(&env, Error::UnsupportedAsset);
        }
        let client = PolicyClient::new(&env, &policy);
        if let Err(error) = validate(&env, &policy, &policy_wasm, &policy_source, daily_limit) {
            soroban_sdk::panic_with_error!(&env, error);
        }
        client.validate_daily_limit(&daily_limit);
        store(
            &env,
            &State {
                owner,
                executor,
                authority,
                asset,
                policy,
                policy_source,
                policy_wasm,
                daily_limit,
                spent: 0,
                spent_day: env.ledger().timestamp() / 86_400,
                nonce: 0,
                revision: 0,
                approved: false,
            },
        );
    }
    pub fn state(env: Env) -> State {
        state(&env)
    }
    pub fn balance(env: Env) -> i128 {
        let s = state(&env);
        token::Client::new(&env, &s.asset).balance(&env.current_contract_address()) / 10
    }
    pub fn deposit(env: Env, from: Address, amount: u64) -> Result<(), Error> {
        from.require_auth();
        if amount == 0 {
            return Err(Error::ZeroAmount);
        }
        if from == env.current_contract_address() {
            return Err(Error::BadRecipient);
        }
        let s = state(&env);
        token::Client::new(&env, &s.asset).transfer(
            &from,
            &env.current_contract_address(),
            &native_amount(amount),
        );
        Ok(())
    }
    pub fn approve(env: Env, approved: bool, expected_revision: u64) -> Result<(), Error> {
        let mut s = state(&env);
        s.owner.require_auth();
        if s.revision != expected_revision {
            return Err(Error::StaleRequest);
        }
        if approved {
            let client = PolicyClient::new(&env, &s.policy);
            validate(
                &env,
                &s.policy,
                &s.policy_wasm,
                &s.policy_source,
                s.daily_limit,
            )?;
            client.validate_daily_limit(&s.daily_limit);
        }
        s.approved = approved;
        changed(&mut s)?;
        store(&env, &s);
        Ok(())
    }
    pub fn set_daily_limit(env: Env, value: u64, expected_revision: u64) -> Result<(), Error> {
        let mut s = state(&env);
        s.owner.require_auth();
        if s.revision != expected_revision {
            return Err(Error::StaleRequest);
        }
        let client = PolicyClient::new(&env, &s.policy);
        validate(
            &env,
            &s.policy,
            &s.policy_wasm,
            &s.policy_source,
            s.daily_limit,
        )?;
        policy_api::validate_daily_limit(value).map_err(|_| Error::InvalidDecision)?;
        client.validate_daily_limit(&value);
        s.daily_limit = value;
        changed(&mut s)?;
        store(&env, &s);
        Ok(())
    }
    pub fn set_policy(
        env: Env,
        policy: Address,
        policy_source: BytesN<32>,
        policy_wasm: BytesN<32>,
        expected_revision: u64,
    ) -> Result<(), Error> {
        let mut s = state(&env);
        s.owner.require_auth();
        if s.revision != expected_revision {
            return Err(Error::StaleRequest);
        }
        let client = PolicyClient::new(&env, &policy);
        validate(&env, &policy, &policy_wasm, &policy_source, s.daily_limit)?;
        client.validate_daily_limit(&s.daily_limit);
        s.policy = policy;
        s.policy_source = policy_source;
        s.policy_wasm = policy_wasm;
        s.approved = false;
        changed(&mut s)?;
        store(&env, &s);
        Ok(())
    }
    pub fn transfer(
        env: Env,
        recipient: Address,
        amount: u64,
        nonce: u64,
        expected_revision: u64,
    ) -> Result<(), Error> {
        let mut s = state(&env);
        s.executor.require_auth();
        s.authority.require_auth();
        if token::Client::new(&env, &s.asset).balance(&env.current_contract_address())
            < native_amount(amount)
        {
            return Err(Error::InsufficientFunds);
        }
        charge(&env, &mut s, &recipient, amount, nonce, expected_revision)?;
        token::Client::new(&env, &s.asset).transfer(
            &env.current_contract_address(),
            &recipient,
            &native_amount(amount),
        );
        env.events().publish(
            (soroban_sdk::symbol_short!("transfer"), nonce),
            (recipient, amount, s.revision, s.policy_source),
        );
        Ok(())
    }
    pub fn withdraw(env: Env, amount: u64) -> Result<(), Error> {
        let s = state(&env);
        s.owner.require_auth();
        if amount == 0 {
            return Err(Error::ZeroAmount);
        }
        token::Client::new(&env, &s.asset).transfer(
            &env.current_contract_address(),
            &s.owner,
            &native_amount(amount),
        );
        Ok(())
    }
    pub fn unsupported(_env: Env, _method: u32) -> Result<(), Error> {
        Err(Error::UnsupportedMethod)
    }
}

#[contractimpl]
impl CustomAccountInterface for Vault {
    type Signature = PaymentAuthorization;
    type Error = Error;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: PaymentAuthorization,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        if auth_contexts.len() != 1 {
            return Err(Error::UnsupportedContext);
        }
        let Context::Contract(context) = auth_contexts.get(0).ok_or(Error::UnsupportedContext)?
        else {
            return Err(Error::UnsupportedContext);
        };
        let mut s = state(&env);
        if context.contract != s.asset
            || context.fn_name != Symbol::new(&env, "transfer")
            || context.args.len() != 3
        {
            return Err(Error::UnsupportedContext);
        }
        let from = Address::try_from_val(&env, &context.args.get(0).unwrap())
            .map_err(|_| Error::UnsupportedContext)?;
        let recipient = Address::try_from_val(&env, &context.args.get(1).unwrap())
            .map_err(|_| Error::UnsupportedContext)?;
        let amount = i128::try_from_val(&env, &context.args.get(2).unwrap())
            .map_err(|_| Error::UnsupportedContext)?;
        if from != env.current_contract_address() {
            return Err(Error::UnsupportedContext);
        }
        if amount <= 0 || amount % 10 != 0 {
            return Err(Error::UnsupportedAsset);
        }
        let units = u64::try_from(amount / 10).map_err(|_| Error::Overflow)?;
        let now = env.ledger().timestamp();
        if signature.expires_at <= now
            || signature.expires_at > now.checked_add(300).ok_or(Error::Overflow)?
        {
            return Err(Error::Expired);
        }
        if signature.request_hash == BytesN::from_array(&env, &[0; 32]) {
            return Err(Error::InvalidAuthorization);
        }
        let digest = payment_digest(
            &env,
            &env.current_contract_address(),
            &signature_payload.to_bytes(),
            &signature,
        );
        env.crypto().ed25519_verify(
            &signer_key(&s.executor)?,
            &digest.clone().into(),
            &signature.executor_signature,
        );
        env.crypto().ed25519_verify(
            &signer_key(&s.authority)?,
            &digest.into(),
            &signature.authority_signature,
        );
        charge(
            &env,
            &mut s,
            &recipient,
            units,
            signature.nonce,
            signature.revision,
        )
    }
}

#[cfg(test)]
mod tests;
