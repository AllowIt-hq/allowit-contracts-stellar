#![no_std]

use allowit_wallet_protocol::{
    ARGUMENT_SCHEMA_DESCRIPTOR, EngineClient, EngineContext, ExecutionRequest, Grant,
    MAX_ARGUMENT_BYTES, MAX_RECIPIENTS, PolicyBinding, PolicyContext, Sep41TransferArgs,
    TransferReceipt, TransferRequest,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Executable, String, Symbol, TryFromVal, Vec,
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    token,
    xdr::{FromXdr, ToXdr},
};

#[cfg(not(any(feature = "test-recipient-policy", feature = "test-xlm-policy")))]
#[rustfmt::skip]
#[allow(unused_braces)]
mod generated_policy;
#[cfg(feature = "test-recipient-policy")]
#[path = "generated_recipient_policy.rs"]
#[rustfmt::skip]
#[allow(unused_braces)]
mod generated_policy;
#[cfg(feature = "test-xlm-policy")]
#[path = "generated_xlm_policy.rs"]
#[rustfmt::skip]
#[allow(unused_braces)]
mod generated_policy;
#[cfg(all(feature = "test-recipient-policy", feature = "test-xlm-policy"))]
compile_error!("Select only one test policy fixture");

const DAY: u64 = 86_400;
const VERSION: u32 = 2;
const TTL_THRESHOLD: u32 = 100_000;
const TTL_EXTEND: u32 = 200_000;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub version: u32,
    pub owner: Address,
    pub agent: Address,
    pub engine: Address,
    pub grant: Grant,
    pub spent_daily: i128,
    pub spent_day: u64,
    pub spent_total: i128,
    pub calls: u64,
    pub nonce: u64,
    pub policy_version: u64,
    pub paused: bool,
}

#[contracttype]
#[derive(Clone)]
struct LegacyState {
    pub version: u32,
    pub owner: Address,
    pub agent: Address,
    pub engine: Address,
    pub grant: Grant,
    pub spent_daily: i128,
    pub spent_day: u64,
    pub spent_total: i128,
    pub calls: u64,
    pub nonce: u64,
    pub revision: u64,
    pub paused: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDeployment {
    pub policy_version: u64,
    pub owner: Address,
    pub agent: Address,
    pub engine: Address,
    pub grant: Grant,
    pub paused: bool,
    pub x402_signer: Option<BytesN<32>>,
    pub wasm_hash: Option<BytesN<32>>,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    InvalidState = 1,
    InvalidGrant = 2,
    UnsupportedAsset = 3,
    InvalidActor = 4,
    StaleRequest = 5,
    Paused = 6,
    Expired = 7,
    InvalidAmount = 8,
    InvalidRecipient = 9,
    BudgetExceeded = 10,
    Overflow = 11,
    ClockRegression = 12,
    EngineDenied = 13,
    InsufficientFunds = 14,
    InvalidEffects = 15,
    UnsupportedOperation = 16,
    InvalidInvocation = 17,
    PolicyDenied = 18,
    Replay = 19,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    PolicyInstance,
    Operation(BytesN<32>),
    X402Config,
}

/// An owner-delegated raw Ed25519 key. Native account thresholds do not revoke it.
#[contracttype]
#[derive(Clone)]
pub struct X402Config {
    pub agent: Address,
    pub public_key: BytesN<32>,
    pub token: String,
}

#[contracttype]
#[derive(Clone)]
pub struct X402Authorization {
    pub execution: ExecutionRequest,
    pub signature: BytesN<64>,
}

#[contract]
pub struct Odc;

fn binding(env: &Env) -> Result<PolicyBinding, Error> {
    if generated_policy::SOURCE_PROFILE != "allowit-stellar-transfer-v1"
        || generated_policy::SOURCE_PROFILE_VERSION != 1
        || generated_policy::ADMITTED_OPERATION != "stellar::sep41_transfer"
        || BytesN::from_array(env, &generated_policy::ARGUMENT_SCHEMA_HASH)
            != env
                .crypto()
                .sha256(&Bytes::from_slice(env, ARGUMENT_SCHEMA_DESCRIPTOR))
                .to_bytes()
    {
        return Err(Error::InvalidState);
    }
    let policy_instance = env
        .storage()
        .instance()
        .get(&Key::PolicyInstance)
        .ok_or(Error::InvalidState)?;
    let Some(Executable::Wasm(module_digest)) = env.current_contract_address().executable() else {
        return Err(Error::InvalidState);
    };
    Ok(PolicyBinding {
        interface_version: VERSION,
        policy_instance,
        module_digest,
        source_digest: BytesN::from_array(env, &generated_policy::SOURCE_HASH),
        argument_schema_digest: BytesN::from_array(env, &generated_policy::ARGUMENT_SCHEMA_HASH),
        entrypoint: Symbol::new(env, "_execute"),
    })
}

fn load(env: &Env) -> Result<State, Error> {
    let raw: soroban_sdk::Val = env
        .storage()
        .instance()
        .get(&0u32)
        .ok_or(Error::InvalidState)?;
    let s = if let Ok(state) = State::try_from_val(env, &raw) {
        if state.version != VERSION {
            return Err(Error::InvalidState);
        }
        state
    } else {
        let old = LegacyState::try_from_val(env, &raw).map_err(|_| Error::InvalidState)?;
        if old.version != 1 {
            return Err(Error::InvalidState);
        }
        State {
            version: VERSION,
            owner: old.owner,
            agent: old.agent,
            engine: old.engine,
            grant: old.grant,
            spent_daily: old.spent_daily,
            spent_day: old.spent_day,
            spent_total: old.spent_total,
            calls: old.calls,
            nonce: old.nonce,
            policy_version: old.revision,
            paused: old.paused,
        }
    };
    if s.version != VERSION {
        return Err(Error::InvalidState);
    }
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
    Ok(s)
}

fn store(env: &Env, state: &State) {
    env.storage().instance().set(&0u32, state);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
}

fn commit_deployment(env: &Env, s: &mut State, policy_version: u64) -> Result<(), Error> {
    if s.policy_version.checked_add(1).ok_or(Error::Overflow)? != policy_version {
        return Err(Error::StaleRequest);
    }
    s.policy_version = policy_version;
    store(env, s);
    Ok(())
}

fn owner_state(env: &Env) -> Result<State, Error> {
    let s = load(env)?;
    s.owner.require_auth();
    Ok(s)
}

fn validate_roles(
    env: &Env,
    owner: &Address,
    agent: &Address,
    engine: &Address,
) -> Result<(), Error> {
    let wallet = env.current_contract_address();
    if owner == agent
        || owner == engine
        || agent == engine
        || owner == &wallet
        || agent == &wallet
        || engine == &wallet
    {
        return Err(Error::InvalidActor);
    }
    Ok(())
}

fn validate_grant(env: &Env, grant: &Grant) -> Result<(), Error> {
    if grant.recipients.is_empty()
        || grant.recipients.len() > MAX_RECIPIENTS
        || grant.per_transfer <= 0
        || grant.daily_limit <= 0
        || grant.total_limit <= 0
        || grant.max_calls == 0
        || grant.expires_at <= env.ledger().timestamp()
    {
        return Err(Error::InvalidGrant);
    }
    for (i, recipient) in grant.recipients.iter().enumerate() {
        if recipient == env.current_contract_address() {
            return Err(Error::InvalidRecipient);
        }
        for prior in grant.recipients.iter().take(i) {
            if prior == recipient {
                return Err(Error::InvalidGrant);
            }
        }
    }
    Ok(())
}

fn policy_token(env: &Env, asset: &Address) -> String {
    // Asset::Native has the exact four-byte XDR discriminant zero. Its SAC
    // address is network-derived; an issued asset merely named "native" differs.
    let native = env
        .deployer()
        .with_stellar_asset(Bytes::from_array(env, &[0; 4]))
        .deployed_address();
    if asset == &native {
        String::from_str(env, "XLM")
    } else {
        token::Client::new(env, asset).symbol()
    }
}

fn move_tokens(env: &Env, asset: &Address, recipient: &Address, amount: i128) -> Result<(), Error> {
    if amount <= 0 {
        return Err(Error::InvalidAmount);
    }
    if recipient == &env.current_contract_address() {
        return Err(Error::InvalidRecipient);
    }
    let client = token::Client::new(env, asset);
    let from = env.current_contract_address();
    let before_from = client.balance(&from);
    let before_to = client.balance(recipient);
    if before_from < amount {
        return Err(Error::InsufficientFunds);
    }
    let after_from = before_from.checked_sub(amount).ok_or(Error::Overflow)?;
    let after_to = before_to.checked_add(amount).ok_or(Error::Overflow)?;
    // Only this exact direct SAC transfer receives the ODC's invoker authority.
    // No authority is delegated to the engine or to arbitrary nested calls.
    client.transfer(&from, recipient, &amount);
    if client.balance(&from) != after_from || client.balance(recipient) != after_to {
        return Err(Error::InvalidEffects);
    }
    Ok(())
}

// Both authorization routes consume identical policy, grant and replay state.
// Hook writes roll back with the enclosing SAC transfer if that transfer fails.
fn admit(
    env: &Env,
    execution: ExecutionRequest,
    token_label: String,
) -> Result<TransferReceipt, Error> {
    let mut s = load(env)?;
    // Authentication covers the complete invocation before canonical arguments are decoded.
    let installed = binding(env)?;
    let invocation = &execution.invocation;
    if execution.policy_instance != installed.policy_instance
        || execution.operation_id == BytesN::from_array(env, &[0; 32])
        || invocation.module_digest != installed.module_digest
        || invocation.entrypoint != installed.entrypoint
        || invocation.argument_schema_digest != installed.argument_schema_digest
        || invocation.arguments.len() > MAX_ARGUMENT_BYTES
    {
        return Err(Error::InvalidInvocation);
    }
    let arguments = Sep41TransferArgs::from_xdr(env, &invocation.arguments)
        .map_err(|_| Error::InvalidInvocation)?;
    if arguments.clone().to_xdr(env) != invocation.arguments
        || arguments.token != s.grant.asset
        || arguments.from != env.current_contract_address()
    {
        return Err(Error::InvalidInvocation);
    }
    let operation_key = Key::Operation(execution.operation_id.clone());
    if env.storage().persistent().has(&operation_key) {
        return Err(Error::Replay);
    }
    let request = TransferRequest {
        recipient: arguments.to.clone(),
        amount: arguments.amount,
        nonce: execution.nonce,
        revision: execution.policy_version,
        expires_at: execution.expires_at,
    };
    if s.paused {
        return Err(Error::Paused);
    }
    if request.nonce != s.nonce || request.revision != s.policy_version {
        return Err(Error::StaleRequest);
    }
    let now = env.ledger().timestamp();
    if request.expires_at <= now
        || s.grant.expires_at <= now
        || request.expires_at > s.grant.expires_at
    {
        return Err(Error::Expired);
    }
    if request.amount <= 0 {
        return Err(Error::InvalidAmount);
    }
    if !s.grant.recipients.contains(&request.recipient)
        || request.recipient == env.current_contract_address()
    {
        return Err(Error::InvalidRecipient);
    }
    let day = now / DAY;
    if day < s.spent_day {
        return Err(Error::ClockRegression);
    }
    let spent_daily = if day == s.spent_day { s.spent_daily } else { 0 };
    let next_daily = spent_daily
        .checked_add(request.amount)
        .ok_or(Error::Overflow)?;
    let next_total = s
        .spent_total
        .checked_add(request.amount)
        .ok_or(Error::Overflow)?;
    let next_calls = s.calls.checked_add(1).ok_or(Error::Overflow)?;
    let next_nonce = s.nonce.checked_add(1).ok_or(Error::Overflow)?;
    if request.amount > s.grant.per_transfer
        || next_daily > s.grant.daily_limit
        || next_total > s.grant.total_limit
        || next_calls > s.grant.max_calls
    {
        return Err(Error::BudgetExceeded);
    }
    let policy_context = PolicyContext {
        asset: s.grant.asset.clone(),
        recipient: request.recipient.clone(),
        token: token_label,
        decimals: 7,
        amount: request.amount,
        spent_daily,
        spent_total: s.spent_total,
        calls: s.calls,
        now,
        spent_day: day,
    };
    if !generated_policy::execute(&policy_context) {
        return Err(Error::PolicyDenied);
    }
    let context = EngineContext {
        wallet: env.current_contract_address(),
        agent: s.agent.clone(),
        asset: s.grant.asset.clone(),
        request: request.clone(),
        grant: s.grant.clone(),
        spent_daily,
        spent_total: s.spent_total,
        calls: s.calls,
        now,
    };
    if !matches!(
        EngineClient::new(env, &s.engine).try_evaluate(&context),
        Ok(Ok(true))
    ) {
        return Err(Error::EngineDenied);
    }
    // Commit local counters before the effect; host rollback restores them if
    // the SAC transfer or exact balance-effect check fails.
    s.spent_daily = next_daily;
    s.spent_day = day;
    s.spent_total = next_total;
    s.calls = next_calls;
    s.nonce = next_nonce;
    store(env, &s);
    let receipt = TransferReceipt {
        operation_id: execution.operation_id,
        token: s.grant.asset,
        from: env.current_contract_address(),
        to: request.recipient,
        amount: request.amount,
        nonce: request.nonce,
        policy_version: request.revision,
    };
    env.storage().persistent().set(&operation_key, &receipt);
    let ttl = env.storage().max_ttl();
    env.storage()
        .persistent()
        .extend_ttl(&operation_key, ttl / 2, ttl);
    Ok(receipt)
}

#[contractimpl]
impl Odc {
    pub fn __constructor(
        env: Env,
        owner: Address,
        agent: Address,
        engine: Address,
        grant: Grant,
        policy_instance: BytesN<32>,
    ) {
        owner.require_auth();
        if policy_instance == BytesN::from_array(&env, &[0; 32]) {
            soroban_sdk::panic_with_error!(&env, Error::InvalidState);
        }
        if let Err(error) = validate_roles(&env, &owner, &agent, &engine) {
            soroban_sdk::panic_with_error!(&env, error);
        }
        if grant.asset.executable() != Some(Executable::StellarAsset)
            || token::Client::new(&env, &grant.asset).decimals() != 7
        {
            soroban_sdk::panic_with_error!(&env, Error::UnsupportedAsset);
        }
        if let Err(error) = validate_grant(&env, &grant) {
            soroban_sdk::panic_with_error!(&env, error);
        }
        env.storage()
            .instance()
            .set(&Key::PolicyInstance, &policy_instance);
        store(
            &env,
            &State {
                version: VERSION,
                owner,
                agent,
                engine,
                grant,
                spent_daily: 0,
                spent_day: env.ledger().timestamp() / DAY,
                spent_total: 0,
                calls: 0,
                nonce: 0,
                policy_version: 0,
                paused: false,
            },
        );
    }

    pub fn state(env: Env) -> Result<State, Error> {
        load(&env)
    }

    /// Immutable installed native module and argument schema for the generated policy wrapper.
    pub fn policy_binding(env: Env) -> Result<PolicyBinding, Error> {
        binding(&env)
    }

    /// Generated transport wrapper around the statically compiled private owner policy.
    /// The admitted native operation is stellar::sep41_transfer, not a second wallet API.
    pub fn execute(env: Env, execution: ExecutionRequest) -> Result<TransferReceipt, Error> {
        let s = load(&env)?;
        s.agent.require_auth();
        let receipt = admit(&env, execution, policy_token(&env, &s.grant.asset))?;
        move_tokens(&env, &receipt.token, &receipt.to, receipt.amount)?;
        Ok(receipt)
    }

    /// Apply one complete owner-approved policy deployment at the next version.
    pub fn deploy_policy(env: Env, deployment: PolicyDeployment) -> Result<(), Error> {
        let mut s = owner_state(&env)?;
        if s.policy_version.checked_add(1).ok_or(Error::Overflow)? != deployment.policy_version {
            return Err(Error::StaleRequest);
        }
        validate_roles(
            &env,
            &deployment.owner,
            &deployment.agent,
            &deployment.engine,
        )?;
        if deployment.grant.asset != s.grant.asset {
            return Err(Error::UnsupportedAsset);
        }
        validate_grant(&env, &deployment.grant)?;
        if deployment.owner != s.owner {
            deployment.owner.require_auth();
        }
        if (deployment.agent != s.agent || deployment.grant != s.grant)
            && deployment.x402_signer.is_some()
        {
            return Err(Error::InvalidActor);
        }
        if let Some(public_key) = deployment.x402_signer {
            let mut encoded = Bytes::from_slice(&env, &[0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0]);
            encoded.append(&public_key.clone().into());
            let agent = Address::from_xdr(&env, &encoded).map_err(|_| Error::InvalidActor)?;
            if agent != deployment.agent {
                return Err(Error::InvalidActor);
            }
            env.storage().instance().set(
                &Key::X402Config,
                &X402Config {
                    agent,
                    public_key,
                    token: policy_token(&env, &s.grant.asset),
                },
            );
        } else {
            env.storage().instance().remove(&Key::X402Config);
        }
        s.owner = deployment.owner;
        s.agent = deployment.agent;
        s.engine = deployment.engine;
        s.grant = deployment.grant;
        s.paused = deployment.paused;
        commit_deployment(&env, &mut s, deployment.policy_version)?;
        if let Some(hash) = deployment.wasm_hash {
            env.deployer()
                .update_current_contract(soroban_sdk::ContractExecutable::Wasm(hash));
        }
        Ok(())
    }

    /// Pause changes use the same next-policy-version sequence as deployments.
    pub fn set_pause(env: Env, paused: bool, policy_version: u64) -> Result<(), Error> {
        let mut s = owner_state(&env)?;
        s.paused = paused;
        commit_deployment(&env, &mut s, policy_version)
    }

    // A separate `recover_funds` ABI is unnecessary once `__check_auth` admits
    // owner-authorized token calls. The SDK delegates recovery to the Stellar rail vendor.
    pub fn recover(env: Env, recipient: Address, amount: i128) -> Result<(), Error> {
        let s = owner_state(&env)?;
        move_tokens(&env, &s.grant.asset, &recipient, amount)
    }

    /// General calls and arbitrary authorization are outside this transfer-only ABI.
    pub fn unsupported(_env: Env) -> Result<(), Error> {
        Err(Error::UnsupportedOperation)
    }
}

#[cfg(test)]
mod tests;

#[contractimpl]
impl CustomAccountInterface for Odc {
    type Signature = X402Authorization;
    type Error = Error;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        authorization: X402Authorization,
        contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let s = load(&env)?;
        let config: X402Config = env
            .storage()
            .instance()
            .get(&Key::X402Config)
            .ok_or(Error::UnsupportedOperation)?;
        if config.agent != s.agent || contexts.len() != 1 {
            return Err(Error::InvalidActor);
        }
        let Context::Contract(context) = contexts.get(0).ok_or(Error::InvalidInvocation)? else {
            return Err(Error::UnsupportedOperation);
        };
        if context.contract != s.grant.asset
            || context.fn_name != Symbol::new(&env, "transfer")
            || context.args.len() != 3
        {
            return Err(Error::UnsupportedOperation);
        }
        let from = Address::try_from_val(&env, &context.args.get(0).unwrap())
            .map_err(|_| Error::InvalidInvocation)?;
        let to = Address::try_from_val(&env, &context.args.get(1).unwrap())
            .map_err(|_| Error::InvalidInvocation)?;
        let amount = i128::try_from_val(&env, &context.args.get(2).unwrap())
            .map_err(|_| Error::InvalidInvocation)?;
        if authorization.execution.invocation.arguments.len() > MAX_ARGUMENT_BYTES {
            return Err(Error::InvalidInvocation);
        }
        let args = Sep41TransferArgs::from_xdr(&env, &authorization.execution.invocation.arguments)
            .map_err(|_| Error::InvalidInvocation)?;
        if from != env.current_contract_address()
            || args.from != from
            || args.token != context.contract
            || args.to != to
            || args.amount != amount
        {
            return Err(Error::InvalidInvocation);
        }
        let digest = env.crypto().sha256(
            &(
                Symbol::new(&env, "allowit_x402_v1"),
                signature_payload.to_bytes(),
                authorization.execution.clone(),
            )
                .to_xdr(&env),
        );
        env.crypto().ed25519_verify(
            &config.public_key,
            &digest.to_bytes().into(),
            &authorization.signature,
        );
        // No token callbacks here: SAC.transfer is already active. SAC identity was
        // admitted at installation; its native implementation enforces exact effects.
        admit(&env, authorization.execution, config.token)?;
        Ok(())
    }
}
