#![no_std]
//! Owner-controlled custody mixins shared by fixed and bespoke policy wallets.
use allowit_wallet_protocol::{
    ARGUMENT_SCHEMA_DESCRIPTOR, EngineRequest, EngineResult, EngineState, ExecutionRequest, Grant,
    MAX_ARGUMENT_BYTES, PolicyBinding, PolicyContext, PolicyEngine, PolicyFailure,
    Sep41TransferArgs, Spent, TransferReceipt, named_values_valid,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Executable, String, Symbol, TryFromVal, Val, Vec,
    auth::{Context, InvokerContractAuthEntry},
    contracterror, contracttype,
    crypto::Hash,
    token,
    xdr::{FromXdr, ToXdr},
};
mod persistent;
mod policy_storage;
use policy_storage::NativePolicyStorage;
const STATE_KEY: u32 = 0;
pub const CONTRACT_VERSION: u32 = 1;

/// Initial owner-signed configuration. Asset and policy_instance stay fixed after creation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConfig {
    pub owner: Address,
    pub agent: Address,
    /// Independent service signer, never a parent-controlled checker address.
    pub server: Address,
    pub asset: Address,
    pub policy_instance: BytesN<32>,
    pub source_digest: BytesN<32>,
    /// Ordered explicit Common checks. Simple and Custom use an empty list.
    pub rules: Vec<Symbol>,
    pub grant: soroban_sdk::Map<String, Val>,
    pub x402_enabled: bool,
}

/// Complete owner update. It preserves asset, logical identity, nonce, pause and spent data.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDeployment {
    pub deployment_version: u64,
    pub owner: Address,
    pub agent: Address,
    pub server: Address,
    pub source_digest: BytesN<32>,
    pub rules: Vec<Symbol>,
    pub grant: soroban_sdk::Map<String, Val>,
    pub x402_enabled: bool,
    pub wasm_hash: Option<BytesN<32>>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub contract_version: u32,
    pub owner: Address,
    pub agent: Address,
    pub server: Address,
    pub asset: Address,
    pub policy_instance: BytesN<32>,
    pub source_digest: BytesN<32>,
    pub rules: Vec<Symbol>,
    pub grant: soroban_sdk::Map<String, Val>,
    pub x402_enabled: bool,
    /// Authenticated SAC label cached before any active-token authorization callback.
    pub token: String,
    pub deployment_version: u64,
    pub nonce: u64,
    pub paused: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct PolicyAuthorization {
    pub execution: ExecutionRequest,
    pub agent_signature: BytesN<64>,
    pub server_signature: BytesN<64>,
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
    Operation(BytesN<32>),
}

/// Compile-time policy mixin. No runtime fallback or system-controlled executable reference exists.
pub trait Policy {
    const KIND: &'static str;
    /// A bespoke implementation binds its compiled source. Fixed tiers use the owner's source digest.
    fn source_digest(_env: &Env) -> Option<BytesN<32>> {
        None
    }
    fn validate(env: &Env, rules: &Vec<Symbol>, grant: &Grant) -> Result<(), Error>;
    fn check(
        env: &Env,
        request: EngineRequest,
        state: EngineState,
        rules: &Vec<Symbol>,
    ) -> Result<Spent, Error>;
}

/// Read initialized state and maintain its instance and code lifetime. Constructor initialization is explicit.
fn load(env: &Env, initial: Option<State>) -> Result<State, Error> {
    if let Some(state) = initial {
        store(env, &state);
    }
    let raw: Val = env
        .storage()
        .instance()
        .get(&STATE_KEY)
        .ok_or(Error::InvalidState)?;
    let state = State::try_from_val(env, &raw).map_err(|_| Error::InvalidState)?;
    let fields = soroban_sdk::Map::<Symbol, Val>::try_from_val(env, &raw)
        .map_err(|_| Error::InvalidState)?;
    if state.contract_version != CONTRACT_VERSION || fields.len() != 14 {
        return Err(Error::InvalidState);
    }
    let ttl = env.storage().max_ttl();
    env.deployer()
        .extend_ttl(env.current_contract_address(), ttl / 2, ttl);
    Ok(state)
}
fn store(env: &Env, state: &State) {
    env.storage().instance().set(&STATE_KEY, state);
}
fn owner_state(env: &Env) -> Result<State, Error> {
    let state = load(env, None)?;
    state.owner.require_auth();
    Ok(state)
}
fn public_key(env: &Env, address: &Address) -> Result<BytesN<32>, Error> {
    let encoded = address.to_xdr(env);
    let prefix = [0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0];
    if encoded.len() != 44
        || prefix
            .iter()
            .enumerate()
            .any(|(i, b)| encoded.get(i as u32) != Some(*b))
    {
        return Err(Error::InvalidActor);
    }
    let mut key = [0; 32];
    encoded.slice(12..44).copy_into_slice(&mut key);
    Ok(BytesN::from_array(env, &key))
}
fn validate<P: Policy>(env: &Env, config: &PolicyConfig) -> Result<(), Error> {
    let roles = [&config.owner, &config.agent, &config.server];
    for (i, role) in roles.iter().enumerate() {
        if **role == env.current_contract_address() || roles[..i].contains(role) {
            return Err(Error::InvalidActor);
        }
    }
    if config.policy_instance == BytesN::from_array(env, &[0; 32])
        || config.source_digest == BytesN::from_array(env, &[0; 32])
    {
        return Err(Error::InvalidState);
    }
    if P::source_digest(env).is_some_and(|digest| digest != config.source_digest) {
        return Err(Error::InvalidState);
    }
    if !named_values_valid(env, &config.grant) {
        return Err(Error::InvalidGrant);
    }
    if config.x402_enabled {
        public_key(env, &config.agent)?;
        public_key(env, &config.server)?;
    }
    P::validate(env, &config.rules, &config.grant)
}
fn binding<P: Policy>(env: &Env, state: &State) -> Result<PolicyBinding, Error> {
    let Some(Executable::Wasm(module_digest)) = env.current_contract_address().executable() else {
        return Err(Error::InvalidState);
    };
    if P::source_digest(env).is_some_and(|digest| digest != state.source_digest) {
        return Err(Error::InvalidState);
    }
    Ok(PolicyBinding {
        engine_kind: Symbol::new(env, P::KIND),
        contract_version: CONTRACT_VERSION,
        policy_instance: state.policy_instance.clone(),
        module_digest,
        source_digest: state.source_digest.clone(),
        argument_schema_digest: env
            .crypto()
            .sha256(&Bytes::from_slice(env, ARGUMENT_SCHEMA_DESCRIPTOR))
            .to_bytes(),
        entrypoint: Symbol::new(env, "_execute"),
    })
}
fn token_label(env: &Env, asset: &Address) -> String {
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
// A transfer to a classic issuer burns its asset. Derive the immutable SAC identity
// from the cached symbol and candidate issuer without reentering the active SAC.
fn issuer_destination(env: &Env, state: &State, to: &Address) -> Result<bool, Error> {
    let len = state.token.len() as usize;
    if len == 0 || len > 48 {
        return Err(Error::InvalidState);
    }
    let mut encoded = [0u8; 48];
    state.token.copy_into_slice(&mut encoded[..len]);
    let mut code = [0u8; 12];
    let mut cursor = 0;
    let mut size = 0;
    while cursor < len {
        if size == 12 {
            return Err(Error::InvalidState);
        }
        code[size] = if encoded[cursor] == b'\\' {
            if cursor + 3 >= len || encoded[cursor + 1] != b'x' {
                return Err(Error::InvalidState);
            }
            let hex = |b| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            let (Some(high), Some(low)) = (hex(encoded[cursor + 2]), hex(encoded[cursor + 3]))
            else {
                return Err(Error::InvalidState);
            };
            cursor += 4;
            high * 16 + low
        } else {
            let b = encoded[cursor];
            cursor += 1;
            b
        };
        size += 1;
    }
    // SEP-11 keeps at least five bytes for AlphaNum12, including escaped zeros.
    let (kind, width) = if size <= 4 { (1u32, 4) } else { (2u32, 12) };
    let Ok(issuer) = public_key(env, to) else {
        return Ok(false);
    };
    let mut asset = Bytes::from_array(env, &kind.to_be_bytes());
    asset.append(&Bytes::from_slice(env, &code[..width]));
    asset.append(&Bytes::from_array(env, &[0; 4]));
    asset.append(&issuer.into());
    Ok(env.deployer().with_stellar_asset(asset).deployed_address() == state.asset)
}
fn move_tokens(env: &Env, asset: &Address, to: &Address, amount: i128) -> Result<(), Error> {
    let client = token::Client::new(env, asset);
    let from = env.current_contract_address();
    let before = client.balance(&from);
    if before < amount {
        return Err(Error::InsufficientFunds);
    }
    let after_from = before.checked_sub(amount).ok_or(Error::Overflow)?;
    let after_to = client
        .balance(to)
        .checked_add(amount)
        .ok_or(Error::Overflow)?;
    client.transfer(&from, to, &amount);
    if client.balance(&from) != after_from || client.balance(to) != after_to {
        return Err(Error::InvalidEffects);
    }
    Ok(())
}
fn admit<P: Policy>(
    env: &Env,
    execution: ExecutionRequest,
    mut state: State,
) -> Result<TransferReceipt, Error> {
    let installed = binding::<P>(env, &state)?;
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
    let args = Sep41TransferArgs::from_xdr(env, &invocation.arguments)
        .map_err(|_| Error::InvalidInvocation)?;
    if args.clone().to_xdr(env) != invocation.arguments
        || args.token != state.asset
        || args.from != env.current_contract_address()
    {
        return Err(Error::InvalidInvocation);
    }
    let operation = Key::Operation(execution.operation_id.clone());
    if env.storage().persistent().has(&operation) {
        return Err(Error::Replay);
    }
    if state.paused {
        return Err(Error::Paused);
    }
    if execution.nonce != state.nonce || execution.deployment_version != state.deployment_version {
        return Err(Error::StaleRequest);
    }
    let now = env.ledger().timestamp();
    if execution.expires_at <= now {
        return Err(Error::Expired);
    }
    if args.amount <= 0 {
        return Err(Error::InvalidAmount);
    }
    if args.to == env.current_contract_address() || issuer_destination(env, &state, &args.to)? {
        return Err(Error::InvalidRecipient);
    }
    let nonce = state.nonce.checked_add(1).ok_or(Error::Overflow)?;
    let request = EngineRequest {
        wallet: args.from.clone(),
        agent: state.agent.clone(),
        asset: state.asset.clone(),
        token: state.token.clone(),
        decimals: 7,
        recipient: args.to.clone(),
        amount: args.amount,
        operation_id: execution.operation_id.clone(),
        nonce: execution.nonce,
        deployment_version: execution.deployment_version,
        expires_at: execution.expires_at,
        now,
    };
    let storage = NativePolicyStorage {
        env,
        policy_instance: state.policy_instance.clone(),
    };
    let initial = storage.load().map_err(|_| Error::InvalidState)?;
    P::validate(env, &state.rules, &state.grant)?;
    let final_spent = P::check(
        env,
        request,
        EngineState {
            grant: state.grant.clone(),
            spent: initial.clone().unwrap_or_else(|| Spent::new(env)),
        },
        &state.rules,
    )?;
    if !named_values_valid(env, &final_spent) {
        return Err(Error::InvalidState);
    }
    storage.commit(&initial, &final_spent);
    state.nonce = nonce;
    store(env, &state);
    let receipt = TransferReceipt {
        operation_id: execution.operation_id,
        token: state.asset,
        from: args.from,
        to: args.to,
        amount: args.amount,
        nonce: execution.nonce,
        deployment_version: execution.deployment_version,
    };
    Ok(persistent::load(env, &operation, Some(&receipt)).unwrap())
}

pub fn construct<P: Policy>(env: &Env, config: PolicyConfig) -> Result<(), Error> {
    config.owner.require_auth();
    validate::<P>(env, &config)?;
    if config.asset.executable() != Some(Executable::StellarAsset) {
        return Err(Error::UnsupportedAsset);
    }
    let token = token_label(env, &config.asset);
    load(
        env,
        Some(State {
            contract_version: CONTRACT_VERSION,
            owner: config.owner,
            agent: config.agent,
            server: config.server,
            asset: config.asset,
            policy_instance: config.policy_instance,
            source_digest: config.source_digest,
            rules: config.rules,
            grant: config.grant,
            x402_enabled: config.x402_enabled,
            token,
            deployment_version: 0,
            nonce: 0,
            paused: false,
        }),
    )?;
    Ok(())
}
pub fn state(env: &Env) -> Result<State, Error> {
    load(env, None)
}
pub fn policy_binding<P: Policy>(env: &Env) -> Result<PolicyBinding, Error> {
    binding::<P>(env, &load(env, None)?)
}
pub fn policy_spent(env: &Env) -> Result<Option<Spent>, Error> {
    let state = load(env, None)?;
    NativePolicyStorage {
        env,
        policy_instance: state.policy_instance,
    }
    .load()
    .map_err(|_| Error::InvalidState)
}
pub fn execute<P: Policy>(
    env: &Env,
    execution: ExecutionRequest,
) -> Result<TransferReceipt, Error> {
    let state = load(env, None)?;
    state.agent.require_auth();
    state.server.require_auth();
    let receipt = admit::<P>(env, execution, state)?;
    move_tokens(env, &receipt.token, &receipt.to, receipt.amount)?;
    Ok(receipt)
}
pub fn deploy_policy<P: Policy>(env: &Env, deployment: PolicyDeployment) -> Result<(), Error> {
    let mut state = owner_state(env)?;
    if state
        .deployment_version
        .checked_add(1)
        .ok_or(Error::Overflow)?
        != deployment.deployment_version
    {
        return Err(Error::StaleRequest);
    }
    let config = PolicyConfig {
        owner: deployment.owner,
        agent: deployment.agent,
        server: deployment.server,
        asset: state.asset.clone(),
        policy_instance: state.policy_instance.clone(),
        source_digest: deployment.source_digest,
        rules: deployment.rules,
        grant: deployment.grant,
        x402_enabled: deployment.x402_enabled,
    };
    // A new bespoke executable validates its source on its next call. The owner binds its exact hash.
    if deployment.wasm_hash.as_ref().is_none_or(|hash| {
        env.current_contract_address().executable() == Some(Executable::Wasm(hash.clone()))
    }) {
        validate::<P>(env, &config)?;
    } else {
        validate::<UpgradeConfig>(env, &config)?;
    }
    if config.owner != state.owner {
        config.owner.require_auth();
    }
    state.owner = config.owner;
    state.agent = config.agent;
    state.server = config.server;
    state.source_digest = config.source_digest;
    state.rules = config.rules;
    state.grant = config.grant;
    state.x402_enabled = config.x402_enabled;
    state.deployment_version = deployment.deployment_version;
    store(env, &state);
    if let Some(hash) = deployment.wasm_hash {
        env.deployer()
            .update_current_contract(soroban_sdk::ContractExecutable::Wasm(hash));
    }
    Ok(())
}
struct UpgradeConfig;
impl Policy for UpgradeConfig {
    const KIND: &'static str = "upgrade";
    fn validate(_env: &Env, _rules: &Vec<Symbol>, _grant: &Grant) -> Result<(), Error> {
        Ok(())
    }
    fn check(
        _env: &Env,
        _request: EngineRequest,
        _state: EngineState,
        _rules: &Vec<Symbol>,
    ) -> Result<Spent, Error> {
        Err(Error::PolicyDenied)
    }
}
pub fn set_pause(env: &Env, paused: bool, deployment_version: u64) -> Result<(), Error> {
    let mut state = owner_state(env)?;
    if state
        .deployment_version
        .checked_add(1)
        .ok_or(Error::Overflow)?
        != deployment_version
    {
        return Err(Error::StaleRequest);
    }
    state.paused = paused;
    state.deployment_version = deployment_version;
    store(env, &state);
    Ok(())
}
pub fn recover(env: &Env, recipient: Address, amount: i128) -> Result<(), Error> {
    let state = owner_state(env)?;
    if amount <= 0 {
        return Err(Error::InvalidAmount);
    }
    if recipient == env.current_contract_address() || issuer_destination(env, &state, &recipient)? {
        return Err(Error::InvalidRecipient);
    }
    move_tokens(env, &state.asset, &recipient, amount)
}
/// Owner-signed passthrough. Native authorization binds target, arguments and every nested scope.
pub fn invoke(
    env: &Env,
    contract: Address,
    function: Symbol,
    args: Vec<Val>,
    auth: Vec<InvokerContractAuthEntry>,
) -> Result<Val, Error> {
    owner_state(env)?;
    env.authorize_as_current_contract(auth);
    Ok(env.invoke_contract(&contract, &function, args))
}
pub fn check_auth<P: Policy>(
    env: &Env,
    payload: Hash<32>,
    authorization: PolicyAuthorization,
    contexts: Vec<Context>,
) -> Result<(), Error> {
    let state = load(env, None)?;
    if !state.x402_enabled {
        return Err(Error::UnsupportedOperation);
    }
    if contexts.len() != 1 {
        return Err(Error::InvalidInvocation);
    }
    let Context::Contract(context) = contexts.get(0).ok_or(Error::InvalidInvocation)? else {
        return Err(Error::UnsupportedOperation);
    };
    if context.contract != state.asset
        || context.fn_name != Symbol::new(env, "transfer")
        || context.args.len() != 3
    {
        return Err(Error::UnsupportedOperation);
    }
    let from = Address::try_from_val(env, &context.args.get(0).unwrap())
        .map_err(|_| Error::InvalidInvocation)?;
    let to = Address::try_from_val(env, &context.args.get(1).unwrap())
        .map_err(|_| Error::InvalidInvocation)?;
    let amount = i128::try_from_val(env, &context.args.get(2).unwrap())
        .map_err(|_| Error::InvalidInvocation)?;
    if authorization.execution.invocation.arguments.len() > MAX_ARGUMENT_BYTES {
        return Err(Error::InvalidInvocation);
    }
    let args = Sep41TransferArgs::from_xdr(env, &authorization.execution.invocation.arguments)
        .map_err(|_| Error::InvalidInvocation)?;
    if from != env.current_contract_address()
        || args.from != from
        || args.token != context.contract
        || args.to != to
        || args.amount != amount
    {
        return Err(Error::InvalidInvocation);
    }
    let digest = env
        .crypto()
        .sha256(
            &(
                Symbol::new(env, "allowit_wallet_v1"),
                payload.to_bytes(),
                authorization.execution.clone(),
            )
                .to_xdr(env),
        )
        .to_bytes();
    env.crypto().ed25519_verify(
        &public_key(env, &state.agent)?,
        &digest.clone().into(),
        &authorization.agent_signature,
    );
    env.crypto().ed25519_verify(
        &public_key(env, &state.server)?,
        &digest.clone().into(),
        &authorization.server_signature,
    );
    admit::<P>(env, authorization.execution, state)?;
    Ok(())
}

/// Fixed minimal policy: server approval is mandatory, with no onchain business predicates.
pub struct Simple;
impl Policy for Simple {
    const KIND: &'static str = "simple_policy_engine";
    fn validate(_env: &Env, rules: &Vec<Symbol>, _grant: &Grant) -> Result<(), Error> {
        if rules.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidGrant)
        }
    }
    fn check(
        _env: &Env,
        _request: EngineRequest,
        state: EngineState,
        _rules: &Vec<Symbol>,
    ) -> Result<Spent, Error> {
        Ok(state.spent)
    }
}
/// Fixed canonical rule set. The owner chooses every enforced rule explicitly.
pub struct Common;
impl Policy for Common {
    const KIND: &'static str = "common_policy_engine";
    fn validate(env: &Env, rules: &Vec<Symbol>, grant: &Grant) -> Result<(), Error> {
        for (i, rule) in rules.iter().enumerate() {
            if rules.iter().take(i).any(|prior| prior == rule) {
                return Err(Error::InvalidGrant);
            }
            allowit_policy_rules::validate_rule(env, &rule, grant)
                .map_err(|_| Error::InvalidGrant)?;
        }
        Ok(())
    }
    fn check(
        env: &Env,
        request: EngineRequest,
        mut state: EngineState,
        rules: &Vec<Symbol>,
    ) -> Result<Spent, Error> {
        let grant = state.grant.clone();
        for rule in rules.iter() {
            let result = if rule == Symbol::new(env, "transaction_cap") {
                allowit_policy_rules::transaction_cap(env.clone(), request.clone(), state)
            } else if rule == Symbol::new(env, "daily_cap") {
                allowit_policy_rules::daily_cap(env.clone(), request.clone(), state)
            } else if rule == Symbol::new(env, "total_cap") {
                allowit_policy_rules::total_cap(env.clone(), request.clone(), state)
            } else if rule == Symbol::new(env, "call_cap") {
                allowit_policy_rules::call_cap(env.clone(), request.clone(), state)
            } else if rule == Symbol::new(env, "recipient") {
                allowit_policy_rules::recipient(env.clone(), request.clone(), state)
            } else if rule == Symbol::new(env, "expiry") {
                allowit_policy_rules::expiry(env.clone(), request.clone(), state)
            } else if rule == Symbol::new(env, "token") {
                allowit_policy_rules::token(env.clone(), request.clone(), state)
            } else {
                return Err(Error::InvalidGrant);
            }
            .map_err(|_| Error::PolicyDenied)?;
            if !result.approval {
                return Err(Error::PolicyDenied);
            }
            state = EngineState {
                grant: grant.clone(),
                spent: result.spent,
            };
            // Each check receives the original owner Grant; final Spent alone advances.
        }
        Ok(state.spent)
    }
}

/// Local-only capability supplied to generated bespoke policies. Shared fallback is unavailable.
pub struct LocalPolicyHost(pub EngineRequest);
impl PolicyEngine for LocalPolicyHost {
    fn request(&self) -> EngineRequest {
        self.0.clone()
    }
    fn engine_check(
        &self,
        _method: &str,
        _spent: &Spent,
        _params: Vec<Val>,
    ) -> Result<EngineResult, PolicyFailure> {
        Err(PolicyFailure)
    }
}
pub fn context(request: &EngineRequest) -> PolicyContext {
    PolicyContext {
        asset: request.asset.clone(),
        recipient: request.recipient.clone(),
        token: request.token.clone(),
        decimals: request.decimals,
        amount: request.amount,
        now: request.now,
    }
}

/// Attach the complete owner and delegated-execution interface to a policy implementation.
#[macro_export]
macro_rules! policy_wallet {
    ($name:ident, $policy:ty) => {
        #[soroban_sdk::contract]
        pub struct $name;
        #[soroban_sdk::contractimpl]
        impl $name {
            pub fn __constructor(env: soroban_sdk::Env, config: $crate::PolicyConfig) {
                $crate::construct::<$policy>(&env, config).unwrap();
            }
            pub fn state(env: soroban_sdk::Env) -> Result<$crate::State, $crate::Error> {
                $crate::state(&env)
            }
            pub fn policy_binding(
                env: soroban_sdk::Env,
            ) -> Result<allowit_wallet_protocol::PolicyBinding, $crate::Error> {
                $crate::policy_binding::<$policy>(&env)
            }
            pub fn policy_spent(
                env: soroban_sdk::Env,
            ) -> Result<
                Option<soroban_sdk::Map<soroban_sdk::String, soroban_sdk::Val>>,
                $crate::Error,
            > {
                $crate::policy_spent(&env)
            }
            pub fn execute(
                env: soroban_sdk::Env,
                execution: allowit_wallet_protocol::ExecutionRequest,
            ) -> Result<allowit_wallet_protocol::TransferReceipt, $crate::Error> {
                $crate::execute::<$policy>(&env, execution)
            }
            pub fn deploy_policy(
                env: soroban_sdk::Env,
                deployment: $crate::PolicyDeployment,
            ) -> Result<(), $crate::Error> {
                $crate::deploy_policy::<$policy>(&env, deployment)
            }
            pub fn set_pause(
                env: soroban_sdk::Env,
                paused: bool,
                deployment_version: u64,
            ) -> Result<(), $crate::Error> {
                $crate::set_pause(&env, paused, deployment_version)
            }
            pub fn recover(
                env: soroban_sdk::Env,
                recipient: soroban_sdk::Address,
                amount: i128,
            ) -> Result<(), $crate::Error> {
                $crate::recover(&env, recipient, amount)
            }
            pub fn invoke(
                env: soroban_sdk::Env,
                contract: soroban_sdk::Address,
                function: soroban_sdk::Symbol,
                args: soroban_sdk::Vec<soroban_sdk::Val>,
                auth: soroban_sdk::Vec<soroban_sdk::auth::InvokerContractAuthEntry>,
            ) -> Result<soroban_sdk::Val, $crate::Error> {
                $crate::invoke(&env, contract, function, args, auth)
            }
        }
        #[soroban_sdk::contractimpl]
        impl soroban_sdk::auth::CustomAccountInterface for $name {
            type Signature = $crate::PolicyAuthorization;
            type Error = $crate::Error;
            fn __check_auth(
                env: soroban_sdk::Env,
                signature_payload: soroban_sdk::crypto::Hash<32>,
                authorization: $crate::PolicyAuthorization,
                contexts: soroban_sdk::Vec<soroban_sdk::auth::Context>,
            ) -> Result<(), $crate::Error> {
                $crate::check_auth::<$policy>(&env, signature_payload, authorization, contexts)
            }
        }
    };
}

#[cfg(test)]
mod tests;
