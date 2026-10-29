#![no_std]

use allowit_wallet_protocol::{
    ARGUMENT_SCHEMA_DESCRIPTOR, EngineError, EngineRequest, EngineResult, EngineState,
    ExecutionRequest, Grant, MAX_ARGUMENT_BYTES, PolicyBinding, PolicyContext, PolicyEngine,
    PolicyFailure, Sep41TransferArgs, TransferReceipt, TransferRequest, named_values_valid,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Executable, String, Symbol, TryFromVal, Vec,
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    token,
    xdr::{FromXdr, ToXdr},
};

mod persistent;
mod policy_storage;
use policy_storage::NativePolicyStorage;

#[cfg(not(any(feature = "test-recipient-policy", feature = "test-xlm-policy", feature="test-state-policy",feature="test-local-state-policy")))]
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
#[cfg(feature="test-state-policy")]
#[path="generated_state_policy.rs"]
#[rustfmt::skip]
mod generated_policy;
#[cfg(feature="test-local-state-policy")]
#[path="generated_local_state_policy.rs"]
#[rustfmt::skip]
mod generated_policy;
#[cfg(all(feature = "test-recipient-policy", feature = "test-xlm-policy"))]
compile_error!("Select only one test policy fixture");

#[cfg(test)]
const DAY: u64 = 86_400;
/// First explicitly numbered kernel release, not Cargo package semver or an admin counter.
const CONTRACT_VERSION: u32 = 1;
const TTL_THRESHOLD: u32 = 100_000;
const TTL_EXTEND: u32 = 200_000;

/// Protected wallet state for one contract release. Ordinary calls never migrate this layout.
/// Incompatible changes require explicit maintenance: pause, deploy and run a migration contract,
/// deploy the policy contract using the migrated state, then unpause. This ABI provides no migration helper.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    /// Contract release that owns this stored layout. Unknown releases reject instead of guessing a conversion.
    pub contract_version: u32,
    /// Current owner address. Native address authorization controls administration and financial recovery.
    pub owner: Address,
    /// Configured delegated executor address. The x402 path derives its signing key from an enabled G-address agent.
    pub agent: Address,
    /// Shared rule-engine address. Only authored checks invoke it; it has no owner administration authority.
    pub engine: Address,
    /// Immutable admitted native SAC. It defines transfer effects, accounting units and financial recovery.
    pub asset: Address,
    /// Owner-signed named configuration. Authored policy selects its validation and required keys.
    pub grant: soroban_sdk::Map<String, soroban_sdk::Val>,
    /// Strict next execution sequence shared by delegated spending paths. It is distinct from the native authorization nonce.
    pub nonce: u64,
    /// Active owner configuration counter. Executions use the current value; configuration changes target exactly the next value.
    pub deployment_version: u64,
    /// Whether delegated spending is blocked. Independent owner administration and recovery remain available.
    pub paused: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDeployment {
    /// Target owner configuration counter, exactly active deployment_version plus one. Stale or skipped targets reject.
    pub deployment_version: u64,
    /// Desired owner address. A handoff requires both the current and desired owners to authorize the exact packet.
    pub owner: Address,
    /// Configured delegated executor address. The x402 path derives its signing key from an enabled G-address agent.
    pub agent: Address,
    /// Shared rule-engine address. Only authored checks invoke it; it has no owner administration authority.
    pub engine: Address,
    /// Owner-signed named configuration. Authored policy selects its validation and required keys.
    pub grant: soroban_sdk::Map<String, soroban_sdk::Val>,
    /// Explicit owner opt-in for exact SAC authorization by the requested G-agent. False disables the path.
    pub x402_enabled: bool,
    /// Optional owner-selected uploaded kernel hash. The host applies it atomically with the configuration deployment.
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

/// Enabled agent identity and authenticated asset label. The raw key is derived from the G-address.
/// Native account threshold or signer changes do not revoke this owner delegation.
#[contracttype]
#[derive(Clone)]
pub struct X402Config {
    /// Configured delegated executor address. The x402 path derives its signing key from an enabled G-address agent.
    pub agent: Address,
    /// Authenticated installed asset label, cached outside the active SAC call to avoid authorization reentry.
    pub token: String,
}

#[contracttype]
#[derive(Clone)]
pub struct X402Authorization {
    /// Complete request bound to the host authorization payload, active deployment version and exact SAC transfer.
    pub execution: ExecutionRequest,
    /// 64-byte Ed25519 agent signature over the domain-separated host authorization payload and complete execution request.
    pub signature: BytesN<64>,
}

#[contract]
pub struct Odc;

fn agent_public_key(env: &Env, agent: &Address) -> Result<BytesN<32>, Error> {
    let encoded = agent.to_xdr(env);
    let prefix = [0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0];
    if encoded.len() != 44
        || prefix
            .iter()
            .enumerate()
            .any(|(i, byte)| encoded.get(i as u32) != Some(*byte))
    {
        return Err(Error::InvalidActor);
    }
    let mut key = [0u8; 32];
    encoded.slice(12..44).copy_into_slice(&mut key);
    Ok(BytesN::from_array(env, &key))
}

fn x402_config(env: &Env, agent: &Address) -> Result<X402Config, Error> {
    let raw: soroban_sdk::Val = env
        .storage()
        .instance()
        .get(&Key::X402Config)
        .ok_or(Error::UnsupportedOperation)?;
    let config = X402Config::try_from_val(env, &raw).map_err(|_| Error::InvalidState)?;
    if config.agent != *agent {
        return Err(Error::InvalidActor);
    }
    let fields = soroban_sdk::Map::<Symbol, soroban_sdk::Val>::try_from_val(env, &raw)
        .map_err(|_| Error::InvalidState)?;
    if fields.len() != 2 {
        return Err(Error::InvalidState);
    }
    Ok(config)
}

/// Trusted immutable request and owner configuration for compiler-selected checks.
/// Authored functional map operations cannot alter these captured custody bindings.
struct NativePolicyHost<'a> {
    env: &'a Env,
    engine: Address,
    request: EngineRequest,
    grant: Grant,
}
impl PolicyEngine for NativePolicyHost<'_> {
    fn request(&self) -> EngineRequest {
        self.request.clone()
    }

    fn engine_check(
        &self,
        method: &str,
        spent: &allowit_wallet_protocol::Spent,
        params: Vec<soroban_sdk::Val>,
    ) -> Result<EngineResult, PolicyFailure> {
        use soroban_sdk::IntoVal;
        let env = self.env;
        let state = EngineState {
            grant: self.grant.clone(),
            spent: spent.clone(),
        };
        let mut args = Vec::new(env);
        args.push_back(self.request.clone().into_val(env));
        args.push_back(state.into_val(env));
        args.append(&params);
        match env.try_invoke_contract::<EngineResult, EngineError>(
            &self.engine,
            &Symbol::new(env, method),
            args,
        ) {
            Ok(Ok(result)) => Ok(result),
            _ => Err(PolicyFailure),
        }
    }
}

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
        contract_version: CONTRACT_VERSION,
        policy_instance,
        module_digest,
        source_digest: BytesN::from_array(env, &generated_policy::SOURCE_HASH),
        argument_schema_digest: BytesN::from_array(env, &generated_policy::ARGUMENT_SCHEMA_HASH),
        entrypoint: Symbol::new(env, "_execute"),
    })
}

fn load(env: &Env, initial: Option<State>) -> Result<State, Error> {
    if let Some(state) = initial {
        store(env, &state);
    }
    let raw: soroban_sdk::Val = env
        .storage()
        .instance()
        .get(&0u32)
        .ok_or(Error::InvalidState)?;
    let s = State::try_from_val(env, &raw).map_err(|_| Error::InvalidState)?;
    let fields = soroban_sdk::Map::<Symbol, soroban_sdk::Val>::try_from_val(env, &raw)
        .map_err(|_| Error::InvalidState)?;
    if s.contract_version != CONTRACT_VERSION || fields.len() != 9 {
        return Err(Error::InvalidState);
    }
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
    Ok(s)
}

fn store(env: &Env, state: &State) {
    env.storage().instance().set(&0u32, state);
}

fn commit_deployment(env: &Env, s: &mut State, deployment_version: u64) -> Result<(), Error> {
    if s.deployment_version.checked_add(1).ok_or(Error::Overflow)? != deployment_version {
        return Err(Error::StaleRequest);
    }
    s.deployment_version = deployment_version;
    store(env, s);
    Ok(())
}

fn owner_state(env: &Env) -> Result<State, Error> {
    let s = load(env, None)?;
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
    mut s: State,
) -> Result<TransferReceipt, Error> {
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
        || arguments.token != s.asset
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
        deployment_version: execution.deployment_version,
        expires_at: execution.expires_at,
    };
    if s.paused {
        return Err(Error::Paused);
    }
    if request.nonce != s.nonce || request.deployment_version != s.deployment_version {
        return Err(Error::StaleRequest);
    }
    let now = env.ledger().timestamp();
    if request.expires_at <= now {
        return Err(Error::Expired);
    }
    if request.amount <= 0 {
        return Err(Error::InvalidAmount);
    }
    if request.recipient == env.current_contract_address() {
        return Err(Error::InvalidRecipient);
    }
    let next_nonce = s.nonce.checked_add(1).ok_or(Error::Overflow)?;
    let policy_context = PolicyContext {
        asset: s.asset.clone(),
        recipient: request.recipient.clone(),
        token: token_label,
        decimals: 7,
        amount: request.amount,
        now,
    };
    let host = NativePolicyHost {
        env,
        engine: s.engine.clone(),
        request: EngineRequest {
            wallet: env.current_contract_address(),
            agent: s.agent.clone(),
            asset: s.asset.clone(),
            token: policy_context.token.clone(),
            decimals: policy_context.decimals,
            recipient: request.recipient.clone(),
            amount: request.amount,
            operation_id: execution.operation_id.clone(),
            nonce: execution.nonce,
            deployment_version: execution.deployment_version,
            expires_at: execution.expires_at,
            now,
        },
        grant: s.grant.clone(),
    };
    let storage = NativePolicyStorage {
        env,
        policy_instance: installed.policy_instance,
    };
    let initial_spent = storage.load().map_err(|_| Error::InvalidState)?;
    let state = EngineState {
        grant: s.grant.clone(),
        spent: initial_spent.clone().unwrap_or_else(|| Grant::new(env)),
    };
    let final_spent = generated_policy::execute(&policy_context, &s.grant, &state, &host)
        .map_err(|_| Error::PolicyDenied)?;
    if !named_values_valid(env, &final_spent) {
        return Err(Error::InvalidState);
    }
    storage.commit(&initial_spent, &final_spent);
    // Native transaction rollback covers approved engine updates and authored property writes.
    s.nonce = next_nonce;
    store(env, &s);
    let receipt = TransferReceipt {
        operation_id: execution.operation_id,
        token: s.asset,
        from: env.current_contract_address(),
        to: request.recipient,
        amount: request.amount,
        nonce: request.nonce,
        deployment_version: request.deployment_version,
    };
    Ok(persistent::load(env, &operation_key, Some(&receipt)).unwrap())
}

#[contractimpl]
impl Odc {
    /// Create an owner-authorized wallet with immutable asset identity and an empty spent namespace.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `owner`: Independent administration authority; authorizes this exact constructor.
    /// - `agent`: Delegated executor, distinct from owner, engine and this wallet.
    /// - `engine`: Shared rule-engine address; it receives no custody authority.
    /// - `asset`: Immutable native SAC with seven decimal places, defining accounting and recovery units.
    /// - `grant`: Initial UTF-8 named raw values. The authored policy validates only the values it uses.
    /// - `policy_instance`: Nonzero stable 32-byte logical identity retained across deployments.
    ///
    /// # Returns
    /// Returns no value. Failed admission or authorization rolls back creation.
    pub fn __constructor(
        env: Env,
        owner: Address,
        agent: Address,
        engine: Address,
        asset: Address,
        grant: soroban_sdk::Map<String, soroban_sdk::Val>,
        policy_instance: BytesN<32>,
    ) {
        owner.require_auth();
        if !named_values_valid(&env, &grant) {
            soroban_sdk::panic_with_error!(&env, Error::InvalidGrant);
        }
        if policy_instance == BytesN::from_array(&env, &[0; 32]) {
            soroban_sdk::panic_with_error!(&env, Error::InvalidState);
        }
        if let Err(error) = validate_roles(&env, &owner, &agent, &engine) {
            soroban_sdk::panic_with_error!(&env, error);
        }
        if asset.executable() != Some(Executable::StellarAsset)
            || token::Client::new(&env, &asset).decimals() != 7
        {
            soroban_sdk::panic_with_error!(&env, Error::UnsupportedAsset);
        }
        env.storage()
            .instance()
            .set(&Key::PolicyInstance, &policy_instance);
        load(
            &env,
            Some(State {
                contract_version: CONTRACT_VERSION,
                owner,
                agent,
                engine,
                asset,
                grant,
                nonce: 0,
                deployment_version: 0,
                paused: false,
            }),
        )
        .unwrap();
    }

    /// Read wallet state after validating its contract release and exact stored layout.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    ///
    /// # Returns
    /// Returns protected configuration and execution ordering without reading spent or invoking the engine.
    pub fn state(env: Env) -> Result<State, Error> {
        load(&env, None)
    }

    /// Read installed policy identities and the executing contract release.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    ///
    /// # Returns
    /// Returns local binding metadata. It never calls the engine or depends on engine availability.
    pub fn policy_binding(env: Env) -> Result<PolicyBinding, Error> {
        binding(&env)
    }

    /// Read the complete persistent policy spent map through the native host view.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment. Callers do not serialize this argument.
    ///
    /// # Returns
    /// Returns the exact raw map, or None only for an absent entry. An existing empty map remains Some.
    /// Archived data follows native restoration rules and is never reinitialized. No write authority is granted.
    pub fn policy_spent(
        env: Env,
    ) -> Result<Option<soroban_sdk::Map<String, soroban_sdk::Val>>, Error> {
        load(&env, None)?;
        let policy_instance = env
            .storage()
            .instance()
            .get(&Key::PolicyInstance)
            .ok_or(Error::InvalidState)?;
        NativePolicyStorage {
            env: &env,
            policy_instance,
        }
        .load()
        .map_err(|_| Error::InvalidState)
    }

    /// Execute one exact delegated SAC transfer through the compiled policy and local grant.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `execution`: Canonical installed invocation, current deployment_version, next execution nonce, logical ID and expiry.
    ///
    /// # Returns
    /// Returns the committed transfer receipt. Effects, consumption and replay records roll back together on failure.
    pub fn execute(env: Env, execution: ExecutionRequest) -> Result<TransferReceipt, Error> {
        let s = load(&env, None)?;
        s.agent.require_auth();
        let receipt = admit(&env, execution, policy_token(&env, &s.asset), s)?;
        move_tokens(&env, &receipt.token, &receipt.to, receipt.amount)?;
        Ok(receipt)
    }

    /// Commit one complete owner-approved policy configuration at the next deployment version.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `deployment`: Complete desired configuration, target active version plus one and optional uploaded kernel hash. A changed owner must also authorize.
    ///
    /// # Returns
    /// Returns success after an atomic configuration commit. Existing consumption, execution nonce and operation IDs remain intact.
    pub fn deploy_policy(env: Env, deployment: PolicyDeployment) -> Result<(), Error> {
        let mut s = owner_state(&env)?;
        if s.deployment_version.checked_add(1).ok_or(Error::Overflow)?
            != deployment.deployment_version
        {
            return Err(Error::StaleRequest);
        }
        if !named_values_valid(&env, &deployment.grant) {
            return Err(Error::InvalidGrant);
        }
        validate_roles(
            &env,
            &deployment.owner,
            &deployment.agent,
            &deployment.engine,
        )?;
        if deployment.owner != s.owner {
            deployment.owner.require_auth();
        }
        if deployment.x402_enabled {
            agent_public_key(&env, &deployment.agent)?;
            env.storage().instance().set(
                &Key::X402Config,
                &X402Config {
                    agent: deployment.agent.clone(),
                    token: policy_token(&env, &s.asset),
                },
            );
        } else {
            env.storage().instance().remove(&Key::X402Config);
        }
        s.owner = deployment.owner;
        s.agent = deployment.agent;
        s.engine = deployment.engine;
        s.grant = deployment.grant;
        s.deployment_version = deployment.deployment_version;
        store(&env, &s);
        if let Some(hash) = deployment.wasm_hash {
            env.deployer()
                .update_current_contract(soroban_sdk::ContractExecutable::Wasm(hash));
        }
        Ok(())
    }

    /// Pause or resume delegated execution using the shared owner configuration sequence.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `paused`: True blocks delegated spending; false permits it subject to all policy checks.
    /// - `deployment_version`: Target version, exactly current plus one. No independent admin nonce exists.
    ///
    /// # Returns
    /// Returns success after owner authorization and one version increment. It does not call the engine.
    pub fn set_pause(env: Env, paused: bool, deployment_version: u64) -> Result<(), Error> {
        let mut s = owner_state(&env)?;
        s.paused = paused;
        commit_deployment(&env, &mut s, deployment_version)
    }

    // A separate `recover_funds` ABI is unnecessary once `__check_auth` admits
    // owner-authorized token calls. The SDK delegates recovery to the Stellar rail vendor.

    /// Move installed-asset funds under independent owner authorization.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `recipient`: Owner-selected destination, distinct from the wallet.
    /// - `amount`: Positive native i128 base units of the installed SAC to transfer.
    ///
    /// # Returns
    /// Returns success after exact balance-effect checks. It has no caller version fence and does not change execution ordering or policy spent.
    pub fn recover(env: Env, recipient: Address, amount: i128) -> Result<(), Error> {
        let s = owner_state(&env)?;
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        if recipient == env.current_contract_address() {
            return Err(Error::InvalidRecipient);
        }
        move_tokens(&env, &s.asset, &recipient, amount)
    }

    /// Reject general calls and arbitrary authorization outside the admitted transfer ABI.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    ///
    /// # Returns
    /// Always returns UnsupportedOperation without authorizing an effect.
    pub fn unsupported(env: Env) -> Result<(), Error> {
        let _ = env;
        Err(Error::UnsupportedOperation)
    }
}

#[cfg(test)]
mod tests;

#[contractimpl]
impl CustomAccountInterface for Odc {
    type Signature = X402Authorization;
    type Error = Error;

    /// Authorize one exact installed-SAC transfer for the explicitly enabled G-address agent.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `signature_payload`: Host-supplied digest binding network, native authorization nonce, expiry and invocation tree.
    /// - `authorization`: Agent signature and complete installed execution request for this exact transfer.
    /// - `contexts`: Exactly one transfer context matching the installed SAC, wallet source, recipient and amount.
    ///
    /// # Returns
    /// Returns success only after derived-key verification and shared policy admission. Enclosing transaction failure rolls back accounting.
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        authorization: X402Authorization,
        contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let s = load(&env, None)?;
        let config = x402_config(&env, &s.agent)?;
        if contexts.len() != 1 {
            return Err(Error::InvalidActor);
        }
        let Context::Contract(context) = contexts.get(0).ok_or(Error::InvalidInvocation)? else {
            return Err(Error::UnsupportedOperation);
        };
        if context.contract != s.asset
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
            &agent_public_key(&env, &s.agent)?,
            &digest.to_bytes().into(),
            &authorization.signature,
        );
        // No token callbacks here: SAC.transfer is already active. SAC identity was
        // admitted at installation; its native implementation enforces exact effects.
        admit(&env, authorization.execution, config.token, s)?;
        Ok(())
    }
}
