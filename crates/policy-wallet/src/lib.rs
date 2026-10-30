#![no_std]
//! Owner-controlled custody mixins shared by fixed and bespoke policy wallets.
use allowit_wallet_protocol::{
    ARGUMENT_SCHEMA_DESCRIPTOR, AccountingHistory, EngineRequest, EngineResult, EngineState,
    ExecutionRequest, ExpenseBounds, Grant, MAX_ARGUMENT_BYTES, MAX_EXPENSE_BYTES, PolicyBinding,
    PolicyContext, PolicyEngine, PolicyFailure, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR, Sep41TransferArgs,
    Sep56DepositArgs, Sep56DepositEvent, Sep56DepositReceipt, Spent, TransferReceipt,
    named_values_valid,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Executable, String, Symbol, TryFromVal, Val, Vec,
    auth::{Context, ContractContext, InvokerContractAuthEntry, SubContractInvocation},
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
    /// Fixed standard prefix digest; Custom uses its complete compiled source digest.
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
    /// Fixed standard prefix digest; Custom uses its complete compiled source digest.
    pub source_digest: BytesN<32>,
    pub rules: Vec<Symbol>,
    pub grant: soroban_sdk::Map<String, Val>,
    pub x402_enabled: bool,
    pub wasm_hash: Option<BytesN<32>>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub history: AccountingHistory,
    pub contract_version: u32,
    pub owner: Address,
    pub agent: Address,
    pub server: Address,
    pub asset: Address,
    pub policy_instance: BytesN<32>,
    /// Fixed standard prefix digest; Custom uses its complete compiled source digest.
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
    Deposit(BytesN<32>),
}

/// Compile-time policy mixin. No runtime fallback or system-controlled executable reference exists.
pub trait Policy {
    const KIND: &'static str;
    /// Fixed standard implementations bind only their owner-approved initial preflight prefix.
    const STANDARD_PREFIX: bool = false;
    /// A bespoke implementation binds its compiled source. Fixed tiers use the owner's source digest.
    fn source_digest(_env: &Env) -> Option<BytesN<32>> {
        None
    }
    /// Default profile reported by policy_binding. Fixed tiers retain transfer as the default.
    fn argument_schema_digest(env: &Env) -> BytesN<32> {
        schema_digest(env, ARGUMENT_SCHEMA_DESCRIPTOR)
    }
    /// Admit only the compiled profile unless an implementation explicitly selects multiple native adapters.
    fn admits_schema(env: &Env, digest: &BytesN<32>) -> bool {
        *digest == Self::argument_schema_digest(env)
    }
    /// Evaluate the exact admitted operation. Existing fixed checks operate on its underlying debit.
    fn check_operation(
        env: &Env,
        request: EngineRequest,
        state: EngineState,
        rules: &Vec<Symbol>,
        _operation: &String,
    ) -> Result<Spent, Error> {
        Self::check(env, request, state, rules)
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
    if state.contract_version != CONTRACT_VERSION || fields.len() != 15 {
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
/// Pure standard-prefix binding. Grant values and the owner-signed offchain suffix are excluded.
pub fn standard_prefix_digest(
    env: &Env,
    kind: &Symbol,
    module: &BytesN<32>,
    asset: &Address,
    rules: &Vec<Symbol>,
) -> BytesN<32> {
    use soroban_sdk::IntoVal;
    let mut checks = Vec::<Val>::new(env);
    for name in rules.iter() {
        checks.push_back((name.clone(), name).into_val(env));
    }
    env.crypto()
        .sha256(
            &(
                Symbol::new(env, "allowit_std_prefix"),
                kind.clone(),
                module.clone(),
                asset.clone(),
                schema_digest(env, ARGUMENT_SCHEMA_DESCRIPTOR),
                schema_digest(env, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR),
                checks,
            )
                .to_xdr(env),
        )
        .to_bytes()
}
fn checked_prefix<P: Policy>(
    env: &Env,
    asset: &Address,
    rules: &Vec<Symbol>,
) -> Result<BytesN<32>, Error> {
    let Some(Executable::Wasm(module)) = env.current_contract_address().executable() else {
        return Err(Error::InvalidState);
    };
    Ok(standard_prefix_digest(
        env,
        &Symbol::new(env, P::KIND),
        &module,
        asset,
        rules,
    ))
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
    P::validate(env, &config.rules, &config.grant)?;
    if P::STANDARD_PREFIX
        && config.source_digest != checked_prefix::<P>(env, &config.asset, &config.rules)?
    {
        return Err(Error::InvalidState);
    }
    if config.x402_enabled {
        public_key(env, &config.agent)?;
        public_key(env, &config.server)?;
    }
    Ok(())
}
fn schema_digest(env: &Env, descriptor: &[u8]) -> BytesN<32> {
    env.crypto()
        .sha256(&Bytes::from_slice(env, descriptor))
        .to_bytes()
}
fn binding_for<P: Policy>(
    env: &Env,
    state: &State,
    digest: BytesN<32>,
) -> Result<PolicyBinding, Error> {
    if !P::admits_schema(env, &digest) {
        return Err(Error::UnsupportedOperation);
    }
    let Some(Executable::Wasm(module_digest)) = env.current_contract_address().executable() else {
        return Err(Error::InvalidState);
    };
    if P::source_digest(env).is_some_and(|digest| digest != state.source_digest) {
        return Err(Error::InvalidState);
    }
    if P::STANDARD_PREFIX
        && state.source_digest != checked_prefix::<P>(env, &state.asset, &state.rules)?
    {
        return Err(Error::InvalidState);
    }
    Ok(PolicyBinding {
        engine_kind: Symbol::new(env, P::KIND),
        contract_version: CONTRACT_VERSION,
        policy_instance: state.policy_instance.clone(),
        module_digest,
        source_digest: state.source_digest.clone(),
        argument_schema_digest: digest,
        entrypoint: Symbol::new(env, "_execute"),
    })
}
fn binding<P: Policy>(env: &Env, state: &State) -> Result<PolicyBinding, Error> {
    binding_for::<P>(env, state, P::argument_schema_digest(env))
}

/// Private native adapter dispatch. No opaque method, target or authorization tree is accepted.
enum NativeOperation {
    Transfer(Sep41TransferArgs),
    Deposit(Sep56DepositArgs),
}
impl NativeOperation {
    fn transfer(&self, asset: &Address) -> Sep41TransferArgs {
        match self {
            Self::Transfer(args) => args.clone(),
            Self::Deposit(args) => Sep41TransferArgs {
                token: asset.clone(),
                from: args.from.clone(),
                to: args.vault.clone(),
                amount: args.assets,
            },
        }
    }
    fn name(&self, env: &Env) -> String {
        String::from_str(
            env,
            match self {
                Self::Transfer(_) => "stellar::sep41_transfer",
                Self::Deposit(_) => "stellar::sep56_deposit",
            },
        )
    }
}
fn decode_operation(
    env: &Env,
    execution: &ExecutionRequest,
    state: &State,
) -> Result<NativeOperation, Error> {
    let invocation = &execution.invocation;
    if invocation.arguments.len() > MAX_ARGUMENT_BYTES {
        return Err(Error::InvalidInvocation);
    }
    if invocation.argument_schema_digest == schema_digest(env, ARGUMENT_SCHEMA_DESCRIPTOR) {
        let args = Sep41TransferArgs::from_xdr(env, &invocation.arguments)
            .map_err(|_| Error::InvalidInvocation)?;
        if args.clone().to_xdr(env) != invocation.arguments
            || args.token != state.asset
            || args.from != env.current_contract_address()
        {
            return Err(Error::InvalidInvocation);
        }
        return Ok(NativeOperation::Transfer(args));
    }
    if invocation.argument_schema_digest != schema_digest(env, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR) {
        return Err(Error::UnsupportedOperation);
    }
    let args = Sep56DepositArgs::from_xdr(env, &invocation.arguments)
        .map_err(|_| Error::InvalidInvocation)?;
    let wallet = env.current_contract_address();
    if args.clone().to_xdr(env) != invocation.arguments
        || args.from != wallet
        || args.receiver != wallet
        || args.operator != wallet
        || args.vault == wallet
        || args.vault == state.asset
    {
        return Err(Error::InvalidInvocation);
    }
    if args.assets <= 0 || args.min_shares <= 0 {
        return Err(Error::InvalidAmount);
    }
    Ok(NativeOperation::Deposit(args))
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
fn decode_expense(env: &Env, raw: Option<&Bytes>) -> Result<Option<ExpenseBounds>, Error> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.len() > MAX_EXPENSE_BYTES {
        return Err(Error::InvalidInvocation);
    }
    let value = ExpenseBounds::from_xdr(env, raw).map_err(|_| Error::InvalidInvocation)?;
    if value.clone().to_xdr(env) != *raw {
        return Err(Error::InvalidInvocation);
    }
    Ok(Some(value))
}
/// Check denomination, operation class and conservative signed cost identities. External facts remain server-attested.
fn validate_expense(
    env: &Env,
    state: &State,
    execution: &ExecutionRequest,
    operation: &NativeOperation,
) -> Result<(), Error> {
    let Some(expense) = decode_expense(env, execution.expense.as_ref())? else {
        return Ok(());
    };
    if expense.asset != state.asset
        || expense.decimals != 7
        || expense.gas_units < 0
        || expense.conversion_units < 0
        || expense.spent_units < 0
        || expense.observed_ledger == 0
        || expense.observed_ledger > env.ledger().sequence()
        || expense.day != env.ledger().timestamp() / 86_400
    {
        return Err(Error::InvalidInvocation);
    }
    let native_asset = env
        .deployer()
        .with_stellar_asset(Bytes::from_array(env, &[0; 4]))
        .deployed_address();
    // Both authenticated actors attest normalized gas for non-XLM accounting assets.
    // The kernel cannot verify a cross-asset price. XLM remains exact stroop identity.
    if (expense.max_fee_stroops == 0 && expense.gas_units != 0)
        || (expense.max_fee_stroops > 0 && expense.gas_units <= 0)
        || (state.asset == native_asset && expense.gas_units != i128::from(expense.max_fee_stroops))
    {
        return Err(Error::InvalidInvocation);
    }
    let principal = match operation {
        NativeOperation::Transfer(args) => {
            if expense.conversion_units != 0 {
                return Err(Error::InvalidInvocation);
            }
            args.amount
        }
        NativeOperation::Deposit(args) => {
            if expense.conversion_units > args.assets {
                return Err(Error::InvalidInvocation);
            }
            expense.conversion_units
        }
    };
    if expense.spent_units
        != principal
            .checked_add(expense.gas_units)
            .ok_or(Error::Overflow)?
    {
        return Err(Error::InvalidInvocation);
    }
    Ok(())
}

fn deposit_tokens(
    env: &Env,
    asset: &Address,
    args: &Sep56DepositArgs,
    expense: Option<&ExpenseBounds>,
) -> Result<i128, Error> {
    use soroban_sdk::IntoVal;
    let underlying: Address =
        env.invoke_contract(&args.vault, &Symbol::new(env, "query_asset"), Vec::new(env));
    if underlying != *asset {
        return Err(Error::UnsupportedAsset);
    }
    let wallet = env.current_contract_address();
    let asset_client = token::Client::new(env, asset);
    let shares_client = token::Client::new(env, &args.vault);
    let before_assets = asset_client.balance(&wallet);
    let before_shares = shares_client.balance(&wallet);
    if before_assets < args.assets {
        return Err(Error::InsufficientFunds);
    }
    if before_shares < 0 {
        return Err(Error::InvalidEffects);
    }
    // The direct vault call is authorized by this invoking contract. Only this exact deeper transfer is delegated.
    env.authorize_as_current_contract(soroban_sdk::vec![
        env,
        InvokerContractAuthEntry::Contract(SubContractInvocation {
            context: ContractContext {
                contract: asset.clone(),
                fn_name: Symbol::new(env, "transfer"),
                args: (wallet.clone(), args.vault.clone(), args.assets).into_val(env),
            },
            sub_invocations: Vec::new(env),
        })
    ]);
    let shares: i128 = env.invoke_contract(
        &args.vault,
        &Symbol::new(env, "deposit"),
        (
            args.assets,
            args.receiver.clone(),
            args.from.clone(),
            args.operator.clone(),
        )
            .into_val(env),
    );
    if let Some(expense) = expense {
        // The selected vault supplies this valuation. It is not a proof of future redemption or economic honesty.
        let redeemable: i128 = env.invoke_contract(
            &args.vault,
            &Symbol::new(env, "preview_redeem"),
            (shares,).into_val(env),
        );
        if redeemable < 0 || args.assets - args.assets.min(redeemable) > expense.conversion_units {
            return Err(Error::InvalidEffects);
        }
    }
    // Finish foreign metadata reads before measuring final effects. A vault getter is not trusted to be pure.
    let after_asset: Address =
        env.invoke_contract(&args.vault, &Symbol::new(env, "query_asset"), Vec::new(env));
    if after_asset != *asset {
        return Err(Error::InvalidEffects);
    }
    let expected_assets = before_assets
        .checked_sub(args.assets)
        .ok_or(Error::Overflow)?;
    let expected_shares = before_shares.checked_add(shares).ok_or(Error::Overflow)?;
    let after_shares = shares_client.balance(&wallet);
    // The immutable SAC read is last: no untrusted vault code runs after these final observations.
    let after_assets = asset_client.balance(&wallet);
    if shares < args.min_shares
        || shares <= 0
        || after_assets != expected_assets
        || after_shares != expected_shares
    {
        return Err(Error::InvalidEffects);
    }
    Ok(shares)
}
fn next_history(
    env: &Env,
    prior: &AccountingHistory,
    execution: &ExecutionRequest,
    amount: i128,
    now: u64,
) -> Result<AccountingHistory, Error> {
    let day = now / 86_400;
    if prior.day > day || prior.spent < 0 || prior.day_spent < 0 || prior.day_total < 0 {
        return Err(Error::InvalidState);
    }
    let mut next = prior.clone();
    if next.day != day {
        next.day = day;
        next.day_spent = 0;
        next.day_total = 0;
        next.day_unpriced = false;
    }
    next.calls = next.calls.checked_add(1).ok_or(Error::Overflow)?;
    next.day_total = next.day_total.checked_add(amount).ok_or(Error::Overflow)?;
    if let Some(expense) = decode_expense(env, execution.expense.as_ref())? {
        next.spent = next
            .spent
            .checked_add(expense.spent_units)
            .ok_or(Error::Overflow)?;
        next.day_spent = next
            .day_spent
            .checked_add(expense.spent_units)
            .ok_or(Error::Overflow)?;
        next.day_total = next
            .day_total
            .checked_add(expense.gas_units)
            .ok_or(Error::Overflow)?;
    } else {
        next.unpriced = true;
        next.day_unpriced = true;
    }
    Ok(next)
}
fn admit<P: Policy>(
    env: &Env,
    execution: ExecutionRequest,
    mut state: State,
    operation: &NativeOperation,
) -> Result<TransferReceipt, Error> {
    let installed = binding_for::<P>(
        env,
        &state,
        execution.invocation.argument_schema_digest.clone(),
    )?;
    let invocation = &execution.invocation;
    if execution.policy_instance != installed.policy_instance
        || execution.source_hash == BytesN::from_array(env, &[0; 32])
        || (!P::STANDARD_PREFIX && execution.source_hash != installed.source_digest)
        || execution.operation_id == BytesN::from_array(env, &[0; 32])
        || invocation.module_digest != installed.module_digest
        || invocation.entrypoint != installed.entrypoint
        || invocation.argument_schema_digest != installed.argument_schema_digest
        || invocation.arguments.len() > MAX_ARGUMENT_BYTES
    {
        return Err(Error::InvalidInvocation);
    }
    let args = operation.transfer(&state.asset);
    let operation_name = operation.name(env);
    let replay_key = Key::Operation(execution.operation_id.clone());
    if env.storage().persistent().has(&replay_key) {
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
    validate_expense(env, &state, &execution, operation)?;
    let nonce = state.nonce.checked_add(1).ok_or(Error::Overflow)?;
    let history = next_history(env, &state.history, &execution, args.amount, now)?;
    let request = EngineRequest {
        history: history.clone(),
        wallet: args.from.clone(),
        agent: state.agent.clone(),
        asset: state.asset.clone(),
        token: state.token.clone(),
        decimals: 7,
        recipient: args.to.clone(),
        amount: args.amount,
        operation_id: execution.operation_id.clone(),
        expense: execution.expense.clone(),
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
    let final_spent = P::check_operation(
        env,
        request,
        EngineState {
            grant: state.grant.clone(),
            spent: initial.clone().unwrap_or_else(|| Spent::new(env)),
        },
        &state.rules,
        &operation_name,
    )?;
    if !named_values_valid(env, &final_spent) {
        return Err(Error::InvalidState);
    }
    storage.commit(&initial, &final_spent);
    state.nonce = nonce;
    state.history = history;
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
    Ok(persistent::load(env, &replay_key, Some(&receipt)).unwrap())
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
            history: AccountingHistory::default(),
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
/// Return a native operation binding only when the installed policy admits that exact profile.
pub fn policy_binding_for<P: Policy>(
    env: &Env,
    argument_schema_digest: BytesN<32>,
) -> Result<PolicyBinding, Error> {
    binding_for::<P>(env, &load(env, None)?, argument_schema_digest)
}
/// Read the atomically retained actual share credit for a successful deposit operation.
pub fn deposit_receipt(
    env: &Env,
    operation_id: BytesN<32>,
) -> Result<Option<Sep56DepositReceipt>, Error> {
    load(env, None)?;
    Ok(persistent::load(env, &Key::Deposit(operation_id), None))
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
    let operation = decode_operation(env, &execution, &state)?;
    let expense = decode_expense(env, execution.expense.as_ref())?;
    let receipt = admit::<P>(env, execution, state, &operation)?;
    match operation {
        NativeOperation::Transfer(_) => {
            move_tokens(env, &receipt.token, &receipt.to, receipt.amount)?
        }
        NativeOperation::Deposit(args) => {
            let shares = deposit_tokens(env, &receipt.token, &args, expense.as_ref())?;
            let deposited = Sep56DepositReceipt {
                operation_id: receipt.operation_id.clone(),
                vault: args.vault,
                asset: receipt.token.clone(),
                from: args.from,
                receiver: args.receiver,
                operator: args.operator,
                assets: args.assets,
                shares,
                nonce: receipt.nonce,
                deployment_version: receipt.deployment_version,
            };
            persistent::load(
                env,
                &Key::Deposit(receipt.operation_id.clone()),
                Some(&deposited),
            );
            Sep56DepositEvent {
                operation_id: receipt.operation_id.clone(),
                vault: deposited.vault,
                assets: deposited.assets,
                shares: deposited.shares,
            }
            .publish(env);
        }
    }
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
    let operation = NativeOperation::Transfer(args);
    admit::<P>(env, authorization.execution, state, &operation)?;
    Ok(())
}

/// Fixed minimal policy: server approval is mandatory, with no onchain business predicates.
pub struct Simple;
impl Policy for Simple {
    const KIND: &'static str = "simple_policy_engine";
    const STANDARD_PREFIX: bool = true;
    fn admits_schema(env: &Env, digest: &BytesN<32>) -> bool {
        *digest == schema_digest(env, ARGUMENT_SCHEMA_DESCRIPTOR)
            || *digest == schema_digest(env, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR)
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
    const STANDARD_PREFIX: bool = true;
    fn admits_schema(env: &Env, digest: &BytesN<32>) -> bool {
        *digest == schema_digest(env, ARGUMENT_SCHEMA_DESCRIPTOR)
            || *digest == schema_digest(env, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR)
    }
    fn validate(env: &Env, rules: &Vec<Symbol>, grant: &Grant) -> Result<(), Error> {
        for rule in rules.iter() {
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
            let name = if rule == Symbol::new(env, "transaction_cap") {
                "transaction_cap"
            } else if rule == Symbol::new(env, "spent_cap") {
                "spent_cap"
            } else if rule == Symbol::new(env, "day_spent_cap") {
                "day_spent_cap"
            } else if rule == Symbol::new(env, "day_total_cap") {
                "day_total_cap"
            } else if rule == Symbol::new(env, "call_cap") {
                "call_cap"
            } else if rule == Symbol::new(env, "recipients") {
                "recipients"
            } else if rule == Symbol::new(env, "expiry") {
                "expiry"
            } else if rule == Symbol::new(env, "tokens") {
                "tokens"
            } else {
                return Err(Error::InvalidGrant);
            };
            let result =
                allowit_policy_rules::check(env, request.clone(), state, name, Vec::new(env))
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
    context_for_operation(
        request,
        &String::from_str(&request.wallet.env(), "stellar::sep41_transfer"),
    )
}
pub fn context_for_operation(request: &EngineRequest, operation: &String) -> PolicyContext {
    PolicyContext {
        operation: operation.clone(),
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
            pub fn policy_binding_for(
                env: soroban_sdk::Env,
                argument_schema_digest: soroban_sdk::BytesN<32>,
            ) -> Result<allowit_wallet_protocol::PolicyBinding, $crate::Error> {
                $crate::policy_binding_for::<$policy>(&env, argument_schema_digest)
            }
            pub fn deposit_receipt(
                env: soroban_sdk::Env,
                operation_id: soroban_sdk::BytesN<32>,
            ) -> Result<Option<allowit_wallet_protocol::Sep56DepositReceipt>, $crate::Error> {
                $crate::deposit_receipt(&env, operation_id)
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

#[cfg(test)]
mod sep56_tests;
