#![no_std]
//! Owner-controlled custody mixins shared by fixed and bespoke policy wallets.
use allowit::{AllowitEnv, Operation, Request, Rule};
use allowit_wallet_protocol::{
    ARGUMENT_SCHEMA_DESCRIPTOR, AccountingHistory, ExecutionRequest, ExpenseBounds, Grant,
    MAX_ARGUMENT_BYTES, MAX_EXPENSE_BYTES, PolicyBinding, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR,
    Sep41TransferArgs, Sep56DepositArgs, Sep56DepositEvent, Sep56DepositReceipt, TransferReceipt,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Executable, IntoVal, Map, String, Symbol, TryFromVal, Val, Vec,
    auth::{Context, ContractContext, InvokerContractAuthEntry, SubContractInvocation},
    contracterror, contracttype,
    crypto::Hash,
    token,
    xdr::{FromXdr, ToXdr},
};
mod persistent;
const STATE_KEY: u32 = 0;
/// Version 2: typed Grant and `Vec<Rule>` prefix. Version 1 stored an untyped Grant map.
pub const CONTRACT_VERSION: u32 = 2;

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
    /// Ordered owner-approved standard prefix. Simple and Custom use an empty list.
    pub rules: Vec<Rule>,
    pub grant: Grant,
    pub x402_enabled: bool,
}

/// Complete owner update. It preserves asset, logical identity, nonce, pause and history.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDeployment {
    pub deployment_version: u64,
    pub owner: Address,
    pub agent: Address,
    pub server: Address,
    /// Fixed standard prefix digest; Custom uses its complete compiled source digest.
    pub source_digest: BytesN<32>,
    pub rules: Vec<Rule>,
    pub grant: Grant,
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
    pub rules: Vec<Rule>,
    pub grant: Grant,
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
    Overflow = 11,
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
    /// Check the owner-approved standard prefix. Only Common admits a nonempty list.
    fn validate(_env: &Env, rules: &Vec<Rule>) -> Result<(), Error> {
        if rules.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidGrant)
        }
    }
    /// Evaluate the compiled checks on the kernel-built rule input. Pass values are discarded.
    fn check(env: &Env, ctx: &AllowitEnv, rules: &Vec<Rule>) -> Result<(), Error>;
}

/// Read initialized state and maintain its instance and code lifetime. Constructor initialization is explicit.
fn load(env: &Env, initial: Option<State>) -> Result<State, Error> {
    if let Some(state) = initial {
        store(env, &state);
    }
    let raw = stored(env)?;
    let state = State::try_from_val(env, &raw).map_err(|_| Error::InvalidState)?;
    // Struct decoding ignores extra keys and reads absent Option keys as None. Only the exact
    // canonical encoding of this layout is accepted, including nested Grant and history.
    if state.contract_version != CONTRACT_VERSION || state.clone().to_xdr(env) != raw.to_xdr(env) {
        return Err(Error::InvalidState);
    }
    extend(env);
    Ok(state)
}
fn extend(env: &Env) {
    let ttl = env.storage().max_ttl();
    env.deployer()
        .extend_ttl(env.current_contract_address(), ttl / 2, ttl);
}
fn store(env: &Env, state: &State) {
    env.storage().instance().set(&STATE_KEY, state);
}
/// Stored fields that owner entrypoints keep. Struct decoding ignores the other State keys, so
/// a stored Grant or rule list that no longer decodes never blocks recovery, passthrough or its
/// replacement by an owner packet. Version 1 differs from version 2 only in Grant and rules.
/// Protected history is read separately, only where it is carried over.
#[contracttype]
struct KeptState {
    contract_version: u32,
    owner: Address,
    asset: Address,
    policy_instance: BytesN<32>,
    token: String,
    deployment_version: u64,
    nonce: u64,
    paused: bool,
}
/// Read the kept fields. Callers require the owner's authorization.
fn kept(env: &Env) -> Result<KeptState, Error> {
    let kept = KeptState::try_from_val(env, &stored(env)?).map_err(|_| Error::InvalidState)?;
    // A later layout may change the meaning of kept fields.
    if kept.contract_version == 0 || kept.contract_version > CONTRACT_VERSION {
        return Err(Error::InvalidState);
    }
    extend(env);
    Ok(kept)
}
/// Protected history carried into a new State. Struct decoding ignores extra keys, so only its
/// exact canonical encoding is accepted.
fn kept_history(env: &Env) -> Result<AccountingHistory, Error> {
    let fields =
        Map::<Symbol, Val>::try_from_val(env, &stored(env)?).map_err(|_| Error::InvalidState)?;
    let raw = fields
        .get(Symbol::new(env, "history"))
        .ok_or(Error::InvalidState)?;
    let history = AccountingHistory::try_from_val(env, &raw).map_err(|_| Error::InvalidState)?;
    if history.clone().to_xdr(env) != raw.to_xdr(env) {
        return Err(Error::InvalidState);
    }
    Ok(history)
}
fn stored(env: &Env) -> Result<Val, Error> {
    env.storage()
        .instance()
        .get(&STATE_KEY)
        .ok_or(Error::InvalidState)
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
    rules: &Vec<Rule>,
) -> BytesN<32> {
    env.crypto()
        .sha256(
            &(
                Symbol::new(env, "allowit_std_prefix"),
                kind.clone(),
                module.clone(),
                asset.clone(),
                schema_digest(env, ARGUMENT_SCHEMA_DESCRIPTOR),
                schema_digest(env, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR),
                rules.clone(),
            )
                .to_xdr(env),
        )
        .to_bytes()
}
fn checked_prefix<P: Policy>(
    env: &Env,
    asset: &Address,
    rules: &Vec<Rule>,
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
    config.grant.validate().map_err(|_| Error::InvalidGrant)?;
    decoded(&config.rules)?;
    let lists = [&config.grant.recipients, &config.grant.tokens];
    for list in lists.into_iter().flatten() {
        decoded(list)?;
    }
    P::validate(env, &config.rules)?;
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
/// Soroban decodes vector elements when read. Owner configuration decodes each one before storing
/// it, so an element that later fails to decode cannot be stored. An unknown Rule symbol aborts.
fn decoded<T: IntoVal<Env, Val> + TryFromVal<Env, Val>>(list: &Vec<T>) -> Result<(), Error> {
    for i in 0..list.len() {
        list.try_get(i).map_err(|_| Error::InvalidGrant)?;
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
        entrypoint: Symbol::new(env, "execute"),
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
    fn kind(&self) -> Operation {
        match self {
            Self::Transfer(_) => Operation::sep41_transfer,
            Self::Deposit(_) => Operation::sep56_deposit,
        }
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
fn issuer_destination(
    env: &Env,
    token: &String,
    asset: &Address,
    to: &Address,
) -> Result<bool, Error> {
    let len = token.len() as usize;
    if len == 0 || len > 48 {
        return Err(Error::InvalidState);
    }
    let mut encoded = [0u8; 48];
    token.copy_into_slice(&mut encoded[..len]);
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
    let mut preimage = Bytes::from_array(env, &kind.to_be_bytes());
    preimage.append(&Bytes::from_slice(env, &code[..width]));
    preimage.append(&Bytes::from_array(env, &[0; 4]));
    preimage.append(&issuer.into());
    Ok(env
        .deployer()
        .with_stellar_asset(preimage)
        .deployed_address()
        == *asset)
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
/// Rule input: owner Grant, proposed protected history and authenticated request facts.
/// Deposits name their vault as the recipient.
fn rule_input(
    state: &State,
    history: &AccountingHistory,
    operation: Operation,
    args: &Sep41TransferArgs,
    now: u64,
    expires_at: u64,
) -> AllowitEnv {
    AllowitEnv {
        grant: state.grant.clone(),
        state: history.clone(),
        request: Request {
            operation,
            asset: state.asset.clone(),
            recipient: args.to.clone(),
            amount: args.amount,
            now,
            expires_at,
        },
    }
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
    if args.to == env.current_contract_address()
        || issuer_destination(env, &state.token, &state.asset, &args.to)?
    {
        return Err(Error::InvalidRecipient);
    }
    validate_expense(env, &state, &execution, operation)?;
    let nonce = state.nonce.checked_add(1).ok_or(Error::Overflow)?;
    let history = next_history(env, &state.history, &execution, args.amount, now)?;
    P::validate(env, &state.rules)?;
    let ctx = rule_input(
        &state,
        &history,
        operation.kind(),
        &args,
        now,
        execution.expires_at,
    );
    P::check(env, &ctx, &state.rules)?;
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
    // Decoding ignores extra keys and reads absent Option keys as None. The owner signs the
    // canonical encoding of the decoded packet, so a packet whose meaning differs fails auth.
    config
        .owner
        .require_auth_for_args((config.clone(),).into_val(env));
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
    let kept = kept(env)?;
    // The current and any new owner sign the canonical encoding of the decoded packet.
    let signed: Vec<Val> = (deployment.clone(),).into_val(env);
    kept.owner.require_auth_for_args(signed.clone());
    if kept
        .deployment_version
        .checked_add(1)
        .ok_or(Error::Overflow)?
        != deployment.deployment_version
    {
        return Err(Error::StaleRequest);
    }
    let history = kept_history(env)?;
    let config = PolicyConfig {
        owner: deployment.owner,
        agent: deployment.agent,
        server: deployment.server,
        asset: kept.asset,
        policy_instance: kept.policy_instance,
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
    if config.owner != kept.owner {
        config.owner.require_auth_for_args(signed);
    }
    // Kept fields carry over. The packet replaces the rest and writes the current layout.
    store(
        env,
        &State {
            history,
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
            token: kept.token,
            deployment_version: deployment.deployment_version,
            nonce: kept.nonce,
            paused: kept.paused,
        },
    );
    if let Some(hash) = deployment.wasm_hash {
        env.deployer()
            .update_current_contract(soroban_sdk::ContractExecutable::Wasm(hash));
    }
    Ok(())
}
struct UpgradeConfig;
impl Policy for UpgradeConfig {
    const KIND: &'static str = "upgrade";
    fn validate(_env: &Env, _rules: &Vec<Rule>) -> Result<(), Error> {
        Ok(())
    }
    fn check(_env: &Env, _ctx: &AllowitEnv, _rules: &Vec<Rule>) -> Result<(), Error> {
        Err(Error::PolicyDenied)
    }
}
pub fn set_pause(env: &Env, paused: bool, deployment_version: u64) -> Result<(), Error> {
    let mut state = load(env, None)?;
    state.owner.require_auth();
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
    let kept = kept(env)?;
    kept.owner.require_auth();
    if amount <= 0 {
        return Err(Error::InvalidAmount);
    }
    if recipient == env.current_contract_address()
        || issuer_destination(env, &kept.token, &kept.asset, &recipient)?
    {
        return Err(Error::InvalidRecipient);
    }
    move_tokens(env, &kept.asset, &recipient, amount)
}
/// Owner-signed passthrough. Native authorization binds target, arguments and every nested scope.
pub fn invoke(
    env: &Env,
    contract: Address,
    function: Symbol,
    args: Vec<Val>,
    auth: Vec<InvokerContractAuthEntry>,
) -> Result<Val, Error> {
    kept(env)?.owner.require_auth();
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
    // The same canonical transfer-profile decoding as execute. A deposit profile rejects here.
    let operation = decode_operation(env, &authorization.execution, &state)?;
    let NativeOperation::Transfer(args) = &operation else {
        return Err(Error::UnsupportedOperation);
    };
    if from != env.current_contract_address() || args.to != to || args.amount != amount {
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
    fn check(_env: &Env, _ctx: &AllowitEnv, _rules: &Vec<Rule>) -> Result<(), Error> {
        Ok(())
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
    /// Any ordered list of typed rules. The kernel decodes each element before storing it.
    fn validate(_env: &Env, _rules: &Vec<Rule>) -> Result<(), Error> {
        Ok(())
    }
    /// Run each prefix call `allowit::<rule>(ctx, &ctx.grant.<rule>)?;` in owner order.
    /// An unset Grant field skips its rule here only; the full offchain policy denies it.
    fn check(_env: &Env, ctx: &AllowitEnv, rules: &Vec<Rule>) -> Result<(), Error> {
        for rule in rules.iter() {
            allowit::preflight(ctx, rule)?;
        }
        Ok(())
    }
}
/// Rule denials collapse to PolicyDenied. Invalid owner configuration and accounting stay distinct.
impl From<allowit::Error> for Error {
    fn from(error: allowit::Error) -> Self {
        match error {
            allowit::Error::MissingGrant | allowit::Error::InvalidParameter => Error::InvalidGrant,
            allowit::Error::InvalidState => Error::InvalidState,
            _ => Error::PolicyDenied,
        }
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
