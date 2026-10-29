#![no_std]
use soroban_sdk::{Address, Bytes, BytesN, Env, String, Symbol, Vec, contractclient, contracttype};

pub const MAX_RECIPIENTS: u32 = 16;
/// Native transfer-profile argument encoding, fixed independently of policy source.
pub const ARGUMENT_SCHEMA_DESCRIPTOR: &[u8] = b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)";
pub const MAX_ARGUMENT_BYTES: u32 = 1024;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    /// Installed SAC address. The wallet admits only native StellarAsset implementations with seven decimal places.
    pub asset: Address,
    /// Distinct permitted destination addresses, at most MAX_RECIPIENTS. The wallet itself is not a valid destination.
    pub recipients: Vec<Address>,
    /// Positive maximum delegated transfer amount in the installed asset's native i128 base units.
    pub per_transfer: i128,
    /// Positive maximum delegated spending per UTC day in native asset base units.
    pub daily_limit: i128,
    /// Positive maximum cumulative delegated spending in native asset base units; additional funding does not reset consumption.
    pub total_limit: i128,
    /// Positive maximum successful delegated transfer count over the grant's lifetime.
    pub max_calls: u64,
    /// Exclusive Unix timestamp expiry in ledger seconds. A request cannot outlive its grant.
    pub expires_at: u64,
}

/// Internal normalized transfer passed to the veto engine. It is not a public wallet entrypoint.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRequest {
    /// Exact intended destination, checked against local permissions and the actual transfer arguments.
    pub recipient: Address,
    /// Positive exact transfer amount in the installed asset's native i128 base units.
    pub amount: i128,
    /// Strict next execution sequence shared by delegated spending paths. It is distinct from the native authorization nonce.
    pub nonce: u64,
    /// Active ordered owner configuration version supplied by the custody wallet. It is not engine_version.
    pub deployment_version: u64,
    /// Exclusive Unix timestamp expiry in ledger seconds. A request cannot outlive its grant.
    pub expires_at: u64,
}

/// Exact arguments of the admitted stellar::sep41_transfer operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sep41TransferArgs {
    /// Exact installed SAC address, distinct from the human-readable asset label.
    pub token: Address,
    /// Exact token source address; delegated spending requires the current wallet address.
    pub from: Address,
    /// Exact token destination, bound to the approved recipient.
    pub to: Address,
    /// Positive exact transfer amount in the installed asset's native i128 base units.
    pub amount: i128,
}

/// The native profile of the canonical signed module-selection record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyInvocation {
    /// Actual wallet Wasm SHA-256 identity. It differs from both release metadata and the authored-source digest.
    pub module_digest: BytesN<32>,
    /// Private compiled policy entrypoint selector. Only the installed selector is admitted.
    pub entrypoint: Symbol,
    /// SHA-256 of the admitted native argument schema. Unknown schemas reject.
    pub argument_schema_digest: BytesN<32>,
    /// Canonical bounded XDR of the admitted transfer arguments; alternative encodings and extra data reject.
    pub arguments: Bytes,
}

/// The SDK maps OperationRef.policy_instance and OperationRef.nonce without changing them.
/// The monotonic execution nonce and deployment version come from authenticated custody state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRequest {
    /// Stable nonzero logical policy identifier. Upgrades and configuration changes preserve this identity.
    pub policy_instance: BytesN<32>,
    /// Nonzero logical operation identifier consumed once with successful effects; replacement preparations retain it.
    pub operation_id: BytesN<32>,
    /// Strict next execution sequence shared by delegated spending paths. It is distinct from the native authorization nonce.
    pub nonce: u64,
    /// Active owner configuration counter. Executions use the current value; configuration changes target exactly the next value.
    pub deployment_version: u64,
    /// Exclusive Unix timestamp expiry in ledger seconds. A request cannot outlive its grant.
    pub expires_at: u64,
    /// Installed module selection and exact canonical arguments, bound before compiled policy execution.
    pub invocation: PolicyInvocation,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyBinding {
    /// Compiled kernel release metadata. Exact executable identity remains module_digest.
    pub contract_version: u32,
    /// Stable nonzero logical policy identifier. Upgrades and configuration changes preserve this identity.
    pub policy_instance: BytesN<32>,
    /// Actual wallet Wasm SHA-256 identity. It differs from both release metadata and the authored-source digest.
    pub module_digest: BytesN<32>,
    /// SHA-256 of the complete authored policy source compiled into this kernel.
    pub source_digest: BytesN<32>,
    /// SHA-256 of the admitted native argument schema. Unknown schemas reject.
    pub argument_schema_digest: BytesN<32>,
    /// Private compiled policy entrypoint selector. Only the installed selector is admitted.
    pub entrypoint: Symbol,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferReceipt {
    /// Nonzero logical operation identifier consumed once with successful effects; replacement preparations retain it.
    pub operation_id: BytesN<32>,
    /// Exact installed SAC address, distinct from the human-readable asset label.
    pub token: Address,
    /// Exact token source address; delegated spending requires the current wallet address.
    pub from: Address,
    /// Exact token destination, bound to the approved recipient.
    pub to: Address,
    /// Positive exact transfer amount in the installed asset's native i128 base units.
    pub amount: i128,
    /// Execution sequence consumed by this transfer. It is distinct from the native authorization nonce.
    pub nonce: u64,
    /// Owner configuration version used to authorize this transfer.
    pub deployment_version: u64,
}

/// Authenticated observations consumed by statically compiled owner policy.
/// Amounts and counters use the admitted SAC's exact native units.
#[derive(Clone)]
pub struct PolicyContext {
    /// Installed SAC address. The wallet admits only native StellarAsset implementations with seven decimal places.
    pub asset: Address,
    /// Exact intended destination, checked against local permissions and the actual transfer arguments.
    pub recipient: Address,
    /// Authenticated installed asset label, cached outside the active SAC call to avoid authorization reentry.
    pub token: String,
    /// Authenticated installed asset decimal scale. This wallet profile fixes it at seven.
    pub decimals: u32,
    /// Positive exact transfer amount in the installed asset's native i128 base units.
    pub amount: i128,
    /// Successful delegated spending in native asset base units for spent_day; owner funding does not reset it.
    pub spent_daily: i128,
    /// Cumulative successful delegated spending in native asset base units; configuration changes preserve it.
    pub spent_total: i128,
    /// Number of successful delegated transfers, shared across execute and x402 and bounded by max_calls.
    pub calls: u64,
    /// Authenticated ledger close timestamp in Unix seconds, never a caller-provided clock.
    pub now: u64,
    /// UTC day number, floor of the ledger timestamp divided by 86400, for spent_daily.
    pub spent_day: u64,
}

/// Observations are supplied by custody. This record alone grants no authority.
/// Custody normalizes spent_daily to the current UTC day before evaluation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineContext {
    /// Custody wallet address supplying these observations. This record alone grants no spending authority.
    pub wallet: Address,
    /// Configured delegated executor address. The x402 path derives its signing key from an enabled G-address agent.
    pub agent: Address,
    /// Installed SAC address. The wallet admits only native StellarAsset implementations with seven decimal places.
    pub asset: Address,
    /// Exact normalized transfer supplied to the shared veto engine; it grants no independent custody authority.
    pub request: TransferRequest,
    /// Local spending permissions and independent ceilings, enforced even when the shared engine approves.
    pub grant: Grant,
    /// Successful delegated spending in native asset base units for spent_day; owner funding does not reset it.
    pub spent_daily: i128,
    /// Cumulative successful delegated spending in native asset base units; configuration changes preserve it.
    pub spent_total: i128,
    /// Number of successful delegated transfers, shared across execute and x402 and bounded by max_calls.
    pub calls: u64,
    /// Authenticated ledger close timestamp in Unix seconds, never a caller-provided clock.
    pub now: u64,
}

#[contractclient(name = "EngineClient")]
pub trait EngineInterface {
    /// Evaluate a custody proposal without granting token authority.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment, omitted from serialized arguments.
    /// - `context`: Custody-supplied transfer, local grant, counters and ledger time.
    ///
    /// # Returns
    /// Returns the additional engine decision. The wallet retains all local checks.
    fn evaluate(env: Env, context: EngineContext) -> bool;
}
