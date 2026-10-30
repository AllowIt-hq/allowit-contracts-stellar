#![no_std]
use allowit::{AllowitEnv, Error};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Symbol, contractclient, contractevent, contracttype,
};

/// Typed owner Grant and the protected accounting that rules read.
pub use allowit::{AccountingHistory, Grant};

/// Native transfer-profile argument encoding, fixed independently of policy source.
pub const ARGUMENT_SCHEMA_DESCRIPTOR: &[u8] = b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)";
/// Exact SEP-56 deposit encoding. The vault is also its SEP-41 share-token contract.
pub const SEP56_DEPOSIT_SCHEMA_DESCRIPTOR: &[u8] = b"allowit.stellar.sep56_deposit.v1:ScValMap(assets:i128,from:Address,min_shares:i128,operator:Address,receiver:Address,vault:Address)";
pub const MAX_ARGUMENT_BYTES: u32 = 1024;
pub const MAX_EXPENSE_BYTES: u32 = 1024;

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

/// Exact arguments of the admitted stellar::sep56_deposit operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sep56DepositArgs {
    /// Vault and share-token contract selected by the request and constrained by authored policy.
    pub vault: Address,
    /// Positive underlying SAC units supplied. The immutable wallet asset fixes their scale.
    pub assets: i128,
    /// Share receiver. Delegated deposits require the current wallet address.
    pub receiver: Address,
    /// Underlying source. Delegated deposits require the current wallet address.
    pub from: Address,
    /// Deposit operator. Delegated deposits require the current wallet address.
    pub operator: Address,
    /// Positive minimum minted share units in the vault share token's native scale.
    pub min_shares: i128,
}

/// Settled deposit effects, stored atomically with custody nonce and underlying transfer receipt.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sep56DepositReceipt {
    /// Single-use logical operation identifier retained across re-preparation.
    pub operation_id: BytesN<32>,
    /// Admitted vault, also the share-token contract.
    pub vault: Address,
    /// Immutable underlying SAC address.
    pub asset: Address,
    /// Underlying source, equal to this wallet.
    pub from: Address,
    /// Share receiver, equal to this wallet.
    pub receiver: Address,
    /// Authorized operator, equal to this wallet.
    pub operator: Address,
    /// Exact observed underlying debit in native units.
    pub assets: i128,
    /// Observed share credit, equal to returned minted units. External vault code defines share behavior.
    pub shares: i128,
    /// Consumed execution sequence, distinct from native authorization nonces.
    pub nonce: u64,
    /// Owner configuration sequence used for this deposit.
    pub deployment_version: u64,
}

/// Confirmed underlying-to-share exchange. The complete receipt remains available by operation identity.
#[contractevent(topics = ["sep56_deposit"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sep56DepositEvent {
    #[topic]
    pub operation_id: BytesN<32>,
    #[topic]
    pub vault: Address,
    pub assets: i128,
    pub shares: i128,
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
    /// Canonical bounded XDR of the selected native operation; alternative encodings and extra data reject.
    pub arguments: Bytes,
}

/// Request-bound conservative economic ceilings, approved by the configured server signer.
/// These are not a proof of final gas or external vault valuation. Amounts use the immutable underlying asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpenseBounds {
    /// Immutable underlying SAC denomination, distinct from the share token.
    pub asset: Address,
    /// Exact underlying scale. This native custody profile requires seven.
    pub decimals: u32,
    /// Conservative attributable gas ceiling in underlying units. Native XLM identity conversion is supported.
    pub gas_units: i128,
    /// Deposit fee/slippage ceiling in underlying units. Transfers require zero.
    pub conversion_units: i128,
    /// Full payment principal plus gas, or deposit conversion loss plus gas. The kernel checks the operation class.
    pub spent_units: i128,
    /// Signed outer transaction fee bound in stroops, checked by the SDK/server; the contract cannot observe final fees.
    pub max_fee_stroops: u32,
    /// Nonzero ledger at which the server observed the economic inputs. It cannot exceed execution ledger.
    pub observed_ledger: u32,
    /// UTC execution day (Unix seconds / 86400). Cross-day use rejects.
    pub day: u64,
}

/// The SDK maps OperationRef.policy_instance and OperationRef.nonce without changing them.
/// The monotonic execution nonce and deployment version come from authenticated custody state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRequest {
    /// Stable nonzero logical policy identifier. Upgrades and configuration changes preserve this identity.
    pub policy_instance: BytesN<32>,
    /// Exact full offchain source identity covered by agent/server authorization. Std binds its prefix separately.
    pub source_hash: BytesN<32>,
    /// Nonzero logical operation identifier consumed once with successful effects; replacement preparations retain it.
    pub operation_id: BytesN<32>,
    /// Strict next execution sequence shared by delegated spending paths. It is distinct from the native authorization nonce.
    pub nonce: u64,
    /// Active owner configuration counter. Executions use the current value; configuration changes target exactly the next value.
    pub deployment_version: u64,
    /// Exclusive Unix timestamp expiry in ledger seconds. Authored policy may add a stricter bound.
    pub expires_at: u64,
    /// Installed module selection and exact canonical arguments, bound before compiled policy execution.
    pub invocation: PolicyInvocation,
    /// Optional canonical XDR of ExpenseBounds, bounded by MAX_EXPENSE_BYTES. New cost rules require Some.
    pub expense: Option<Bytes>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyBinding {
    /// Exact installed wallet tier, independently bound by its executable hash.
    pub engine_kind: Symbol,
    /// Compiled kernel release metadata. Exact executable identity remains module_digest.
    pub contract_version: u32,
    /// Stable nonzero logical policy identifier. Upgrades and configuration changes preserve this identity.
    pub policy_instance: BytesN<32>,
    /// Actual wallet Wasm SHA-256 identity. It differs from both release metadata and the authored-source digest.
    pub module_digest: BytesN<32>,
    /// Fixed standard prefix binding, or the complete compiled source digest for Custom.
    /// Standard offchain source authorization is separate and does not change this binding.
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

/// Shared stateless checker. Each method runs `allowit::<rule>(&ctx, &ctx.grant.<rule>)`.
/// It returns the passing constraint or the rule error. It holds no custody or state.
#[contractclient(name = "EngineClient")]
pub trait EngineInterface {
    /// Run canonical `transaction_cap`; returns the headroom left for this operation.
    fn transaction_cap(env: Env, ctx: AllowitEnv) -> Result<i128, Error>;
    /// Run canonical `spent_cap`; returns the cumulative expense headroom.
    fn spent_cap(env: Env, ctx: AllowitEnv) -> Result<i128, Error>;
    /// Run canonical `day_spent_cap`; returns the UTC-day expense headroom.
    fn day_spent_cap(env: Env, ctx: AllowitEnv) -> Result<i128, Error>;
    /// Run canonical `day_total_cap`; returns the UTC-day gross headroom.
    fn day_total_cap(env: Env, ctx: AllowitEnv) -> Result<i128, Error>;
    /// Run canonical `call_cap`; returns the operations left.
    fn call_cap(env: Env, ctx: AllowitEnv) -> Result<u64, Error>;
    /// Run canonical `recipients`; returns the matched recipient.
    fn recipients(env: Env, ctx: AllowitEnv) -> Result<Address, Error>;
    /// Run canonical `tokens`; returns the matched asset.
    fn tokens(env: Env, ctx: AllowitEnv) -> Result<Address, Error>;
    /// Run canonical `expiry`; returns the seconds left.
    fn expiry(env: Env, ctx: AllowitEnv) -> Result<u64, Error>;
}
