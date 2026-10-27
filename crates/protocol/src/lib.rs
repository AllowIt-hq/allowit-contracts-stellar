#![no_std]
use soroban_sdk::{Address, Bytes, BytesN, Env, String, Symbol, Vec, contractclient, contracttype};

pub const MAX_RECIPIENTS: u32 = 16;
/// Native transfer-profile argument encoding, fixed independently of policy source.
pub const ARGUMENT_SCHEMA_DESCRIPTOR: &[u8] = b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)";
pub const MAX_ARGUMENT_BYTES: u32 = 1024;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    pub asset: Address,
    pub recipients: Vec<Address>,
    pub per_transfer: i128,
    pub daily_limit: i128,
    pub total_limit: i128,
    pub max_calls: u64,
    pub expires_at: u64,
}

/// Internal normalized transfer passed to the veto engine. It is not a public wallet entrypoint.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRequest {
    pub recipient: Address,
    pub amount: i128,
    pub nonce: u64,
    pub revision: u64,
    pub expires_at: u64,
}

/// Exact arguments of the admitted stellar::sep41_transfer operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sep41TransferArgs {
    pub token: Address,
    pub from: Address,
    pub to: Address,
    pub amount: i128,
}

/// The native profile of the canonical signed module-selection record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyInvocation {
    pub module_digest: BytesN<32>,
    pub entrypoint: Symbol,
    pub argument_schema_digest: BytesN<32>,
    pub arguments: Bytes,
}

/// The SDK maps OperationRef.policy_instance and OperationRef.nonce without changing them.
/// The monotonic native nonce and configuration revision come from authenticated custody state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRequest {
    pub policy_instance: BytesN<32>,
    pub operation_id: BytesN<32>,
    pub nonce: u64,
    pub revision: u64,
    pub expires_at: u64,
    pub invocation: PolicyInvocation,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyBinding {
    pub policy_instance: BytesN<32>,
    pub module_digest: BytesN<32>,
    pub source_digest: BytesN<32>,
    pub argument_schema_digest: BytesN<32>,
    pub entrypoint: Symbol,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferReceipt {
    pub operation_id: BytesN<32>,
    pub token: Address,
    pub from: Address,
    pub to: Address,
    pub amount: i128,
    pub nonce: u64,
    pub revision: u64,
}

/// Authenticated observations consumed by statically compiled owner policy.
/// Amounts and counters use the admitted SAC's exact native units.
#[derive(Clone)]
pub struct PolicyContext {
    pub asset: Address,
    pub recipient: Address,
    pub token: String,
    pub decimals: u32,
    pub amount: i128,
    pub spent_daily: i128,
    pub spent_total: i128,
    pub calls: u64,
    pub now: u64,
    pub spent_day: u64,
}

/// Observations are supplied by custody. This record alone grants no authority.
/// Custody normalizes spent_daily to the current UTC day before evaluation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineContext {
    pub wallet: Address,
    pub agent: Address,
    pub asset: Address,
    pub request: TransferRequest,
    pub grant: Grant,
    pub spent_daily: i128,
    pub spent_total: i128,
    pub calls: u64,
    pub now: u64,
}

#[contractclient(name = "EngineClient")]
pub trait EngineInterface {
    fn evaluate(env: Env, context: EngineContext) -> bool;
}
