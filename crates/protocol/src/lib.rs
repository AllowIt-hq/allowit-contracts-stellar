#![no_std]
use soroban_sdk::{Address, Env, Vec, contractclient, contracttype};

pub const MAX_RECIPIENTS: u32 = 16;

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

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRequest {
    pub recipient: Address,
    pub amount: i128,
    pub nonce: u64,
    pub revision: u64,
    pub expires_at: u64,
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
