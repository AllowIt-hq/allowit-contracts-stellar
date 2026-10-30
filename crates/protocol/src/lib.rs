#![no_std]
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Map, String, Symbol, Val, Vec, contractclient, contractevent,
    contracttype,
};

/// Native transfer-profile argument encoding, fixed independently of policy source.
pub const ARGUMENT_SCHEMA_DESCRIPTOR: &[u8] = b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)";
/// Exact SEP-56 deposit encoding. The vault is also its SEP-41 share-token contract.
pub const SEP56_DEPOSIT_SCHEMA_DESCRIPTOR: &[u8] = b"allowit.stellar.sep56_deposit.v1:ScValMap(assets:i128,from:Address,min_shares:i128,operator:Address,receiver:Address,vault:Address)";
pub const MAX_ARGUMENT_BYTES: u32 = 1024;

/// Owner-signed UTF-8 names mapped to exact native values. Values retain their representation.
/// No names or limits are mandatory. Authored policy selects and validates the values it reads.
pub type Grant = Map<String, Val>;

/// Mutable UTF-8 named policy usage data. Native values and unknown keys remain exact.
pub type Spent = Map<String, Val>;

/// Validate a native String as UTF-8 without an artificial length limit or heap allocation.
/// # Parameters
/// - `value`: Exact native String bytes, which Soroban can represent even when not UTF-8.
/// # Returns
/// Returns true only for valid UTF-8. Chunk boundaries preserve incomplete multibyte sequences.
pub fn utf8_string(value: &String) -> bool {
    let bytes = value.to_bytes();
    let mut buffer = [0u8; 259];
    let mut carry = 0usize;
    let mut offset = 0u32;
    while offset < bytes.len() {
        let end = bytes.len().min(offset.saturating_add(256));
        let count = (end - offset) as usize;
        bytes
            .slice(offset..end)
            .copy_into_slice(&mut buffer[carry..carry + count]);
        let length = carry + count;
        match core::str::from_utf8(&buffer[..length]) {
            Ok(_) => carry = 0,
            Err(error) => {
                if error.error_len().is_some() {
                    return false;
                }
                carry = length - error.valid_up_to();
                buffer.copy_within(error.valid_up_to()..length, 0);
            }
        }
        offset = end;
    }
    carry == 0
}

/// Validate the names of a Grant/Spent map without restricting its values or size.
/// # Parameters
/// - `env`: Native value environment owning this map.
/// - `values`: Exact raw object represented by the named-map type.
/// # Returns
/// Returns false for non-String or non-UTF-8 top-level keys. Nested and unrelated values are untouched.
pub fn named_values_valid(env: &Env, values: &Map<String, Val>) -> bool {
    use soroban_sdk::TryFromVal;
    let Ok(raw) = Map::<Val, Val>::try_from_val(env, &values.to_val()) else {
        return false;
    };
    raw.iter()
        .all(|(name, _)| String::try_from_val(env, &name).is_ok_and(|name| utf8_string(&name)))
}

/// Native helper failure collapsed by generated policy lowering into the custody policy-denied result.
/// This zero-sized error is not serialized as a contract argument or state field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyFailure;
impl From<PolicyFailure> for () {
    fn from(_: PolicyFailure) {}
}

/// Scalar value available to authored policy property helpers.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyValue {
    /// Unsigned integer with checked arithmetic in policy evaluation.
    U64(u64),
    /// Boolean value with no numeric coercion.
    Bool(bool),
    /// Native UTF-8 string, preserved without numeric or Boolean coercion.
    String(String),
}

impl PolicyValue {
    /// Decode one raw grant scalar without coercion. Other valid native values remain unsupported by scalar helpers.
    ///
    /// # Parameters
    /// - `env`: Host environment that owns the raw native value.
    /// - `value`: Exact raw grant value selected by its authored key.
    ///
    /// # Returns
    /// Returns its scalar value, or an error for every other native type.
    pub fn from_raw(env: &Env, value: &Val) -> Result<Self, PolicyFailure> {
        use soroban_sdk::TryFromVal;
        if let Ok(value) = u64::try_from_val(env, value) {
            Ok(Self::U64(value))
        } else if let Ok(value) = bool::try_from_val(env, value) {
            Ok(Self::Bool(value))
        } else if let Ok(value) = String::try_from_val(env, value) {
            if utf8_string(&value) {
                Ok(Self::String(value))
            } else {
                Err(PolicyFailure)
            }
        } else {
            Err(PolicyFailure)
        }
    }
    /// Encode this supported scalar as its raw native value, without an enum wrapper.
    /// # Parameters
    /// - `env`: Host environment that owns the resulting native value.
    /// # Returns
    /// Returns exact U64, Boolean or native String data without coercion.
    pub fn into_raw(self, env: &Env) -> Val {
        use soroban_sdk::IntoVal;
        match self {
            Self::U64(value) => value.into_val(env),
            Self::Bool(value) => value.into_val(env),
            Self::String(value) => value.into_val(env),
        }
    }
}

/// Private selected-check capability for compiler-selected shared-engine checks.
/// Authored source cannot select arbitrary methods or supply custody identity payloads.
pub trait PolicyEngine {
    /// Read the immutable request authenticated by custody.
    /// # Returns
    /// Returns copied request data and operation identity, without spending authority.
    fn request(&self) -> EngineRequest;

    /// Invoke one compiler-selected shared-engine check without committing its result.
    /// # Parameters
    /// - `method`: Fixed admitted engine method selected at authoring time.
    /// - `spent`: Explicit current usage map selected by functional source chaining.
    /// - `params`: Exact typed extra arguments emitted from authored source.
    /// # Returns
    /// Returns a decision and proposed map. Errors never trigger a local fallback.
    fn engine_check(
        &self,
        method: &str,
        spent: &Spent,
        params: Vec<Val>,
    ) -> Result<EngineResult, PolicyFailure>;
}

/// Internal normalized transfer used by custody admission. It is not a public wallet entrypoint.
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
    /// Exclusive Unix timestamp expiry in ledger seconds. Authored policy may add a stricter bound.
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
    /// Actual share credit, equal to the vault's returned minted units.
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
    /// Exclusive Unix timestamp expiry in ledger seconds. Authored policy may add a stricter bound.
    pub expires_at: u64,
    /// Installed module selection and exact canonical arguments, bound before compiled policy execution.
    pub invocation: PolicyInvocation,
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
/// Amounts use the admitted SAC's exact native units.
#[derive(Clone)]
pub struct PolicyContext {
    /// Kernel-selected canonical operation name. Callers cannot substitute an action label.
    pub operation: String,
    /// Immutable installed SAC address authenticated by custody.
    pub asset: Address,
    /// Exact intended token destination, bound by custody to the native transfer.
    pub recipient: Address,
    /// Authenticated SAC label. The x402 path uses the label cached outside the active SAC call.
    pub token: String,
    /// Authenticated SAC decimal scale, fixed at seven by this custody profile.
    pub decimals: u32,
    /// Positive native i128 base units of the proposed gross underlying debit.
    pub amount: i128,
    /// Authenticated ledger close time in Unix seconds.
    pub now: u64,
}

/// Exact proposal copied by custody into every explicitly selected shared-engine check.
/// This record grants no token authority and contains no caller-controlled accounting override.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineRequest {
    /// Custody contract that owns the transfer and named spent data.
    pub wallet: Address,
    /// Configured agent whose request custody authenticated.
    pub agent: Address,
    /// Immutable installed SAC address, distinct from its label.
    pub asset: Address,
    /// Authenticated SAC label supplied without an active-token callback.
    pub token: String,
    /// Authenticated native decimal scale, fixed at seven by custody.
    pub decimals: u32,
    /// Exact intended destination from the canonical transfer arguments.
    pub recipient: Address,
    /// Positive exact transfer amount in native i128 base units.
    pub amount: i128,
    /// Nonzero logical operation identity, used for once-per-operation engine accounting.
    pub operation_id: BytesN<32>,
    /// Current execution sequence checked by custody before policy evaluation.
    pub nonce: u64,
    /// Current owner configuration version checked by custody.
    pub deployment_version: u64,
    /// Exclusive request expiry in Unix ledger seconds.
    pub expires_at: u64,
    /// Authenticated ledger close time in Unix seconds.
    pub now: u64,
}

/// Shared copies supplied to each selected engine check, never mutable references into custody.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineState {
    /// Complete immutable owner-signed configuration. Only the selected check interprets its needed keys.
    pub grant: Map<String, Val>,
    /// Complete current named usage map, including prior approved checks in this operation.
    pub spent: Map<String, Val>,
}

/// Engine-owned business-state proposal. It contains no executable command or custody configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineResult {
    /// Predicate decision. Authored policy determines whether false denies or selects another branch.
    pub approval: bool,
    /// Proposed complete usage map. Custody applies it only on approval and rolls it back on enclosing failure.
    pub spent: Map<String, Val>,
}

#[soroban_sdk::contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EngineError {
    InvalidState = 1,
    InvalidParameter = 2,
    Overflow = 3,
}

#[contractclient(name = "EngineClient")]
pub trait EngineInterface {
    /// Run the explicitly selected daily_cap shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn daily_cap(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected transaction_cap shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn transaction_cap(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected total_cap shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn total_cap(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected call_cap shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn call_cap(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected recipient shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn recipient(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected expiry shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn expiry(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected token shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn token(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected cap_per_transaction shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    /// - `limit`: Positive cap in native asset base units.
    /// - `token`: Expected authenticated SAC label.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn cap_per_transaction(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        limit: i128,
        token: String,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected cap_per_day shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    /// - `limit`: Positive UTC-day cap in native asset base units.
    /// - `token`: Expected authenticated SAC label.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn cap_per_day(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        limit: i128,
        token: String,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected recipient_is shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    /// - `expected`: Exact allowed destination address.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn recipient_is(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        expected: Address,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected asset_label shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    /// - `expected`: Exact authenticated SAC label required by this source check.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn asset_label(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        expected: String,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected actions shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    /// - `allowed`: Explicit source-selected action identifiers.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn actions(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        allowed: Vec<String>,
    ) -> Result<EngineResult, EngineError>;
    /// Run the explicitly selected amount_at_most shared-engine check.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from native serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Full owner grant and current spent map copied by custody.
    /// - `limit`: Positive comparison bound in native asset base units.
    /// - `token`: Expected authenticated SAC label.
    ///
    /// # Returns
    /// Returns a decision and proposed spent map, or an error for invalid parameters or state.
    fn amount_at_most(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        limit: i128,
        token: String,
    ) -> Result<EngineResult, EngineError>;
}
