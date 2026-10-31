//! Stellar adapters for the existing typed execution request and operation lifecycle.
//! Native and policy wallet custody use the same authored policy and exact operation identity.
use allowit_policy_sdk::typed_workflow::{
    AbiValue, AccountId as WorkflowAccount, AccountKind, Amount256, Chain, ExecutionInput,
    ExecutionRequest, NativeInstruction, WorkflowAsset,
};
use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stellar_strkey::{Contract, Strkey, ed25519};
use stellar_xdr::*;

pub use allowit_policy_sdk::PolicyEngine;
pub mod admin;
mod authorization;
pub mod owner;
pub use authorization::authorize_server;
pub mod properties;
mod values;
pub use values::NativeValues;
pub mod rpc;
pub mod x402;
pub type Result<T> = std::result::Result<T, String>;

pub const PROFILE: &str = "allowit-stellar-wallet-v1";
pub const ARGUMENT_SCHEMA: &[u8] = b"allowit.stellar.sep41_transfer.v1:ScValMap(amount:i128,from:Address,to:Address,token:Address)";
const MAX_BYTES: usize = 1_048_576;

pub fn hash(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(bytes.as_ref()).into()
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid hexadecimal identity".into());
    }
    let mut out = [0; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(err)?;
    }
    Ok(out)
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn limits() -> Limits {
    Limits {
        depth: 64,
        len: MAX_BYTES,
    }
}
fn xdr<T: WriteXdr>(value: &T) -> Result<String> {
    value.to_xdr_base64(limits()).map_err(err)
}
fn read<T: ReadXdr>(value: &str) -> Result<T> {
    if value.len() > MAX_BYTES * 2 {
        return Err("XDR exceeds limit".into());
    }
    T::from_xdr_base64(value, limits()).map_err(err)
}
pub fn passphrase(network: &str) -> Result<&'static str> {
    match network {
        "stellar:mainnet" => Ok("Public Global Stellar Network ; September 2015"),
        "stellar:testnet" => Ok("Test SDF Network ; September 2015"),
        _ => Err("Unsupported Stellar network".into()),
    }
}
pub fn network_id(network: &str) -> Result<[u8; 32]> {
    Ok(hash(passphrase(network)?))
}
/// Decode a canonical local Ed25519 seed. Never include this value in an export bundle.
pub fn decode_seed(value: &str) -> Result<[u8; 32]> {
    ed25519::PrivateKey::from_string(value)
        .map(|v| v.0)
        .map_err(|_| "Expected a canonical Stellar S seed".into())
}
pub fn account_for_seed(seed: &[u8; 32]) -> String {
    ed25519::PublicKey(SigningKey::from_bytes(seed).verifying_key().to_bytes()).to_string()
}
pub fn account_key(address: &str) -> Result<[u8; 32]> {
    ed25519::PublicKey::from_string(address)
        .map(|v| v.0)
        .map_err(|_| "Expected canonical Stellar G account".into())
}
pub fn address(value: &str) -> Result<ScAddress> {
    match Strkey::from_string(value).map_err(err)? {
        Strkey::PublicKeyEd25519(v) => Ok(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(v.0)),
        ))),
        Strkey::Contract(v) => Ok(ScAddress::Contract(ContractId(Hash(v.0)))),
        _ => Err("Only canonical G and C addresses are admitted".into()),
    }
}
pub fn address_text(value: &ScAddress) -> Result<String> {
    match value {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(v))) => {
            Ok(ed25519::PublicKey(v.0).to_string())
        }
        ScAddress::Contract(v) => Ok(Contract(v.0.0).to_string()),
        _ => Err("Unsupported address".into()),
    }
}
fn workflow_address(value: &WorkflowAccount) -> Result<String> {
    if value.chain != Chain::Stellar {
        return Err("Wrong request rail".into());
    }
    match value.kind {
        AccountKind::Wallet => Ok(ed25519::PublicKey(value.address).to_string()),
        AccountKind::Contract => Ok(Contract(value.address).to_string()),
        _ => Err("Unsupported Stellar account kind".into()),
    }
}
fn value_symbol(v: &str) -> Result<ScVal> {
    Ok(ScVal::Symbol(ScSymbol(
        v.as_bytes().to_vec().try_into().map_err(err)?,
    )))
}
fn value_bytes(v: &[u8]) -> Result<ScVal> {
    Ok(ScVal::Bytes(ScBytes(v.to_vec().try_into().map_err(err)?)))
}
fn value_map(entries: Vec<(&str, ScVal)>) -> Result<ScVal> {
    let mut out = entries
        .into_iter()
        .map(|(k, val)| {
            Ok(ScMapEntry {
                key: value_symbol(k)?,
                val,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(ScVal::Map(Some(ScMap(out.try_into().map_err(err)?))))
}
fn i128_value(v: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (v >> 64) as i64,
        lo: v as u64,
    })
}
fn amount(v: &Amount256) -> Result<i128> {
    if v.0[..16].iter().any(|b| *b != 0) {
        return Err("Amount exceeds native i128".into());
    }
    i128::try_from(u128::from_be_bytes(v.0[16..].try_into().unwrap())).map_err(err)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum WalletRoute {
    Native,
    PolicyWallet,
    /// Historical signed packets only. New preparation rejects this route.
    #[doc(hidden)]
    Odc,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletConfig {
    pub network: String,
    pub policy_instance: [u8; 32],
    pub wallet: String,
    pub owner: String,
    pub agent: String,
    #[serde(alias = "engine")]
    pub server: String,
    pub route: WalletRoute,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_engine: Option<PolicyEngine>,
    pub asset: String,
    pub asset_symbol: String,
    #[serde(default)]
    pub asset_issuer: Option<String>,
    pub policy_source: String,
    pub source_hash: [u8; 32],
    pub module_digest: [u8; 32],
    pub max_fee_stroops: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountSigner {
    pub key: String,
    pub weight: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountState {
    pub address: String,
    pub sequence: i64,
    pub master_weight: u32,
    pub low_threshold: u32,
    pub medium_threshold: u32,
    pub high_threshold: u32,
    pub signers: Vec<AccountSigner>,
}
fn automated_roles(c: &WalletConfig) -> Vec<&str> {
    let mut roles = vec![c.agent.as_str()];
    if c.route == WalletRoute::Native && c.server != c.agent {
        roles.push(c.server.as_str());
    }
    roles
}
impl AccountState {
    pub fn validate_structure(&self) -> Result<()> {
        account_key(&self.address)?;
        if self.sequence < 0
            || self.master_weight > 255
            || [
                self.low_threshold,
                self.medium_threshold,
                self.high_threshold,
            ]
            .iter()
            .any(|v| *v > 255)
            || self.signers.len() > 20
        {
            return Err("Invalid live account structure".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for signer in &self.signers {
            let key = Strkey::from_string(&signer.key).map_err(err)?;
            if !matches!(
                key,
                Strkey::PublicKeyEd25519(_)
                    | Strkey::PreAuthTx(_)
                    | Strkey::HashX(_)
                    | Strkey::SignedPayloadEd25519(_)
            ) || key.to_string() != signer.key
                || signer.key == self.address
                || !seen.insert(signer.key.clone())
            {
                return Err("Invalid or duplicate live account signer".into());
            }
        }
        Ok(())
    }
    pub fn signer_weight(&self, signer: &str) -> Result<u32> {
        self.validate_structure()?;
        account_key(signer)?;
        Ok(if signer == self.address {
            self.master_weight
        } else {
            self.signers
                .iter()
                .find(|s| s.key == signer)
                .map_or(0, |s| s.weight.min(255))
        })
    }
    pub fn validate_signer_quorum(&self, signers: &[&str], threshold: u32) -> Result<()> {
        self.validate_structure()?;
        if threshold > 255 {
            return Err("Invalid account threshold".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut weight = 0u32;
        for signer in signers {
            if !seen.insert(*signer) {
                return Err("Duplicate quorum signer".into());
            }
            weight = weight
                .checked_add(self.signer_weight(signer)?)
                .ok_or("Signer weight overflow")?;
        }
        if weight == 0 || weight < threshold {
            return Err("Current account signer quorum is insufficient".into());
        }
        Ok(())
    }
    pub fn validate_wallet(&self, c: &WalletConfig) -> Result<()> {
        if self.address != c.wallet {
            return Err("Native wallet identity differs".into());
        }
        if self.signer_weight(&c.agent)? == 0 {
            return Err("Customer is not a current account signer".into());
        }
        Ok(())
    }
}
/// Complete native policy inputs. Both maps preserve arbitrary ScVal values.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyStateSnapshot {
    pub grant: NativeValues,
    pub spent: NativeValues,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedState {
    /// Executable release metadata. Legacy code has no advertised release version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_version: Option<u32>,
    /// Full chain-observed policy wallet maps; classic usage fields below are not policy wallet accounting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_state: Option<PolicyStateSnapshot>,
    pub source: AccountState,
    pub nonce: u64,
    /// Current ordered owner configuration. Historical spellings identify this same counter.
    #[serde(alias = "revision")]
    pub deployment_version: u64,
    pub spent_daily: i128,
    pub spent_total: i128,
    pub spent_day: u64,
    pub calls: u64,
    pub ledger: u32,
    pub module_digest: [u8; 32],
    pub source_hash: [u8; 32],
    pub owner: String,
    pub agent: String,
    #[serde(alias = "engine")]
    pub server: String,
    pub policy_instance: [u8; 32],
}
/// Ephemeral proof that the exact native operation passed trusted RPC preflight.
/// It grants no authority against later chain changes and cannot be deserialized.
#[derive(Clone, Debug)]
pub struct NativePreflight {
    binding: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedOperation {
    pub version: u32,
    pub config: WalletConfig,
    pub request: ExecutionRequest,
    pub state: TrustedState,
    pub transaction_xdr: String,
    pub transaction_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub simulation_data: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(skip)]
    pub native_preflight: Option<NativePreflight>,
}
// The ephemeral preflight is new-signing admission, not durable signed-record identity.
impl PartialEq for PreparedOperation {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.config == other.config
            && self.request == other.request
            && self.state == other.state
            && self.transaction_xdr == other.transaction_xdr
            && self.transaction_hash == other.transaction_hash
            && self.request_hash == other.request_hash
            && self.simulation_data == other.simulation_data
            && self.created_at == other.created_at
            && self.expires_at == other.expires_at
    }
}
impl Eq for PreparedOperation {}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetachedSignature {
    pub signer: String,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedOperation {
    pub prepared: PreparedOperation,
    pub transaction_xdr: String,
    pub transaction_hash: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum OperationStatus {
    Prepared,
    Submitted,
    SubmissionUnknown,
    Confirmed,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub token: String,
    pub source: String,
    pub recipient: String,
    pub amount: i128,
    pub native: bool,
}

pub fn validate_config(c: &WalletConfig) -> Result<()> {
    passphrase(&c.network)?;
    if c.policy_instance == [0; 32]
        || c.source_hash != hash(c.policy_source.as_bytes())
        || c.max_fee_stroops < 100
        || c.max_fee_stroops
            > match c.route {
                WalletRoute::Native => 1_000_000,
                WalletRoute::PolicyWallet | WalletRoute::Odc => 2_000_000,
            }
    {
        return Err("Invalid installed policy or fee binding".into());
    }
    address(&c.owner)?;
    account_key(&c.agent)?;
    match c.route {
        WalletRoute::Native => {
            account_key(&c.wallet)?;
            account_key(&c.server)?;
        }
        WalletRoute::PolicyWallet | WalletRoute::Odc => {
            if c.route == WalletRoute::PolicyWallet {
                account_key(&c.server)?;
                if c.server == c.agent || c.policy_engine.is_none() {
                    return Err(
                        "Distinct agent and service signer and selected policy engine are required"
                            .into(),
                    );
                }
            } else {
                Contract::from_string(&c.server).map_err(err)?;
            }
            Contract::from_string(&c.wallet).map_err(err)?;
            if c.module_digest == [0; 32] {
                return Err("Missing installed policy wallet code identity".into());
            }
        }
    }
    address(&c.asset)?;
    if c.asset != sac_address(&c.network, &asset_xdr(c)?)? {
        return Err("SAC does not match installed native asset identity".into());
    }
    Ok(())
}
/// Decode only the admitted catalog transfer profile, with exact effect and fee bounds.
pub fn transfer_from_request(c: &WalletConfig, r: &ExecutionRequest) -> Result<Transfer> {
    decode_transfer(c, r, false)
}
fn decode_transfer(c: &WalletConfig, r: &ExecutionRequest, retained: bool) -> Result<Transfer> {
    validate_config(c)?;
    if r.operation.policy_instance != c.policy_instance || r.operation.nonce == [0; 32] {
        return Err("Operation installation or identity differs".into());
    }
    let ExecutionInput::Instructions(instructions) = &r.input else {
        return Err("Stellar execution requires typed instructions".into());
    };
    if instructions.len() != 1 || r.effect_bounds.len() != 1 || !r.evidence.is_empty() {
        return Err("Only one admitted transfer without unresolved evidence is supported".into());
    }
    let transfer = match &instructions[0] {
        NativeInstruction::StellarNativeTransfer {
            source,
            destination,
            stroops,
        } => Transfer {
            token: c.asset.clone(),
            source: workflow_address(source)?,
            recipient: workflow_address(destination)?,
            amount: i128::from(*stroops),
            native: true,
        },
        NativeInstruction::StellarCall {
            contract,
            schema_digest,
            function,
            arguments,
        } => {
            if workflow_address(contract)? != c.asset
                || *schema_digest != hash(ARGUMENT_SCHEMA)
                || function != "transfer"
                || arguments.len() != 3
            {
                return Err("Unknown Stellar module, schema or method".into());
            }
            let [
                AbiValue::Account(from),
                AbiValue::Account(to),
                AbiValue::Signed128(units),
            ] = arguments.as_slice()
            else {
                return Err("Invalid SEP-41 arguments".into());
            };
            Transfer {
                token: c.asset.clone(),
                source: workflow_address(from)?,
                recipient: workflow_address(to)?,
                amount: *units,
                native: false,
            }
        }
        _ => return Err("Unsupported Stellar instruction".into()),
    };
    if transfer.native && asset_xdr(c)? != Asset::Native {
        return Err("Native XLM request differs from installed asset".into());
    }
    if transfer.amount <= 0 || transfer.source != c.wallet || transfer.recipient == c.wallet {
        return Err("Invalid transfer source, amount or recipient".into());
    }
    if !retained && c.asset_issuer.as_deref() == Some(transfer.recipient.as_str()) {
        return Err("Issued-asset payments to the issuer burn units instead of crediting the required recipient balance".into());
    }
    let effect = &r.effect_bounds[0];
    let asset = match &effect.asset {
        WorkflowAsset::Native { chain, network } => {
            *chain == Chain::Stellar && *network == network_id(&c.network)? && transfer.native
        }
        WorkflowAsset::Token(a) => {
            a.network == network_id(&c.network)?
                && workflow_address(&a.token)? == c.asset
                && !transfer.native
        }
    };
    if !asset
        || workflow_address(&effect.source)? != transfer.source
        || workflow_address(&effect.beneficiary)? != transfer.recipient
        || amount(&effect.max_debit)? != transfer.amount
        || amount(&effect.min_credit)? != transfer.amount
        || amount(&effect.max_burn)? != 0
    {
        return Err("Transfer effects differ from approved bounds".into());
    }
    let fees = r
        .fee_bounds
        .as_ref()
        .ok_or("Resolved native fee bounds are required")?;
    if fees.len() != 1 {
        return Err("One native fee bound is required".into());
    }
    let fee = &fees[0];
    let payer = workflow_address(&fee.payer)?;
    account_key(&payer)?;
    if (c.route == WalletRoute::Native && payer != c.wallet)
        || !matches!(&fee.asset,WorkflowAsset::Native{chain:Chain::Stellar,network} if *network==network_id(&c.network)?)
        || amount(&fee.max_fee)? < i128::from(c.max_fee_stroops)
    {
        return Err("Native fee payer or fee bound differs".into());
    }
    Ok(transfer)
}
pub fn asset_xdr(c: &WalletConfig) -> Result<Asset> {
    asset_from_identity(&c.asset_symbol, c.asset_issuer.as_deref())
}
/// Construct the exact classic asset before deriving its network-bound SAC address.
pub fn asset_from_identity(symbol: &str, issuer: Option<&str>) -> Result<Asset> {
    if symbol == "XLM" && issuer.is_none() {
        return Ok(Asset::Native);
    }
    let issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key(
        issuer.ok_or("Issued asset needs exact issuer")?,
    )?)));
    let code = symbol.as_bytes();
    if code.is_empty() || code.len() > 12 || !code.iter().all(|v| v.is_ascii_alphanumeric()) {
        return Err("Invalid issued asset code".into());
    }
    if code.len() <= 4 {
        let mut v = [0; 4];
        v[..code.len()].copy_from_slice(code);
        Ok(Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(v),
            issuer,
        }))
    } else {
        let mut v = [0; 12];
        v[..code.len()].copy_from_slice(code);
        Ok(Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(v),
            issuer,
        }))
    }
}
pub fn sac_address(network: &str, asset: &Asset) -> Result<String> {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network_id(network)?),
        contract_id_preimage: ContractIdPreimage::Asset(asset.clone()),
    });
    Ok(Contract(hash(preimage.to_xdr(limits()).map_err(err)?)).to_string())
}
pub fn verify_policy(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    now: u64,
) -> Result<()> {
    let t = transfer_from_request(c, r)?;
    let policy = allowit_policy_sdk::compile_stellar_policy(&c.policy_source).map_err(err)?;
    if c.route == WalletRoute::Native
        && (policy.uses_named_state() || !policy.explicit_engine_checks.is_empty())
    {
        return Err(
            "Classic/native custody cannot enforce named-state or shared-engine policy calls"
                .into(),
        );
    }
    if c.route == WalletRoute::PolicyWallet && policy.requires_native_preflight() {
        return Err("Native policy requires authoritative execution preflight".into());
    }
    if policy.source_hash != c.source_hash
        || !policy.evaluate(&allowit_policy_sdk::StellarPolicyContext {
            asset: c.asset.clone(),
            recipient: t.recipient,
            token: c.asset_symbol.clone(),
            decimals: 7,
            amount: t.amount,
            spent_daily: state.spent_daily,
            spent_total: state.spent_total,
            calls: state.calls,
            now,
            spent_day: state.spent_day,
        })
    {
        return Err("Authored policy rejected this exact Stellar operation".into());
    }
    Ok(())
}
fn muxed(value: &str) -> Result<MuxedAccount> {
    Ok(MuxedAccount::Ed25519(Uint256(account_key(value)?)))
}
fn transaction_hash(network: &str, tx: &Transaction) -> Result<[u8; 32]> {
    Ok(hash(
        TransactionSignaturePayload {
            network_id: Hash(network_id(network)?),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        }
        .to_xdr(limits())
        .map_err(err)?,
    ))
}
fn transfer_args(c: &WalletConfig, t: &Transfer) -> Result<ScVal> {
    value_map(vec![
        ("amount", i128_value(t.amount)),
        ("from", ScVal::Address(address(&c.wallet)?)),
        ("to", ScVal::Address(address(&t.recipient)?)),
        ("token", ScVal::Address(address(&c.asset)?)),
    ])
}
fn policy_wallet_request(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    t: &Transfer,
    expires: u64,
    legacy_revision: bool,
) -> Result<ScVal> {
    let args = transfer_args(c, t)?.to_xdr(limits()).map_err(err)?;
    let invocation = value_map(vec![
        ("module_digest", value_bytes(&c.module_digest)?),
        ("entrypoint", value_symbol("_execute")?),
        (
            "argument_schema_digest",
            value_bytes(&hash(ARGUMENT_SCHEMA))?,
        ),
        ("arguments", value_bytes(&args)?),
    ])?;
    value_map(vec![
        ("policy_instance", value_bytes(&c.policy_instance)?),
        ("operation_id", value_bytes(&r.operation.nonce)?),
        ("nonce", ScVal::U64(state.nonce)),
        (
            if legacy_revision {
                "revision"
            } else {
                "deployment_version"
            },
            ScVal::U64(state.deployment_version),
        ),
        ("expires_at", ScVal::U64(expires)),
        ("invocation", invocation),
    ])
}
#[derive(Clone, Copy)]
enum PacketUse {
    Current,
    Retained,
    RetainedRevision,
    NativePreflight,
}
fn build(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    now: u64,
    expires: u64,
    retained_native_lower_bound: bool,
    packet: PacketUse,
) -> Result<Transaction> {
    let admit_policy = matches!(packet, PacketUse::Current);
    let legacy_revision = matches!(packet, PacketUse::RetainedRevision);
    if c.route == WalletRoute::Odc
        && matches!(packet, PacketUse::Current | PacketUse::NativePreflight)
    {
        return Err("Historical wallet packets are read-only".into());
    }
    if matches!(c.route, WalletRoute::PolicyWallet | WalletRoute::Odc) {
        if legacy_revision {
            if admit_policy || state.contract_version.is_some() {
                return Err("Legacy policy wallet packets are read-only".into());
            }
        } else if state.contract_version != Some(1) {
            return Err("Unsupported policy contract version".into());
        }
    }
    let t = decode_transfer(
        c,
        r,
        matches!(packet, PacketUse::Retained | PacketUse::RetainedRevision),
    )?;
    if admit_policy {
        verify_policy(c, r, state, now)?;
    }
    if c.route == WalletRoute::Native
        && expires
            > (now / 86400)
                .checked_add(1)
                .and_then(|day| day.checked_mul(86400))
                .ok_or("UTC boundary overflow")?
    {
        return Err("Native approval cannot cross its UTC budget day".into());
    }
    if expires <= now || expires > now.checked_add(300).ok_or("Expiry overflow")? {
        return Err("Operation expiry must be within 300 seconds".into());
    }
    if state.source_hash != c.source_hash {
        return Err("Installed authored source identity differs".into());
    }
    if state.policy_instance != c.policy_instance
        || (c.route == WalletRoute::Native && state.agent != c.agent)
        || (c.route != WalletRoute::Odc && state.server != c.server)
    {
        return Err("Trusted wallet identity differs".into());
    }
    let mut body = match c.route {
        WalletRoute::Native => {
            state.source.validate_wallet(c)?;
            OperationBody::Payment(PaymentOp {
                destination: muxed(&t.recipient)?,
                asset: asset_xdr(c)?,
                amount: i64::try_from(t.amount).map_err(|_| "Classic payment exceeds i64")?,
            })
        }
        WalletRoute::PolicyWallet | WalletRoute::Odc => {
            state.source.validate_structure()?;
            if state.source.signer_weight(&c.agent)? == 0 {
                return Err("Customer is not a current policy wallet agent account signer".into());
            }
            if state.module_digest != c.module_digest || state.source.address != state.agent {
                return Err(
                    "policy wallet executable or current agent transaction source differs".into(),
                );
            }
            let fee = &r.fee_bounds.as_ref().ok_or("Native fee bound required")?[0];
            if workflow_address(&fee.payer)? != state.source.address {
                return Err(
                    "policy wallet fee payer differs from its current agent account".into(),
                );
            }
            OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: address(&c.wallet)?,
                    function_name: ScSymbol(b"execute".to_vec().try_into().map_err(err)?),
                    args: vec![policy_wallet_request(
                        c,
                        r,
                        state,
                        &t,
                        expires,
                        legacy_revision,
                    )?]
                    .try_into()
                    .map_err(err)?,
                }),
                auth: vec![SorobanAuthorizationEntry {
                    credentials: SorobanCredentials::SourceAccount,
                    root_invocation: SorobanAuthorizedInvocation {
                        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                            contract_address: address(&c.wallet)?,
                            function_name: ScSymbol(b"execute".to_vec().try_into().map_err(err)?),
                            args: vec![policy_wallet_request(
                                c,
                                r,
                                state,
                                &t,
                                expires,
                                legacy_revision,
                            )?]
                            .try_into()
                            .map_err(err)?,
                        }),
                        sub_invocations: VecM::default(),
                    },
                }]
                .try_into()
                .map_err(err)?,
            })
        }
    };
    if c.route == WalletRoute::PolicyWallet {
        let OperationBody::InvokeHostFunction(op) = &mut body else {
            unreachable!()
        };
        let mut auth = op.auth.to_vec();
        auth.push(authorization::server_entry(
            c,
            r,
            state,
            auth[0].root_invocation.clone(),
        )?);
        op.auth = auth.try_into().map_err(err)?;
    }
    let tx = Transaction {
        source_account: muxed(&state.source.address)?,
        fee: c.max_fee_stroops,
        seq_num: SequenceNumber(
            state
                .source
                .sequence
                .checked_add(1)
                .ok_or("Sequence overflow")?,
        ),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(
                if c.route == WalletRoute::Native && !retained_native_lower_bound {
                    0
                } else {
                    now
                },
            ),
            max_time: TimePoint(expires),
        }),
        memo: if c.route == WalletRoute::Native {
            Memo::Hash(Hash(r.operation.nonce))
        } else {
            Memo::None
        },
        operations: vec![Operation {
            source_account: None,
            body,
        }]
        .try_into()
        .map_err(err)?,
        ext: TransactionExt::V0,
    };
    if c.route == WalletRoute::Native {
        account_transaction_signers(
            &state.source,
            &transaction_hash(&c.network, &tx)?,
            &automated_roles(c),
        )?;
    }
    Ok(tx)
}
pub fn prepare(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    prepare_with_bounds(c, r, state, now, expires_at, false, PacketUse::Current)
}
fn prepare_with_bounds(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
    retained_native_lower_bound: bool,
    packet: PacketUse,
) -> Result<PreparedOperation> {
    let tx = build(
        c,
        r,
        state,
        now,
        expires_at,
        retained_native_lower_bound,
        packet,
    )?;
    Ok(PreparedOperation {
        version: 1,
        config: c.clone(),
        request: r.clone(),
        state: state.clone(),
        transaction_xdr: xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: tx.clone(),
            signatures: VecM::default(),
        }))?,
        transaction_hash: transaction_hash(&c.network, &tx)?,
        request_hash: hash(serde_json::to_vec(r).map_err(err)?),
        simulation_data: None,
        created_at: now,
        expires_at,
        native_preflight: None,
    })
}
fn needs_native_preflight(c: &WalletConfig) -> Result<bool> {
    Ok(c.route == WalletRoute::PolicyWallet)
}
fn preflight_binding(p: &PreparedOperation) -> Result<[u8; 32]> {
    Ok(hash(serde_json::to_vec(p).map_err(err)?))
}
pub(crate) fn record_native_preflight(p: &mut PreparedOperation) -> Result<()> {
    p.native_preflight = Some(NativePreflight {
        binding: preflight_binding(p)?,
    });
    Ok(())
}
pub(crate) fn prepare_for_native_preflight(
    c: &WalletConfig,
    r: &ExecutionRequest,
    state: &TrustedState,
    now: u64,
    expires_at: u64,
) -> Result<PreparedOperation> {
    let compiled = allowit_policy_sdk::compile_stellar_policy(&c.policy_source).map_err(err)?;
    if c.source_hash != compiled.source_hash {
        return Err("Compiled policy source identity differs".into());
    }
    if c.route != WalletRoute::PolicyWallet {
        return prepare(c, r, state, now, expires_at);
    }
    if state.policy_state.is_none() {
        return Err("Trusted native Grant and spent observations are required".into());
    }
    prepare_with_bounds(
        c,
        r,
        state,
        now,
        expires_at,
        false,
        PacketUse::NativePreflight,
    )
}
fn validate_signing_policy(p: &PreparedOperation, now: u64) -> Result<()> {
    transfer_from_request(&p.config, &p.request)?;
    if needs_native_preflight(&p.config)? {
        let marker = p
            .native_preflight
            .as_ref()
            .ok_or("Native policy preflight is required before new signing")?;
        if marker.binding != preflight_binding(p)? {
            return Err("Native preflight no longer binds this exact operation".into());
        }
        Ok(())
    } else {
        verify_policy(&p.config, &p.request, &p.state, now)
    }
}
/// Rebuild every authorization field before signing. Caller-supplied prepared metadata is not trusted.
pub fn validate_prepared(p: &PreparedOperation, now: u64) -> Result<()> {
    if p.config.route == WalletRoute::Odc
        || (p.config.route == WalletRoute::PolicyWallet && p.state.contract_version != Some(1))
    {
        return Err(
            "Legacy or unsupported policy wallet packets cannot authorize execution".into(),
        );
    }
    if p.version != 1 || p.created_at > now || now >= p.expires_at {
        return Err("Prepared operation is stale".into());
    }
    validate_signing_policy(p, p.created_at)?;
    validate_retained_prepared(p)
}
/// Verify retained transport and effect identity for read-only history or recovery.
/// This does not compile source, grant authorization, or permit a broadcast.
/// Native signatures do not prove source metadata. Bind it to the durable owner-approved record first.
pub fn validate_retained_prepared(p: &PreparedOperation) -> Result<()> {
    if p.version != 1 {
        return Err("Unsupported retained operation version".into());
    }
    let retained_native_lower_bound = if p.config.route == WalletRoute::Native {
        match native_lower_bound(p)? {
            0 => false,
            value if value == p.created_at => true,
            _ => return Err("Native lower time bound changed".into()),
        }
    } else {
        false
    };
    let mut expected = prepare_with_bounds(
        &p.config,
        &p.request,
        &p.state,
        p.created_at,
        p.expires_at,
        retained_native_lower_bound,
        if retained_revision_packet(p)? {
            PacketUse::RetainedRevision
        } else {
            PacketUse::Retained
        },
    )?;
    if p.config.route == WalletRoute::PolicyWallet {
        expected = authorization::attach(&expected, authorization::server_signature(p, false)?)?;
    }
    if let Some(data) = &p.simulation_data {
        expected = attach_simulation(&expected, data)?;
    }
    if &expected != p {
        return Err("Prepared operation changed".into());
    }
    Ok(())
}
// Canonical main emitted revision packets before contract release metadata existed.
// This private decoder permits only original-byte status/recovery verification.
fn retained_revision_packet(p: &PreparedOperation) -> Result<bool> {
    if p.config.route != WalletRoute::Odc {
        return Ok(false);
    }
    let TransactionEnvelope::Tx(env) = read(&p.transaction_xdr)? else {
        return Err("Invalid retained envelope".into());
    };
    let Some(Operation {
        body: OperationBody::InvokeHostFunction(op),
        ..
    }) = env.tx.operations.first()
    else {
        return Err("Invalid retained policy wallet operation".into());
    };
    let HostFunction::InvokeContract(call) = &op.host_function else {
        return Err("Invalid retained policy wallet call".into());
    };
    let Some(ScVal::Map(Some(fields))) = call.args.first() else {
        return Err("Invalid retained policy wallet request".into());
    };
    let keys: Vec<_> = fields
        .iter()
        .filter_map(|f| match &f.key {
            ScVal::Symbol(k) => Some(k.0.as_slice()),
            _ => None,
        })
        .collect();
    match (
        p.state.contract_version,
        keys.contains(&b"revision".as_slice()),
        keys.contains(&b"deployment_version".as_slice()),
    ) {
        (None, true, false) => Ok(true),
        (Some(1), false, true) => Ok(false),
        _ => Err("Unsupported retained policy wallet contract format".into()),
    }
}
fn native_lower_bound(p: &PreparedOperation) -> Result<u64> {
    let TransactionEnvelope::Tx(envelope) = read(&p.transaction_xdr)? else {
        return Err("Unsupported transaction envelope".into());
    };
    let Preconditions::Time(bounds) = envelope.tx.cond else {
        return Err("Native time bounds are required".into());
    };
    Ok(bounds.min_time.0)
}
fn current_authorization_bounds(p: &PreparedOperation) -> Result<()> {
    if p.config.route == WalletRoute::Native && native_lower_bound(p)? != 0 {
        return Err("Retained native time bounds are read-only".into());
    }
    Ok(())
}
pub fn sign(p: &PreparedOperation, seed: &[u8; 32], now: u64) -> Result<DetachedSignature> {
    validate_prepared(p, now)?;
    current_authorization_bounds(p)?;
    validate_signing_policy(p, now)?;
    if p.config.route == WalletRoute::PolicyWallet && p.simulation_data.is_none() {
        return Err("policy wallet resource simulation is required before signing".into());
    }
    if p.config.route == WalletRoute::PolicyWallet {
        authorization::server_signature(p, true)?;
    }
    let signer = account_for_seed(seed);
    let allowed = if p.config.route == WalletRoute::Native {
        signer == p.config.agent || signer == p.config.server
    } else {
        signer == p.config.agent
    };
    if !allowed {
        return Err("Signer has no automated role".into());
    }
    Ok(DetachedSignature {
        signer,
        signature: SigningKey::from_bytes(seed)
            .sign(&p.transaction_hash)
            .to_bytes()
            .to_vec(),
    })
}
fn transaction_signers(p: &PreparedOperation, candidates: &[&str]) -> Result<Vec<String>> {
    account_transaction_signers(&p.state.source, &p.transaction_hash, candidates)
}
fn account_transaction_signers(
    source: &AccountState,
    transaction_hash: &[u8; 32],
    candidates: &[&str],
) -> Result<Vec<String>> {
    source.validate_structure()?;
    let automatic: Vec<_> = source.signers.iter().filter(|s| matches!(Strkey::from_string(&s.key), Ok(Strkey::PreAuthTx(key)) if key.0 == *transaction_hash)).collect();
    let automatic_weight = automatic.iter().map(|s| s.weight.min(255)).sum::<u32>();
    let mut masks: Vec<_> = (0usize..(1usize << candidates.len())).collect();
    masks.sort_by_key(|mask| (mask.count_ones(), *mask));
    for mask in masks {
        let chosen: Vec<_> = candidates
            .iter()
            .enumerate()
            .filter(|(n, _)| mask & (1 << n) != 0)
            .map(|(_, key)| *key)
            .collect();
        let mut used = std::collections::BTreeSet::new();
        let mut satisfies = |threshold: u32| -> Result<bool> {
            if !automatic.is_empty() && automatic_weight >= threshold {
                return Ok(true);
            }
            let mut weight = automatic_weight;
            for key in &chosen {
                let current = source.signer_weight(key)?;
                if current > 0 {
                    weight = weight
                        .checked_add(current)
                        .ok_or("Signer weight overflow")?;
                    used.insert(*key);
                    if weight >= threshold {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        };
        // The source authorizes the transaction at LOW; Payment and InvokeHostFunction
        // then authorize this same account at MEDIUM. Neither check uses HIGH.
        if satisfies(source.low_threshold)?
            && satisfies(source.medium_threshold)?
            && used.len() == chosen.len()
        {
            return Ok(chosen.into_iter().map(str::to_owned).collect());
        }
    }
    Err("Current account cannot authorize this exact transaction with the supplied keys".into())
}
pub fn authorize(
    p: &PreparedOperation,
    signatures: &[DetachedSignature],
    now: u64,
) -> Result<SignedOperation> {
    validate_prepared(p, now)?;
    current_authorization_bounds(p)?;
    if p.config.route == WalletRoute::PolicyWallet {
        authorization::server_signature(p, true)?;
    }
    let required = automated_roles(&p.config);
    let aliased_roles = p.config.route == WalletRoute::Native && p.config.agent == p.config.server;
    if signatures.len() != required.len() && !(aliased_roles && signatures.len() == 2) {
        return Err("Exact automated signature quorum required".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut verified = std::collections::BTreeMap::new();
    for s in signatures {
        if !required.contains(&s.signer.as_str())
            || (!seen.insert(s.signer.clone()) && !aliased_roles)
        {
            return Err("Unexpected or duplicate signature".into());
        }
        let key = account_key(&s.signer)?;
        let sig: [u8; 64] = s
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length")?;
        VerifyingKey::from_bytes(&key)
            .map_err(err)?
            .verify_strict(&p.transaction_hash, &EdSignature::from_bytes(&sig))
            .map_err(err)?;
        verified.insert(
            s.signer.clone(),
            DecoratedSignature {
                hint: SignatureHint(key[28..].try_into().unwrap()),
                signature: stellar_xdr::Signature(sig.to_vec().try_into().map_err(err)?),
            },
        );
    }
    let candidates = required;
    let selected = transaction_signers(p, &candidates)?;
    let out: Vec<_> = selected
        .iter()
        .map(|key| {
            verified
                .get(key)
                .cloned()
                .ok_or("Missing selected role signature".to_string())
        })
        .collect::<Result<_>>()?;
    let TransactionEnvelope::Tx(mut env) = read(&p.transaction_xdr)? else {
        return Err("Unsupported transaction envelope".into());
    };
    env.signatures = out.try_into().map_err(err)?;
    Ok(SignedOperation {
        prepared: p.clone(),
        transaction_xdr: xdr(&TransactionEnvelope::Tx(env))?,
        transaction_hash: p.transaction_hash,
    })
}
pub fn validate_signed(s: &SignedOperation, now: u64) -> Result<()> {
    transfer_from_request(&s.prepared.config, &s.prepared.request)?;
    if s.prepared.state.contract_version == Some(1) && needs_native_preflight(&s.prepared.config)? {
        if s.prepared.created_at > now || now >= s.prepared.expires_at {
            return Err("Signed operation is stale".into());
        }
        validate_retained_signed(s)
    } else {
        validate_prepared(&s.prepared, now)?;
        validate_retained_signed(s)
    }
}
/// Verify an original signed packet without reauthorizing retired policy source.
/// Callers must compare their durable original identity and use it only for status/recovery.
pub fn validate_retained_signed(s: &SignedOperation) -> Result<()> {
    validate_retained_prepared(&s.prepared)?;
    if s.prepared.config.route == WalletRoute::PolicyWallet {
        authorization::server_signature(&s.prepared, true)?;
    }
    if s.transaction_hash != s.prepared.transaction_hash {
        return Err("Signed transaction identity differs".into());
    }
    let TransactionEnvelope::Tx(env) = read(&s.transaction_xdr)? else {
        return Err("Unsupported signed envelope".into());
    };
    let TransactionEnvelope::Tx(unsigned) = read(&s.prepared.transaction_xdr)? else {
        return Err("Unsupported unsigned envelope".into());
    };
    if env.tx != unsigned.tx {
        return Err("Signed transaction bytes differ".into());
    }
    let candidates = automated_roles(&s.prepared.config);
    let expected = transaction_signers(&s.prepared, &candidates)?;
    if env.signatures.len() != expected.len() {
        return Err("Signed transaction quorum differs".into());
    }
    let mut used = std::collections::BTreeSet::new();
    for sig in env.signatures.iter() {
        let mut matched = None;
        for signer in &expected {
            let key = account_key(signer)?;
            if sig.hint.0 == key[28..]
                && VerifyingKey::from_bytes(&key)
                    .map_err(err)?
                    .verify_strict(
                        &s.transaction_hash,
                        &EdSignature::from_slice(sig.signature.as_slice()).map_err(err)?,
                    )
                    .is_ok()
            {
                matched = Some((*signer).clone());
                break;
            }
        }
        let signer = matched.ok_or("Invalid transaction signature")?;
        if !used.insert(signer) {
            return Err("Duplicate transaction signer".into());
        }
    }
    Ok(())
}

/// Attach only RPC resource data. The exact invocation and authorization remain unchanged.
pub fn attach_simulation(p: &PreparedOperation, data: &str) -> Result<PreparedOperation> {
    if !matches!(p.config.route, WalletRoute::PolicyWallet | WalletRoute::Odc) {
        return Err("Resource data is only valid for policy wallet execution".into());
    }
    let resource: SorobanTransactionData = read(data)?;
    let required = u32::try_from(resource.resource_fee)
        .map_err(|_| "Invalid resource fee")?
        .checked_add(100)
        .ok_or("Resource fee overflow")?;
    if required > p.config.max_fee_stroops {
        return Err("Simulation resource fee exceeds approved fee bound".into());
    }
    let TransactionEnvelope::Tx(mut env) = read(&p.transaction_xdr)? else {
        return Err("Unsupported transaction envelope".into());
    };
    env.tx.ext = TransactionExt::V1(resource);
    env.tx.fee = required;
    let mut out = p.clone();
    out.transaction_hash = transaction_hash(&p.config.network, &env.tx)?;
    out.transaction_xdr = xdr(&TransactionEnvelope::Tx(env))?;
    out.simulation_data = Some(data.into());
    // An unsigned service entry has not established the final transaction hash.
    // Exact source-account quorum is checked after that entry is signed.
    if out.config.route != WalletRoute::PolicyWallet
        || authorization::server_signature(&out, false)? != ScVal::Void
    {
        transaction_signers(&out, &automated_roles(&out.config))?;
    }
    Ok(out)
}
