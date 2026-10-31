//! Archive-safe observations of the complete native spent namespace.
use crate::*;
use serde_json::json;

pub(crate) fn key(config: &WalletConfig) -> Result<LedgerKey> {
    Ok(LedgerKey::ContractData(LedgerKeyContractData {
        contract: address(&config.wallet)?,
        durability: ContractDataDurability::Persistent,
        key: ScVal::Vec(Some(
            vec![
                value_symbol("Spent")?,
                value_bytes(&config.policy_instance)?,
            ]
            .try_into()
            .map_err(err)?,
        )),
    }))
}
fn missing_is_live_none(
    rpc: &dyn rpc::Rpc,
    config: &WalletConfig,
    source: &AccountState,
) -> Result<()> {
    let response =
        rpc::readonly_simulation(rpc, config, source, &config.wallet, "policy_spent", vec![])?;
    if response
        .get("restorePreamble")
        .is_some_and(|value| !value.is_null())
    {
        return Err("Policy spent observation requires restoration".into());
    }
    if let Some(data) = response.get("transactionData") {
        let data: SorobanTransactionData =
            read(data.as_str().ok_or("Invalid spent observation resources")?)?;
        if matches!(data.ext,SorobanTransactionDataExt::V1(ref ext) if !ext.archived_soroban_entries.is_empty())
        {
            return Err("Policy spent observation includes archived entries".into());
        }
    }
    if rpc::readonly_result(&response)? != ScVal::Void {
        return Err("Missing ledger spent map differs from its native observation".into());
    }
    Ok(())
}
/// Read all native spent values for the installed stable policy identity.
/// `rpc` must serve `config.network`; `source` supplies an unsigned simulation account.
/// Missing data requires the native getter's successful None result. Archived data,
/// restoration requirements and inconsistent keys/types reject instead of becoming defaults.
/// This read does not sign, restore entries or submit a transaction.
pub fn read_spent(
    rpc: &dyn rpc::Rpc,
    config: &WalletConfig,
    source: &AccountState,
) -> Result<NativeValues> {
    validate_config(config)?;
    if config.route != WalletRoute::PolicyWallet {
        return Err("Native spent maps require policy wallet custody".into());
    }
    if rpc.call("getNetwork", json!({}))?["passphrase"] != passphrase(&config.network)? {
        return Err("Spent RPC network differs from installation".into());
    }
    let expected = key(config)?;
    let encoded = xdr(&expected)?;
    let response = rpc.call("getLedgerEntries", json!({"keys":[encoded]}))?;
    let ledger = response["latestLedger"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= u64::from(u32::MAX))
        .ok_or("Missing spent observation ledger")?;
    let entries = response["entries"]
        .as_array()
        .ok_or("Missing spent ledger entries")?;
    if entries.is_empty() {
        missing_is_live_none(rpc, config, source)?;
        return Ok(NativeValues::default());
    }
    if entries.len() != 1 {
        return Err("Unexpected spent ledger entry count".into());
    }
    let entry = &entries[0];
    if entry["key"].as_str() != Some(&encoded) {
        return Err("Spent ledger key differs from the policy namespace".into());
    }
    let ttl = entry["liveUntilLedgerSeq"]
        .as_u64()
        .ok_or("Missing spent lifetime")?;
    if ttl < ledger {
        return Err("Policy spent map is archived or expired".into());
    }
    let LedgerEntryData::ContractData(data) =
        read(entry["xdr"].as_str().ok_or("Missing spent XDR")?)?
    else {
        return Err("Wrong spent ledger entry type".into());
    };
    let LedgerKey::ContractData(expected) = expected else {
        unreachable!()
    };
    if data.contract != expected.contract
        || data.key != expected.key
        || data.durability != expected.durability
    {
        return Err("Spent ledger namespace differs".into());
    }
    NativeValues::from_value(&data.val)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct QueryRpc {
        config: WalletConfig,
        entries: Vec<serde_json::Value>,
        result: ScVal,
        restoration: bool,
        archived: bool,
    }
    impl rpc::Rpc for QueryRpc {
        fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
            if method == "getNetwork" {
                return Ok(json!({"passphrase":passphrase(&self.config.network)?}));
            }
            if method == "getLedgerEntries" {
                assert_eq!(params["keys"], json!([xdr(&key(&self.config)?)?]));
                return Ok(json!({"latestLedger":120,"entries":self.entries}));
            }
            assert_eq!(method, "simulateTransaction");
            let TransactionEnvelope::Tx(env) = read(params["transaction"].as_str().unwrap())?
            else {
                panic!()
            };
            assert!(env.signatures.is_empty());
            let OperationBody::InvokeHostFunction(op) = &env.tx.operations[0].body else {
                panic!()
            };
            assert!(op.auth.is_empty());
            let HostFunction::InvokeContract(call) = &op.host_function else {
                panic!()
            };
            assert_eq!(call.contract_address, address(&self.config.wallet)?);
            assert_eq!(call.function_name.0.as_slice(), b"policy_spent");
            assert!(call.args.is_empty());
            let mut response = json!({"results":[{"xdr":xdr(&self.result)?}]});
            if self.restoration {
                response["restorePreamble"] = json!({"transactionData":"restore"});
            }
            if self.archived {
                response["transactionData"] = json!(xdr(&SorobanTransactionData {
                    ext: SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
                        archived_soroban_entries: vec![0].try_into().unwrap()
                    }),
                    ..Default::default()
                })?);
            }
            Ok(response)
        }
    }
    fn setup() -> (QueryRpc, AccountState) {
        let source = AccountState {
            address: account_for_seed(&[2; 32]),
            sequence: 1,
            master_weight: 1,
            low_threshold: 1,
            medium_threshold: 1,
            high_threshold: 1,
            signers: vec![],
        };
        let policy_source="use allowit::v1::prelude::*; async fn _execute(ctx: &Context) -> PolicyResult { Ok(()) }".to_owned();
        let mut config = WalletConfig {
            network: "stellar:testnet".into(),
            policy_instance: [7; 32],
            wallet: Contract([4; 32]).to_string(),
            owner: account_for_seed(&[1; 32]),
            agent: source.address.clone(),
            server: account_for_seed(&[3; 32]),
            route: WalletRoute::PolicyWallet,
            policy_engine: Some(PolicyEngine::SimplePolicyEngine),
            asset: String::new(),
            asset_symbol: "XLM".into(),
            asset_issuer: None,
            source_hash: hash(&policy_source),
            policy_source,
            module_digest: [5; 32],
            max_fee_stroops: 50_000,
        };
        config.asset = sac_address(&config.network, &Asset::Native).unwrap();
        (
            QueryRpc {
                config,
                entries: vec![],
                result: ScVal::Void,
                restoration: false,
                archived: false,
            },
            source,
        )
    }
    fn entry(config: &WalletConfig, value: ScVal) -> serde_json::Value {
        let LedgerKey::ContractData(k) = key(config).unwrap() else {
            panic!()
        };
        json!({"key":xdr(&LedgerKey::ContractData(k.clone())).unwrap(),"liveUntilLedgerSeq":200,"xdr":xdr(&LedgerEntryData::ContractData(ContractDataEntry {ext:ExtensionPoint::V0,contract:k.contract,key:k.key,durability:k.durability,val:value})).unwrap()})
    }
    fn query(rpc: &QueryRpc, source: &AccountState) -> Result<NativeValues> {
        read_spent(rpc, &rpc.config, source)
    }
    fn values() -> NativeValues {
        NativeValues(std::collections::BTreeMap::from([
            ("large".into(), ScVal::U64(u64::MAX)),
            ("above_f64".into(), ScVal::U64(9_007_199_254_740_993)),
            ("custom_bytes".into(), value_bytes(&[1, 2, 3]).unwrap()),
            ("negative".into(), i128_value(-9)),
        ]))
    }
    #[test]
    fn arbitrary_values_and_exact_u64_survive_namespace_reads_and_json() {
        let (mut rpc, source) = setup();
        let expected = values();
        rpc.entries = vec![entry(&rpc.config, expected.value().unwrap())];
        assert_eq!(query(&rpc, &source).unwrap(), expected);
        assert_eq!(
            serde_json::from_value::<NativeValues>(serde_json::to_value(&expected).unwrap())
                .unwrap(),
            expected
        );
        let other = WalletConfig {
            policy_instance: [8; 32],
            ..rpc.config.clone()
        };
        assert_ne!(key(&other).unwrap(), key(&rpc.config).unwrap());
    }
    #[test]
    fn missing_default_requires_native_none_without_restoration() {
        let (mut rpc, source) = setup();
        assert!(query(&rpc, &source).unwrap().0.is_empty());
        rpc.result = values().value().unwrap();
        assert!(query(&rpc, &source).is_err());
        rpc.result = NativeValues::default().value().unwrap();
        assert!(query(&rpc, &source).is_err());
        rpc.result = ScVal::Void;
        rpc.restoration = true;
        assert!(query(&rpc, &source).is_err());
        rpc.restoration = false;
        rpc.archived = true;
        assert!(query(&rpc, &source).is_err());
    }
    #[test]
    fn archived_expired_malformed_or_duplicate_observations_reject() {
        let (mut rpc, source) = setup();
        let good = entry(&rpc.config, values().value().unwrap());
        for ttl in [0, 119] {
            let mut bad = good.clone();
            bad["liveUntilLedgerSeq"] = json!(ttl);
            rpc.entries = vec![bad];
            assert!(query(&rpc, &source).is_err());
        }
        let mut bad = good.clone();
        bad.as_object_mut().unwrap().remove("liveUntilLedgerSeq");
        rpc.entries = vec![bad];
        assert!(query(&rpc, &source).is_err());
        let other = WalletConfig {
            policy_instance: [99; 32],
            ..rpc.config.clone()
        };
        let mut bad = entry(&other, values().value().unwrap());
        bad["key"] = json!(xdr(&key(&rpc.config).unwrap()).unwrap());
        rpc.entries = vec![bad];
        assert!(query(&rpc, &source).is_err());
        rpc.entries = vec![good.clone(), good];
        assert!(query(&rpc, &source).is_err());
        rpc.entries = vec![entry(&rpc.config, ScVal::Bool(true))];
        assert!(query(&rpc, &source).is_err());
    }
}
