extern crate std;
use super::*;
use allowit_wallet_protocol::PolicyInvocation;
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    IntoVal, Map, TryIntoVal, contract, contractimpl,
    testutils::{Address as _, Ledger, MockAuth, MockAuthInvoke},
    token::StellarAssetClient,
    vec,
};
mod native {
    crate::policy_wallet!(Harness, crate::Common);
}
use native::HarnessClient as Client;
pub(super) const SIMPLE: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_simple_policy_engine.wasm");
pub(super) const COMMON: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_common_policy_engine.wasm");
pub(super) const CUSTOM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_custom_policy.wasm");

pub(super) struct Fixture {
    pub(super) env: Env,
    pub(super) wallet: Address,
    pub(super) owner: Address,
    pub(super) agent: Address,
    pub(super) server: Address,
    pub(super) asset: Address,
    pub(super) recipient: Address,
    akey: SigningKey,
    skey: SigningKey,
}
fn address(env: &Env, key: &SigningKey) -> Address {
    let mut bytes = Bytes::from_slice(env, &[0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.append(&Bytes::from_slice(env, &key.verifying_key().to_bytes()));
    Address::from_xdr(env, &bytes).unwrap()
}
impl Fixture {
    pub(super) fn new(wasm: &[u8], x402: bool) -> Self {
        Self::new_with_native(wasm, x402, false)
    }
    pub(super) fn new_native(wasm: &[u8]) -> Self {
        Self::new_with_native(wasm, false, true)
    }
    fn new_with_native(wasm: &[u8], x402: bool, native: bool) -> Self {
        let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.mock_all_auths_allowing_non_root_auth();
        env.ledger().with_mut(|l| {
            l.timestamp = 86_410;
            l.sequence_number = 100;
        });
        let owner = Address::generate(&env);
        let akey = SigningKey::from_bytes(&[7; 32]);
        let skey = SigningKey::from_bytes(&[8; 32]);
        let agent = if x402 {
            address(&env, &akey)
        } else {
            Address::generate(&env)
        };
        let server = if x402 {
            address(&env, &skey)
        } else {
            Address::generate(&env)
        };
        let recipient = Address::generate(&env);
        let asset = if native {
            use soroban_sdk::xdr as x;
            let created = env
                .host()
                .invoke_function(x::HostFunction::CreateContract(x::CreateContractArgs {
                    contract_id_preimage: x::ContractIdPreimage::Asset(x::Asset::Native),
                    executable: x::ContractExecutable::StellarAsset,
                }))
                .unwrap();
            Address::try_from_val(&env, &created).unwrap()
        } else {
            env.register_stellar_asset_contract_v2(Address::generate(&env))
                .address()
        };
        let grant = Grant {
            transaction_cap: Some(100),
            spent_cap: Some(250),
            day_spent_cap: Some(150),
            day_total_cap: Some(150),
            call_cap: Some(3),
            recipients: Some(vec![&env, recipient.clone()]),
            tokens: Some(vec![&env, asset.clone()]),
            expiry: Some(1_000_000),
        };
        let mut rules = Vec::new(&env);
        if wasm == COMMON {
            for rule in [
                Rule::recipients,
                Rule::tokens,
                Rule::transaction_cap,
                Rule::day_spent_cap,
                Rule::day_total_cap,
                Rule::spent_cap,
                Rule::call_cap,
                Rule::expiry,
            ] {
                rules.push_back(rule);
            }
        }
        let source_digest = if wasm == CUSTOM {
            env.crypto()
                .sha256(&Bytes::from_slice(
                    &env,
                    include_bytes!("../../custom-policy/policy/policy.rs"),
                ))
                .to_bytes()
        } else {
            let kind = if wasm == COMMON {
                "common_policy_engine"
            } else {
                "simple_policy_engine"
            };
            standard_prefix_digest(
                &env,
                &Symbol::new(&env, kind),
                &env.crypto()
                    .sha256(&Bytes::from_slice(&env, wasm))
                    .to_bytes(),
                &asset,
                &rules,
            )
        };
        let config = PolicyConfig {
            owner: owner.clone(),
            agent: agent.clone(),
            server: server.clone(),
            asset: asset.clone(),
            policy_instance: BytesN::from_array(&env, &[1; 32]),
            source_digest,
            rules,
            grant,
            x402_enabled: x402,
        };
        let wallet = env.register(wasm, (config,));
        if native {
            use soroban_sdk::xdr as x;
            let funding_key = SigningKey::from_bytes(&[44; 32]);
            let funder = address(&env, &funding_key);
            let account_id = x::AccountId(x::PublicKey::PublicKeyTypeEd25519(x::Uint256(
                funding_key.verifying_key().to_bytes(),
            )));
            let key = std::rc::Rc::new(x::LedgerKey::Account(x::LedgerKeyAccount {
                account_id: account_id.clone(),
            }));
            let entry = std::rc::Rc::new(x::LedgerEntry {
                data: x::LedgerEntryData::Account(x::AccountEntry {
                    account_id,
                    balance: 1_000_000_000,
                    flags: 0,
                    home_domain: Default::default(),
                    inflation_dest: None,
                    num_sub_entries: 0,
                    seq_num: x::SequenceNumber(0),
                    thresholds: x::Thresholds([1; 4]),
                    signers: Default::default(),
                    ext: x::AccountEntryExt::V0,
                }),
                last_modified_ledger_seq: 100,
                ext: x::LedgerEntryExt::V0,
            });
            env.host().add_ledger_entry(&key, &entry, None).unwrap();
            token::Client::new(&env, &asset).transfer(&funder, &wallet, &1_000);
        } else {
            StellarAssetClient::new(&env, &asset).mint(&wallet, &1_000);
        }
        env.mock_auths(&[]);
        Self {
            env,
            wallet,
            owner,
            agent,
            server,
            asset,
            recipient,
            akey,
            skey,
        }
    }
    pub(super) fn client(&self) -> Client<'_> {
        Client::new(&self.env, &self.wallet)
    }
    pub(super) fn execution(&self, amount: i128) -> ExecutionRequest {
        let s = self.client().state();
        let b = self.client().policy_binding();
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&(s.nonce + 1).to_be_bytes());
        ExecutionRequest {
            source_hash: if b.engine_kind == Symbol::new(&self.env, "custom_policy") {
                b.source_digest.clone()
            } else {
                BytesN::from_array(&self.env, &[9; 32])
            },
            expense: Some(
                ExpenseBounds {
                    asset: self.asset.clone(),
                    decimals: 7,
                    gas_units: 0,
                    conversion_units: 0,
                    spent_units: amount.max(0),
                    max_fee_stroops: 0,
                    observed_ledger: 1,
                    day: self.env.ledger().timestamp() / 86_400,
                }
                .to_xdr(&self.env),
            ),
            policy_instance: b.policy_instance,
            operation_id: BytesN::from_array(&self.env, &id),
            nonce: s.nonce,
            deployment_version: s.deployment_version,
            expires_at: self.env.ledger().timestamp() + 100,
            invocation: PolicyInvocation {
                module_digest: b.module_digest,
                entrypoint: b.entrypoint,
                argument_schema_digest: b.argument_schema_digest,
                arguments: Sep41TransferArgs {
                    token: self.asset.clone(),
                    from: self.wallet.clone(),
                    to: self.recipient.clone(),
                    amount,
                }
                .to_xdr(&self.env),
            },
        }
    }
    /// Execution for a module whose binding no longer resolves.
    fn execution_unbound(&self, amount: i128, module: &BytesN<32>) -> ExecutionRequest {
        let s = self.client().state();
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&(s.nonce + 1).to_be_bytes());
        ExecutionRequest {
            source_hash: BytesN::from_array(&self.env, &[9; 32]),
            expense: None,
            policy_instance: s.policy_instance,
            operation_id: BytesN::from_array(&self.env, &id),
            nonce: s.nonce,
            deployment_version: s.deployment_version,
            expires_at: self.env.ledger().timestamp() + 100,
            invocation: PolicyInvocation {
                module_digest: module.clone(),
                entrypoint: Symbol::new(&self.env, "execute"),
                argument_schema_digest: schema_digest(&self.env, ARGUMENT_SCHEMA_DESCRIPTOR),
                arguments: Sep41TransferArgs {
                    token: self.asset.clone(),
                    from: self.wallet.clone(),
                    to: self.recipient.clone(),
                    amount,
                }
                .to_xdr(&self.env),
            },
        }
    }
    pub(super) fn auth(&self, actors: &[&Address], method: &str, args: Vec<Val>) {
        let invoke = MockAuthInvoke {
            contract: &self.wallet,
            fn_name: method,
            args,
            sub_invokes: &[],
        };
        self.env.mock_auths(
            &actors
                .iter()
                .map(|actor| MockAuth {
                    address: actor,
                    invoke: &invoke,
                })
                .collect::<std::vec::Vec<_>>(),
        );
    }
    pub(super) fn transfer(&self, amount: i128) -> TransferReceipt {
        let e = self.execution(amount);
        self.auth(
            &[&self.agent, &self.server],
            "execute",
            (e.clone(),).into_val(&self.env),
        );
        self.client().execute(&e)
    }
    pub(super) fn history(&self) -> AccountingHistory {
        self.client().state().history
    }
    pub(super) fn balance(&self) -> i128 {
        token::Client::new(&self.env, &self.asset).balance(&self.wallet)
    }
    /// Exact raw encoding of a typed packet, for edits the typed client cannot express.
    pub(super) fn packet(&self, p: &PolicyDeployment) -> Map<Symbol, Val> {
        let raw: Val = p.clone().into_val(&self.env);
        Map::try_from_val(&self.env, &raw).unwrap()
    }
    /// Invoke deploy_policy with a raw packet that the owner authorized exactly as sent.
    pub(super) fn deploy_raw(&self, packet: Map<Symbol, Val>) -> bool {
        let args: Vec<Val> = (packet,).into_val(&self.env);
        self.auth(&[&self.owner], "deploy_policy", args.clone());
        self.env
            .try_invoke_contract::<(), Error>(
                &self.wallet,
                &Symbol::new(&self.env, "deploy_policy"),
                args,
            )
            .is_ok()
    }
    pub(super) fn deployment(&self) -> PolicyDeployment {
        let s = self.client().state();
        PolicyDeployment {
            deployment_version: s.deployment_version + 1,
            owner: s.owner,
            agent: s.agent,
            server: s.server,
            source_digest: s.source_digest,
            rules: s.rules,
            grant: s.grant,
            x402_enabled: s.x402_enabled,
            wasm_hash: None,
        }
    }
    fn authorization(
        &self,
        execution: ExecutionRequest,
        payload: &BytesN<32>,
    ) -> PolicyAuthorization {
        let digest = self.env.crypto().sha256(
            &(
                Symbol::new(&self.env, "allowit_wallet_v1"),
                payload.clone(),
                execution.clone(),
            )
                .to_xdr(&self.env),
        );
        PolicyAuthorization {
            execution,
            agent_signature: BytesN::from_array(
                &self.env,
                &self.akey.sign(&digest.to_array()).to_bytes(),
            ),
            server_signature: BytesN::from_array(
                &self.env,
                &self.skey.sign(&digest.to_array()).to_bytes(),
            ),
        }
    }
    fn host_entry(
        &self,
        execution: ExecutionRequest,
        amount: i128,
        nonce: i64,
    ) -> soroban_sdk::xdr::SorobanAuthorizationEntry {
        use soroban_sdk::xdr::{self, WriteXdr};
        let invocation: xdr::SorobanAuthorizedInvocation = (&MockAuthInvoke {
            contract: &self.asset,
            fn_name: "transfer",
            args: (self.wallet.clone(), self.recipient.clone(), amount).into_val(&self.env),
            sub_invokes: &[],
        })
            .into();
        let preimage =
            xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
                network_id: xdr::Hash(self.env.ledger().network_id().to_array()),
                nonce,
                signature_expiration_ledger: 100,
                invocation: invocation.clone(),
            });
        let payload = self
            .env
            .crypto()
            .sha256(&Bytes::from_slice(
                &self.env,
                &preimage.to_xdr(xdr::Limits::none()).unwrap(),
            ))
            .to_bytes();
        let signature: Val = self.authorization(execution, &payload).into_val(&self.env);
        xdr::SorobanAuthorizationEntry {
            credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                address: (&self.wallet).into(),
                nonce,
                signature_expiration_ledger: 100,
                signature: signature.try_into_val(&self.env).unwrap(),
            }),
            root_invocation: invocation,
        }
    }
}
#[test]
fn simple_requires_both_signers_and_does_not_infer_rules_from_grant() {
    let f = Fixture::new(SIMPLE, false);
    let e = f.execution(200);
    for actors in [&[&f.agent][..], &[&f.server][..], &[&f.owner][..], &[][..]] {
        f.auth(actors, "execute", (e.clone(),).into_val(&f.env));
        assert!(f.client().try_execute(&e).is_err());
        assert_eq!(f.balance(), 1_000);
        assert_eq!(f.client().state().nonce, 0);
    }
    assert_eq!(f.transfer(200).amount, 200);
    assert_eq!(f.balance(), 800);
    assert_eq!(f.history().calls, 1);
    assert_eq!(
        f.client().policy_binding().engine_kind,
        Symbol::new(&f.env, "simple_policy_engine")
    );
}
#[test]
fn common_rules_bound_transfers_and_commit_usage_once() {
    let f = Fixture::new(COMMON, false);
    f.transfer(100);
    f.transfer(50);
    assert_eq!(f.history().day_spent, 150);
    assert_eq!(f.history().spent, 150);
    assert_eq!(f.history().calls, 2);
    let before = f.history();
    let e = f.execution(1);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    assert_eq!(f.client().try_execute(&e), Err(Ok(Error::PolicyDenied)));
    assert_eq!(f.history(), before);
    assert_eq!(f.client().state().nonce, 2);
    f.env.ledger().with_mut(|l| l.timestamp = 172_800);
    f.transfer(100);
    assert_eq!(f.history().day_spent, 100);
    assert_eq!(f.history().spent, 250);
}
#[test]
fn common_skips_unset_parameters_and_rejects_unknown_names_or_negative_caps() {
    let f = Fixture::new(COMMON, false);
    // Soroban decodes vector elements when read. The packet binds a digest over the raw rules, so
    // only the kernel's element decoding rejects them before they are stored.
    let module = f.env.crypto().sha256(&Bytes::from_slice(&f.env, COMMON));
    let kind = Symbol::new(&f.env, "common_policy_engine");
    let packet = |rule: Val, grant: Option<(&str, Val)>| {
        let rules: Val = vec![&f.env, rule].into_val(&f.env);
        let lazy = Vec::<Rule>::try_from_val(&f.env, &rules).unwrap();
        let digest = standard_prefix_digest(&f.env, &kind, &module.to_bytes(), &f.asset, &lazy);
        let mut packet = f.packet(&f.deployment());
        packet.set(Symbol::new(&f.env, "rules"), rules);
        packet.set(
            Symbol::new(&f.env, "source_digest"),
            digest.into_val(&f.env),
        );
        if let Some((name, value)) = grant {
            let raw = packet.get(Symbol::new(&f.env, "grant")).unwrap();
            let mut fields = Map::<Symbol, Val>::try_from_val(&f.env, &raw).unwrap();
            fields.set(Symbol::new(&f.env, name), value);
            packet.set(Symbol::new(&f.env, "grant"), fields.into_val(&f.env));
        }
        packet
    };
    let deploy = |packet: Map<Symbol, Val>| {
        let args: Vec<Val> = (packet,).into_val(&f.env);
        f.auth(&[&f.owner], "deploy_policy", args.clone());
        let deploy_policy = Symbol::new(&f.env, "deploy_policy");
        let result = f
            .env
            .try_invoke_contract::<(), Error>(&f.wallet, &deploy_policy, args);
        assert_eq!(f.client().state().deployment_version, 0);
        result
    };
    // A malformed rule element or allowlist element is InvalidGrant.
    let junk: Val = 5u32.into_val(&f.env);
    let recipient: Val = vec![&f.env, Symbol::new(&f.env, "recipients")].into_val(&f.env);
    let junk_list: Val = vec![&f.env, junk].into_val(&f.env);
    for raw in [
        packet(junk, None),
        packet(recipient, Some(("recipients", junk_list))),
        packet(recipient, Some(("tokens", junk_list))),
    ] {
        assert_eq!(deploy(raw), Err(Ok(Error::InvalidGrant)));
    }
    // A name outside the enum aborts in the host's symbol lookup.
    for name in [
        "unknown",
        "daily_cap",
        "total_cap",
        "recipient",
        "token",
        "set_cap_per_day",
        "cap_per_transaction",
        "require_recipient",
        "require_asset",
        "allow_actions",
        "state_remove",
        "fail",
    ] {
        let rule: Val = vec![&f.env, Symbol::new(&f.env, name)].into_val(&f.env);
        assert!(deploy(packet(rule, None)).is_err());
    }
    for field in 0..4 {
        let mut p = f.deployment();
        *[
            &mut p.grant.transaction_cap,
            &mut p.grant.spent_cap,
            &mut p.grant.day_spent_cap,
            &mut p.grant.day_total_cap,
        ][field] = Some(-1);
        f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
        assert_eq!(
            f.client().try_deploy_policy(&p),
            Err(Ok(Error::InvalidGrant))
        );
    }
    let mut p = f.deployment();
    p.grant = Grant::default();
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    assert_eq!(f.client().state().grant, Grant::default());
    // Every selected rule is skipped by the standard preflight when its field is unset.
    assert_eq!(f.transfer(500).amount, 500);
    // The same raw path stores a known rule.
    assert!(f.deploy_raw(packet(recipient, None)));
    assert_eq!(f.client().state().rules, vec![&f.env, Rule::recipients]);
}
#[test]
fn custom_policy_denies_an_unset_grant_field_that_common_preflight_skips() {
    for wasm in [COMMON, CUSTOM] {
        let f = Fixture::new(wasm, false);
        let mut p = f.deployment();
        p.grant.expiry = None;
        f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
        f.client().deploy_policy(&p);
        let e = f.execution(10);
        f.auth(
            &[&f.agent, &f.server],
            "execute",
            (e.clone(),).into_val(&f.env),
        );
        if wasm == CUSTOM {
            assert_eq!(f.client().try_execute(&e), Err(Ok(Error::InvalidGrant)));
            assert_eq!(f.history(), AccountingHistory::default());
        } else {
            f.client().execute(&e);
            assert_eq!(f.history().calls, 1);
        }
    }
}
#[test]
fn untyped_or_legacy_grant_packets_do_not_decode() {
    use soroban_sdk::Map;
    let f = Fixture::new(COMMON, false);
    let p = f.deployment();
    let mut legacy = Map::<String, Val>::new(&f.env);
    legacy.set(
        String::from_str(&f.env, "per_transfer"),
        10i128.into_val(&f.env),
    );
    let typed: Val = p.grant.clone().into_val(&f.env);
    let mut fields = Map::<Symbol, Val>::try_from_val(&f.env, &typed).unwrap();
    fields.set(Symbol::new(&f.env, "call_cap"), true.into_val(&f.env));
    let packet: Val = p.clone().into_val(&f.env);
    for grant in [legacy.into_val(&f.env), fields.into_val(&f.env)] {
        let mut raw = Map::<Symbol, Val>::try_from_val(&f.env, &packet).unwrap();
        raw.set(Symbol::new(&f.env, "grant"), grant);
        let args: Vec<Val> = (raw,).into_val(&f.env);
        f.auth(&[&f.owner], "deploy_policy", args.clone());
        assert!(
            f.env
                .try_invoke_contract::<(), Error>(
                    &f.wallet,
                    &Symbol::new(&f.env, "deploy_policy"),
                    args
                )
                .is_err()
        );
        assert_eq!(f.client().state().deployment_version, 0);
    }
}
#[test]
fn owner_signs_the_canonical_packet_so_absent_or_extra_keys_reject() {
    let f = Fixture::new(COMMON, false);
    let p = f.deployment();
    let grant = |edit: &dyn Fn(&mut Map<Symbol, Val>)| {
        let mut packet = f.packet(&p);
        let typed: Val = p.grant.clone().into_val(&f.env);
        let mut fields = Map::<Symbol, Val>::try_from_val(&f.env, &typed).unwrap();
        edit(&mut fields);
        packet.set(Symbol::new(&f.env, "grant"), fields.into_val(&f.env));
        packet
    };
    let legacy = |fields: &mut Map<Symbol, Val>| {
        fields.set(Symbol::new(&f.env, "per_transfer"), 5i128.into_val(&f.env))
    };
    let mut extra_top = f.packet(&p);
    extra_top.set(Symbol::new(&f.env, "per_transfer"), 5i128.into_val(&f.env));
    let mut absent_top = f.packet(&p);
    absent_top.remove(Symbol::new(&f.env, "wasm_hash"));
    for packet in [
        // A legacy name beside an absent typed field would decode as an unset cap.
        grant(&|fields| {
            fields.remove(Symbol::new(&f.env, "transaction_cap"));
            legacy(fields);
        }),
        grant(&legacy),
        grant(&|fields| {
            fields.remove(Symbol::new(&f.env, "expiry"));
        }),
        extra_top,
        absent_top,
    ] {
        assert!(!f.deploy_raw(packet));
        assert_eq!(f.client().state().deployment_version, 0);
        assert_eq!(f.client().state().grant, p.grant);
    }
    // The canonical raw packet passes through the same path.
    assert!(f.deploy_raw(f.packet(&p)));
    assert_eq!(f.client().state().deployment_version, 1);
}
#[test]
fn custom_sample_executes_compiled_initial_rule_prefix() {
    let f = Fixture::new(CUSTOM, false);
    f.transfer(20);
    f.transfer(30);
    assert_eq!(f.history().day_spent, 50);
    assert_eq!(f.history().spent, 50);
    assert_eq!(f.history().calls, 2);
    assert_eq!(
        f.client().policy_binding().engine_kind,
        Symbol::new(&f.env, "custom_policy")
    );
}
#[test]
fn exact_request_replay_pause_and_expiry_are_independent_of_business_rules() {
    let f = Fixture::new(SIMPLE, false);
    let e = f.execution(1);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    f.client().execute(&e);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    assert_eq!(f.client().try_execute(&e), Err(Ok(Error::Replay)));
    let mut bad = f.execution(1);
    bad.expires_at = f.env.ledger().timestamp();
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (bad.clone(),).into_val(&f.env),
    );
    assert_eq!(f.client().try_execute(&bad), Err(Ok(Error::Expired)));
    f.auth(&[&f.owner], "set_pause", (true, 1u64).into_val(&f.env));
    f.client().set_pause(&true, &1);
    let next = f.execution(1);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (next.clone(),).into_val(&f.env),
    );
    assert_eq!(f.client().try_execute(&next), Err(Ok(Error::Paused)));
    f.auth(
        &[&f.owner],
        "recover",
        (f.recipient.clone(), 10i128).into_val(&f.env),
    );
    f.client().recover(&f.recipient, &10);
    assert_eq!(f.balance(), 989);
}
#[test]
fn owner_packet_requires_current_and_candidate_authorization_and_preserves_usage() {
    let f = Fixture::new(COMMON, false);
    f.transfer(10);
    let before = f.history();
    let next = Address::generate(&f.env);
    let mut p = f.deployment();
    p.owner = next.clone();
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    assert!(f.client().try_deploy_policy(&p).is_err());
    f.auth(
        &[&f.owner, &next],
        "deploy_policy",
        (p.clone(),).into_val(&f.env),
    );
    f.client().deploy_policy(&p);
    assert_eq!(f.client().state().owner, next);
    assert_eq!(f.history(), before);
    assert_eq!(f.client().state().nonce, 1);
    f.auth(&[&next], "deploy_policy", (p.clone(),).into_val(&f.env));
    assert_eq!(
        f.client().try_deploy_policy(&p),
        Err(Ok(Error::StaleRequest))
    );
}
#[test]
fn real_x402_requires_both_signatures_and_commits_with_native_effects() {
    for wasm in [SIMPLE, COMMON, CUSTOM] {
        let f = Fixture::new(wasm, true);
        let e = f.execution(10);
        let entry = f.host_entry(e.clone(), 10, 1);
        f.env.set_auths(core::slice::from_ref(&entry));
        token::Client::new(&f.env, &f.asset).transfer(&f.wallet, &f.recipient, &10);
        assert_eq!(f.balance(), 990);
        assert_eq!(f.client().state().nonce, 1);
        f.env.set_auths(&[f.host_entry(e.clone(), 10, 2)]);
        assert!(
            token::Client::new(&f.env, &f.asset)
                .try_transfer(&f.wallet, &f.recipient, &10)
                .is_err()
        );
        assert_eq!(f.balance(), 990);
        let mut bad = f.host_entry(f.execution(10), 10, 3);
        if let soroban_sdk::xdr::SorobanCredentials::Address(ref mut credential) = bad.credentials {
            let mut auth: PolicyAuthorization =
                PolicyAuthorization::try_from_val(&f.env, &credential.signature).unwrap();
            auth.server_signature = BytesN::from_array(&f.env, &[0; 64]);
            let raw: Val = auth.into_val(&f.env);
            credential.signature = raw.try_into_val(&f.env).unwrap();
        }
        f.env.set_auths(&[bad]);
        assert!(
            token::Client::new(&f.env, &f.asset)
                .try_transfer(&f.wallet, &f.recipient, &10)
                .is_err()
        );
        assert_eq!(f.balance(), 990);
    }
}
#[test]
fn failed_native_transfer_rolls_back_spent_nonce_and_operation_marker() {
    let f = Fixture::new(SIMPLE, true);
    let e = f.execution(2_000);
    f.env.set_auths(&[f.host_entry(e.clone(), 2_000, 1)]);
    assert!(
        token::Client::new(&f.env, &f.asset)
            .try_transfer(&f.wallet, &f.recipient, &2_000)
            .is_err()
    );
    assert_eq!(f.client().state().nonce, 0);
    assert_eq!(f.balance(), 1_000);
    f.env.mock_all_auths();
    StellarAssetClient::new(&f.env, &f.asset).mint(&f.wallet, &2_000);
    f.env.set_auths(&[f.host_entry(e, 2_000, 2)]);
    token::Client::new(&f.env, &f.asset).transfer(&f.wallet, &f.recipient, &2_000);
    assert_eq!(f.client().state().nonce, 1);
}
#[contract]
struct Forwarder;
#[contractimpl]
impl Forwarder {
    pub fn send(env: Env, asset: Address, from: Address, to: Address, amount: i128) {
        token::Client::new(&env, &asset).transfer(&from, &to, &amount);
    }
}
#[test]
fn owner_passthrough_supports_exact_nested_auth_without_agent_access() {
    use soroban_sdk::auth::{ContractContext, SubContractInvocation};
    let f = Fixture::new(COMMON, false);
    let forwarder = f.env.register(Forwarder, ());
    let function = Symbol::new(&f.env, "send");
    let args: Vec<Val> = (
        f.asset.clone(),
        f.wallet.clone(),
        f.recipient.clone(),
        200i128,
    )
        .into_val(&f.env);
    let auth = vec![
        &f.env,
        InvokerContractAuthEntry::Contract(SubContractInvocation {
            context: ContractContext {
                contract: f.asset.clone(),
                fn_name: Symbol::new(&f.env, "transfer"),
                args: (f.wallet.clone(), f.recipient.clone(), 200i128).into_val(&f.env),
            },
            sub_invocations: Vec::new(&f.env),
        }),
    ];
    let owner_args: Vec<Val> = (
        forwarder.clone(),
        function.clone(),
        args.clone(),
        auth.clone(),
    )
        .into_val(&f.env);
    f.auth(&[&f.agent, &f.server], "invoke", owner_args.clone());
    assert!(
        f.client()
            .try_invoke(&forwarder, &function, &args, &auth)
            .is_err()
    );
    f.auth(&[&f.owner], "invoke", owner_args);
    f.client().invoke(&forwarder, &function, &args, &auth);
    assert_eq!(f.balance(), 800);
    assert_eq!(f.client().state().nonce, 0);
    assert_eq!(f.history(), AccountingHistory::default());
    let changed: Vec<Val> = (
        f.asset.clone(),
        f.wallet.clone(),
        f.recipient.clone(),
        201i128,
    )
        .into_val(&f.env);
    f.auth(
        &[&f.owner],
        "invoke",
        (
            forwarder.clone(),
            function.clone(),
            changed.clone(),
            auth.clone(),
        )
            .into_val(&f.env),
    );
    assert!(
        f.client()
            .try_invoke(&forwarder, &function, &changed, &auth)
            .is_err()
    );
    assert_eq!(f.balance(), 800);
}
#[test]
fn owner_upgrades_exact_code_without_server_and_preserves_state() {
    let f = Fixture::new(SIMPLE, false);
    let mut bytes = Bytes::from_slice(&f.env, SIMPLE);
    bytes.append(&Bytes::from_slice(&f.env, &[0, 2, 1, b'x']));
    let hash = f.env.deployer().upload_contract_wasm(bytes);
    let mut p = f.deployment();
    p.wasm_hash = Some(hash.clone());
    p.source_digest = standard_prefix_digest(
        &f.env,
        &Symbol::new(&f.env, "simple_policy_engine"),
        &hash,
        &f.asset,
        &p.rules,
    );
    f.auth(
        &[&f.agent, &f.server],
        "deploy_policy",
        (p.clone(),).into_val(&f.env),
    );
    assert!(f.client().try_deploy_policy(&p).is_err());
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    assert_eq!(f.client().policy_binding().module_digest, hash);
    assert_eq!(f.client().state().deployment_version, 1);
    assert_eq!(f.balance(), 1_000);
}

#[test]
fn request_bindings_reject_changed_fields_and_unexpected_effects() {
    let f = Fixture::new(SIMPLE, false);
    let e = f.execution(10);
    for field in 0..14 {
        let mut bad = e.clone();
        match field {
            0 => bad.policy_instance = BytesN::from_array(&f.env, &[3; 32]),
            1 => bad.invocation.module_digest = BytesN::from_array(&f.env, &[3; 32]),
            2 => bad.invocation.argument_schema_digest = BytesN::from_array(&f.env, &[3; 32]),
            3 => bad.invocation.entrypoint = Symbol::new(&f.env, "other"),
            4 => bad.nonce += 1,
            5 => bad.deployment_version += 1,
            7 => bad.operation_id = BytesN::from_array(&f.env, &[0; 32]),
            8 => bad
                .invocation
                .arguments
                .append(&Bytes::from_array(&f.env, &[0; 4])),
            9 => {
                bad.invocation.arguments =
                    Bytes::from_slice(&f.env, &std::vec![0; MAX_ARGUMENT_BYTES as usize + 1])
            }
            _ => {
                let mut args =
                    Sep41TransferArgs::from_xdr(&f.env, &bad.invocation.arguments).unwrap();
                match field {
                    6 => args.from = f.recipient.clone(),
                    10 => args.token = f.recipient.clone(),
                    11 => args.to = f.wallet.clone(),
                    12 => args.amount = 0,
                    _ => args.amount = -1,
                }
                bad.invocation.arguments = args.to_xdr(&f.env);
            }
        }
        f.auth(
            &[&f.agent, &f.server],
            "execute",
            (bad.clone(),).into_val(&f.env),
        );
        assert!(f.client().try_execute(&bad).is_err());
        assert_eq!(f.balance(), 1_000);
        assert_eq!(f.client().state().nonce, 0);
    }
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    let mut changed = e;
    let mut args = Sep41TransferArgs::from_xdr(&f.env, &changed.invocation.arguments).unwrap();
    args.amount = 11;
    changed.invocation.arguments = args.to_xdr(&f.env);
    assert!(f.client().try_execute(&changed).is_err());
    assert_eq!(f.balance(), 1_000);
}

#[test]
fn custom_source_and_unknown_storage_layout_reject() {
    let f = Fixture::new(CUSTOM, false);
    let mut p = f.deployment();
    p.source_digest = BytesN::from_array(&f.env, &[5; 32]);
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    assert_eq!(
        f.client().try_deploy_policy(&p),
        Err(Ok(Error::InvalidState))
    );
    let original: State = f.client().state();
    let extra = Symbol::new(&f.env, "per_transfer");
    for case in 0..5 {
        f.env.as_contract(&f.wallet, || {
            let mut raw: Map<Symbol, Val> = f.env.storage().instance().get(&STATE_KEY).unwrap();
            let nested = |name: &str| {
                let key = Symbol::new(&f.env, name);
                let mut inner = Map::<Symbol, Val>::try_from_val(&f.env, &raw.get(key).unwrap());
                let inner = inner.as_mut().unwrap();
                inner.set(extra.clone(), 5i128.into_val(&f.env));
                inner.clone()
            };
            match case {
                0 => {
                    raw.remove(Symbol::new(&f.env, "server"));
                }
                1 => raw.set(extra.clone(), 5i128.into_val(&f.env)),
                2 => raw.set(
                    Symbol::new(&f.env, "grant"),
                    nested("grant").into_val(&f.env),
                ),
                3 => raw.set(
                    Symbol::new(&f.env, "history"),
                    nested("history").into_val(&f.env),
                ),
                // A legacy empty Grant map would otherwise decode as an all-unset typed Grant.
                _ => raw.set(
                    Symbol::new(&f.env, "grant"),
                    Map::<Symbol, Val>::new(&f.env).into_val(&f.env),
                ),
            }
            f.env.storage().instance().set(&STATE_KEY, &raw);
        });
        assert_eq!(f.client().try_state(), Err(Ok(Error::InvalidState)));
        f.env.as_contract(&f.wallet, || {
            f.env.storage().instance().set(&STATE_KEY, &original)
        });
        assert_eq!(f.client().state(), original);
    }
}

/// Version 1 layout: untyped Grant map and symbol rules.
#[contracttype]
#[derive(Clone)]
struct LegacyState {
    history: AccountingHistory,
    contract_version: u32,
    owner: Address,
    agent: Address,
    server: Address,
    asset: Address,
    policy_instance: BytesN<32>,
    source_digest: BytesN<32>,
    rules: Vec<Symbol>,
    grant: Map<String, Val>,
    x402_enabled: bool,
    token: String,
    deployment_version: u64,
    nonce: u64,
    paused: bool,
}

#[test]
fn upgraded_legacy_layout_keeps_owner_recovery_and_accepts_a_typed_owner_packet() {
    let f = Fixture::new(COMMON, false);
    f.transfer(10);
    let current = f.client().state();
    let mut grant = Map::<String, Val>::new(&f.env);
    grant.set(
        String::from_str(&f.env, "transaction_cap"),
        5i128.into_val(&f.env),
    );
    let mut legacy = LegacyState {
        history: current.history.clone(),
        contract_version: 1,
        owner: current.owner.clone(),
        agent: current.agent.clone(),
        server: current.server.clone(),
        asset: current.asset.clone(),
        policy_instance: current.policy_instance.clone(),
        source_digest: current.source_digest.clone(),
        rules: vec![&f.env, Symbol::new(&f.env, "transaction_cap")],
        grant,
        x402_enabled: false,
        token: current.token.clone(),
        deployment_version: current.deployment_version,
        nonce: current.nonce,
        paused: false,
    };
    let install = |state: &LegacyState| {
        f.env.as_contract(&f.wallet, || {
            f.env.storage().instance().set(&STATE_KEY, state)
        })
    };
    install(&legacy);
    // The state written by an in-place upgrade from a version 1 release does not decode.
    assert!(f.client().try_state().is_err());
    // Only the owner recovers funds from it.
    f.auth(
        &[&f.agent],
        "recover",
        (f.recipient.clone(), 7i128).into_val(&f.env),
    );
    assert!(f.client().try_recover(&f.recipient, &7).is_err());
    f.auth(
        &[&f.owner],
        "recover",
        (f.recipient.clone(), 7i128).into_val(&f.env),
    );
    f.client().recover(&f.recipient, &7);
    assert_eq!(f.balance(), 983);
    // A complete owner packet replaces Grant and rules and keeps history and nonce.
    let p = PolicyDeployment {
        deployment_version: current.deployment_version + 1,
        owner: current.owner.clone(),
        agent: current.agent.clone(),
        server: current.server.clone(),
        source_digest: current.source_digest.clone(),
        rules: current.rules.clone(),
        grant: current.grant.clone(),
        x402_enabled: false,
        wasm_hash: None,
    };
    // Struct decoding would ignore an extra history key. Only canonical history carries over.
    f.env.as_contract(&f.wallet, || {
        let encoded: Val = legacy.clone().into_val(&f.env);
        let mut raw = Map::<Symbol, Val>::try_from_val(&f.env, &encoded).unwrap();
        let key = Symbol::new(&f.env, "history");
        let mut history =
            Map::<Symbol, Val>::try_from_val(&f.env, &raw.get(key.clone()).unwrap()).unwrap();
        history.set(Symbol::new(&f.env, "per_transfer"), 5i128.into_val(&f.env));
        raw.set(key, history.into_val(&f.env));
        f.env.storage().instance().set(&STATE_KEY, &raw);
    });
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    assert_eq!(
        f.client().try_deploy_policy(&p),
        Err(Ok(Error::InvalidState))
    );
    install(&legacy);
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    let migrated = f.client().state();
    assert_eq!(migrated.contract_version, CONTRACT_VERSION);
    assert_eq!(migrated.history, current.history);
    assert_eq!(migrated.nonce, current.nonce);
    assert_eq!(migrated.grant, current.grant);
    f.transfer(10);
    assert_eq!(f.history().calls, 2);
    // A later layout may change kept fields, so even owner recovery rejects it.
    legacy.contract_version = CONTRACT_VERSION + 1;
    install(&legacy);
    f.auth(
        &[&f.owner],
        "recover",
        (f.recipient.clone(), 1i128).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_recover(&f.recipient, &1),
        Err(Ok(Error::InvalidState))
    );
}

#[test]
fn constructor_state_reads_and_operation_receipts_maintain_full_lifetimes() {
    use soroban_sdk::testutils::{Deployer as _, storage::Persistent as _};
    let f = Fixture::new(COMMON, false);
    let max = f.env.storage().max_ttl();
    assert_eq!(f.env.deployer().get_contract_instance_ttl(&f.wallet), max);
    assert_eq!(f.env.deployer().get_contract_code_ttl(&f.wallet), max);
    f.env
        .ledger()
        .with_mut(|l| l.sequence_number += max / 2 + 1);
    f.client().state();
    assert_eq!(f.env.deployer().get_contract_instance_ttl(&f.wallet), max);
    let receipt = f.transfer(1);
    let key = Key::Operation(receipt.operation_id);
    assert_eq!(
        f.env
            .as_contract(&f.wallet, || f.env.storage().persistent().get_ttl(&key)),
        max
    );
}

#[contract]
struct Constructor;
#[contractimpl]
impl Constructor {
    pub fn deploy(env: Env, wasm: BytesN<32>, config: PolicyConfig) -> Address {
        env.deployer()
            .with_current_contract(BytesN::from_array(&env, &[0; 32]))
            .deploy_contract(soroban_sdk::ContractExecutable::Wasm(wasm), (config,))
    }
    /// Deploy with an exact raw packet, for edits the typed config cannot express.
    pub fn deploy_raw(env: Env, wasm: BytesN<32>, config: Map<Symbol, Val>) -> Address {
        env.deployer()
            .with_current_contract(BytesN::from_array(&env, &[0; 32]))
            .deploy_contract(soroban_sdk::ContractExecutable::Wasm(wasm), (config,))
    }
}
#[test]
fn constructor_owner_signs_the_canonical_packet_so_absent_or_extra_keys_reject() {
    let f = Fixture::new(COMMON, false);
    let s = f.client().state();
    let config = PolicyConfig {
        owner: s.owner,
        agent: s.agent,
        server: s.server,
        asset: s.asset,
        policy_instance: s.policy_instance,
        source_digest: s.source_digest,
        rules: s.rules,
        grant: s.grant,
        x402_enabled: false,
    };
    let wasm = f.env.deployer().upload_contract_wasm(COMMON);
    let factory = f.env.register(Constructor, ());
    let salt = BytesN::from_array(&f.env, &[0; 32]);
    let wallet = f
        .env
        .deployer()
        .with_address(factory.clone(), salt)
        .deployed_address();
    let key = |name: &str| Symbol::new(&f.env, name);
    type Fields = Map<Symbol, Val>;
    let raw = |edit: &dyn Fn(&mut Fields, &mut Fields)| {
        let encoded: Val = config.clone().into_val(&f.env);
        let mut packet = Map::<Symbol, Val>::try_from_val(&f.env, &encoded).unwrap();
        let mut grant =
            Map::<Symbol, Val>::try_from_val(&f.env, &packet.get(key("grant")).unwrap()).unwrap();
        edit(&mut packet, &mut grant);
        packet.set(key("grant"), grant.into_val(&f.env));
        packet
    };
    // The owner authorizes exactly the raw packet sent.
    let deploy = |packet: Map<Symbol, Val>| {
        let args: Vec<Val> = (packet.clone(),).into_val(&f.env);
        f.env.mock_auths(&[MockAuth {
            address: &config.owner,
            invoke: &MockAuthInvoke {
                contract: &wallet,
                fn_name: "__constructor",
                args,
                sub_invokes: &[],
            },
        }]);
        ConstructorClient::new(&f.env, &factory)
            .try_deploy_raw(&wasm, &packet)
            .is_ok()
    };
    let legacy = |grant: &mut Map<Symbol, Val>| {
        grant.set(key("per_transfer"), 5i128.into_val(&f.env));
    };
    for packet in [
        // A legacy name beside an absent typed field would decode as an unset cap.
        raw(&|_, grant| {
            grant.remove(key("transaction_cap"));
            legacy(grant);
        }),
        raw(&|_, grant| legacy(grant)),
        raw(&|_, grant| {
            grant.remove(key("expiry"));
        }),
        raw(&|packet, _| packet.set(key("per_transfer"), 5i128.into_val(&f.env))),
    ] {
        assert!(!deploy(packet));
    }
    assert!(deploy(raw(&|_, _| {})));
    assert_eq!(Client::new(&f.env, &wallet).state().grant, config.grant);
}
#[test]
fn ordinary_compiled_deployment_requires_owner_authorization() {
    let f = Fixture::new(SIMPLE, false);
    let state = f.client().state();
    let wasm = f.env.deployer().upload_contract_wasm(SIMPLE);
    let constructor = f.env.register(Constructor, ());
    let config = PolicyConfig {
        owner: state.owner,
        agent: state.agent,
        server: state.server,
        asset: state.asset,
        policy_instance: state.policy_instance,
        source_digest: state.source_digest,
        rules: state.rules,
        grant: state.grant,
        x402_enabled: false,
    };
    f.env.mock_auths(&[]);
    assert!(
        ConstructorClient::new(&f.env, &constructor)
            .try_deploy(&wasm, &config)
            .is_err()
    );
}

fn transfer_context(f: &Fixture, amount: i128) -> Context {
    Context::Contract(soroban_sdk::auth::ContractContext {
        contract: f.asset.clone(),
        fn_name: Symbol::new(&f.env, "transfer"),
        args: (f.wallet.clone(), f.recipient.clone(), amount).into_val(&f.env),
    })
}

#[test]
fn x402_context_signatures_pause_and_enablement_fail_closed() {
    for case in 0..10 {
        let f = Fixture::new(SIMPLE, true);
        let payload = BytesN::from_array(&f.env, &[4; 32]);
        let mut auth = f.authorization(f.execution(10), &payload);
        let mut context = transfer_context(&f, 10);
        match case {
            0 => auth.agent_signature = BytesN::from_array(&f.env, &[0; 64]),
            1 => core::mem::swap(&mut auth.agent_signature, &mut auth.server_signature),
            2..=5 => {
                if let Context::Contract(ref mut c) = context {
                    match case {
                        2 => c.fn_name = Symbol::new(&f.env, "approve"),
                        3 => c.contract = Address::generate(&f.env),
                        4 => c.args = (f.wallet.clone(), f.wallet.clone(), 10i128).into_val(&f.env),
                        _ => {
                            c.args =
                                (f.wallet.clone(), f.recipient.clone(), 11i128).into_val(&f.env)
                        }
                    }
                }
            }
            7 => {
                let mut p = f.deployment();
                p.x402_enabled = false;
                f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
                f.client().deploy_policy(&p);
                auth = f.authorization(f.execution(10), &payload);
            }
            8 => {
                f.auth(&[&f.owner], "set_pause", (true, 1u64).into_val(&f.env));
                f.client().set_pause(&true, &1);
                auth = f.authorization(f.execution(10), &payload);
            }
            _ => (),
        }
        let contexts = if case == 6 {
            vec![&f.env, context.clone(), context]
        } else if case == 9 {
            Vec::new(&f.env)
        } else {
            vec![&f.env, context]
        };
        let result = f.env.try_invoke_contract_check_auth::<Error>(
            &f.wallet,
            &payload,
            auth.into_val(&f.env),
            &contexts,
        );
        match case {
            0 | 1 => assert_eq!(result, Err(Err(soroban_sdk::InvokeError::Abort))),
            2 | 3 | 7 => assert_eq!(result, Err(Ok(Error::UnsupportedOperation))),
            8 => assert_eq!(result, Err(Ok(Error::Paused))),
            _ => assert_eq!(result, Err(Ok(Error::InvalidInvocation))),
        }
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
}

#[test]
fn operation_replay_rejects_even_with_a_new_host_payload() {
    let f = Fixture::new(SIMPLE, true);
    let execution = f.execution(10);
    f.env.set_auths(&[f.host_entry(execution.clone(), 10, 1)]);
    token::Client::new(&f.env, &f.asset).transfer(&f.wallet, &f.recipient, &10);
    let payload = BytesN::from_array(&f.env, &[42; 32]);
    assert_eq!(
        f.env.try_invoke_contract_check_auth::<Error>(
            &f.wallet,
            &payload,
            f.authorization(execution, &payload).into_val(&f.env),
            &vec![&f.env, transfer_context(&f, 10)]
        ),
        Err(Ok(Error::Replay))
    );
    assert_eq!(f.client().state().nonce, 1);
}

/// A transfer execution to an arbitrary destination with its matching token context.
fn x402_request(f: &Fixture, to: &Address, amount: i128) -> (ExecutionRequest, Context) {
    let mut e = f.execution(amount);
    e.invocation.arguments = Sep41TransferArgs {
        token: f.asset.clone(),
        from: f.wallet.clone(),
        to: to.clone(),
        amount,
    }
    .to_xdr(&f.env);
    let context = Context::Contract(soroban_sdk::auth::ContractContext {
        contract: f.asset.clone(),
        fn_name: Symbol::new(&f.env, "transfer"),
        args: (f.wallet.clone(), to.clone(), amount).into_val(&f.env),
    });
    (e, context)
}

#[test]
fn x402_enforces_compiled_business_rules_without_committing() {
    for wasm in [COMMON, CUSTOM] {
        for case in 0..3 {
            let f = Fixture::new(wasm, true);
            let (to, amount, expected) = match case {
                0 => (f.recipient.clone(), 101, Error::PolicyDenied),
                1 => (Address::generate(&f.env), 10, Error::PolicyDenied),
                _ => {
                    let mut p = f.deployment();
                    p.grant.expiry = None;
                    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
                    f.client().deploy_policy(&p);
                    // Common preflight skips the unset field; Custom denies it.
                    let expected = if wasm == CUSTOM {
                        Error::InvalidGrant
                    } else {
                        Error::PolicyDenied
                    };
                    (
                        f.recipient.clone(),
                        if wasm == CUSTOM { 10 } else { 101 },
                        expected,
                    )
                }
            };
            let before = f.client().state();
            let payload = BytesN::from_array(&f.env, &[6; 32]);
            let (e, context) = x402_request(&f, &to, amount);
            assert_eq!(
                f.env.try_invoke_contract_check_auth::<Error>(
                    &f.wallet,
                    &payload,
                    f.authorization(e, &payload).into_val(&f.env),
                    &vec![&f.env, context],
                ),
                Err(Ok(expected))
            );
            assert_eq!(f.client().state(), before);
            assert_eq!(f.balance(), 1_000);
        }
        // Through a real host entry the token transfer itself fails.
        let f = Fixture::new(wasm, true);
        f.env.set_auths(&[f.host_entry(f.execution(101), 101, 1)]);
        assert!(
            token::Client::new(&f.env, &f.asset)
                .try_transfer(&f.wallet, &f.recipient, &101)
                .is_err()
        );
        assert_eq!(f.balance(), 1_000);
        assert_eq!(f.client().state().nonce, 0);
        assert_eq!(f.history(), AccountingHistory::default());
    }
}

#[test]
fn x402_binds_the_transfer_schema_and_its_canonical_arguments() {
    for wasm in [SIMPLE, COMMON] {
        for case in 0..2 {
            let f = Fixture::new(wasm, true);
            let payload = BytesN::from_array(&f.env, &[7; 32]);
            let (mut e, context) = x402_request(&f, &f.recipient, 10);
            if case == 0 {
                // Simple and Common admit the deposit profile, but never for a token transfer.
                e.invocation.argument_schema_digest = f
                    .env
                    .crypto()
                    .sha256(&Bytes::from_slice(
                        &f.env,
                        allowit_wallet_protocol::SEP56_DEPOSIT_SCHEMA_DESCRIPTOR,
                    ))
                    .to_bytes();
            } else {
                // Struct decoding ignores an extra key. Only the canonical encoding is accepted.
                let args = Sep41TransferArgs::from_xdr(&f.env, &e.invocation.arguments).unwrap();
                let raw: Val = args.into_val(&f.env);
                let mut fields = Map::<Symbol, Val>::try_from_val(&f.env, &raw).unwrap();
                fields.set(Symbol::new(&f.env, "zzz"), 1u32.into_val(&f.env));
                assert_eq!(
                    Sep41TransferArgs::from_xdr(&f.env, &fields.clone().to_xdr(&f.env)),
                    Ok(Sep41TransferArgs::from_xdr(&f.env, &e.invocation.arguments).unwrap())
                );
                e.invocation.arguments = fields.to_xdr(&f.env);
            }
            let result = f.env.try_invoke_contract_check_auth::<Error>(
                &f.wallet,
                &payload,
                f.authorization(e, &payload).into_val(&f.env),
                &vec![&f.env, context],
            );
            assert_eq!(result, Err(Ok(Error::InvalidInvocation)), "case {case}");
            assert_eq!(f.client().state().nonce, 0);
            assert_eq!(f.balance(), 1_000);
        }
    }
}

#[test]
fn x402_rejects_a_canonical_deposit_authorization_for_a_token_transfer() {
    for wasm in [SIMPLE, COMMON] {
        let f = Fixture::new(wasm, true);
        let payload = BytesN::from_array(&f.env, &[8; 32]);
        let (mut e, context) = x402_request(&f, &f.recipient, 10);
        // A raw transfer to the vault would mint no shares and charge no principal.
        e.invocation.argument_schema_digest =
            schema_digest(&f.env, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR);
        e.invocation.arguments = Sep56DepositArgs {
            vault: f.recipient.clone(),
            assets: 10,
            receiver: f.wallet.clone(),
            from: f.wallet.clone(),
            operator: f.wallet.clone(),
            min_shares: 10,
        }
        .to_xdr(&f.env);
        e.expense = Some(
            ExpenseBounds {
                asset: f.asset.clone(),
                decimals: 7,
                gas_units: 0,
                conversion_units: 0,
                spent_units: 0,
                max_fee_stroops: 0,
                observed_ledger: 1,
                day: f.env.ledger().timestamp() / 86_400,
            }
            .to_xdr(&f.env),
        );
        assert_eq!(
            f.env.try_invoke_contract_check_auth::<Error>(
                &f.wallet,
                &payload,
                f.authorization(e, &payload).into_val(&f.env),
                &vec![&f.env, context],
            ),
            Err(Ok(Error::UnsupportedOperation))
        );
        assert_eq!(f.client().state().nonce, 0);
        assert_eq!(f.history(), AccountingHistory::default());
    }
}

#[test]
fn upgraded_standard_wallet_must_rebind_its_prefix_to_the_new_module() {
    let f = Fixture::new(COMMON, false);
    let mut bytes = Bytes::from_slice(&f.env, COMMON);
    bytes.append(&Bytes::from_slice(&f.env, &[0, 2, 1, b'x']));
    let hash = f.env.deployer().upload_contract_wasm(bytes);
    // The upgrade packet keeps the digest bound to the old module.
    let mut p = f.deployment();
    p.wasm_hash = Some(hash.clone());
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    assert_eq!(
        f.client().try_policy_binding(),
        Err(Ok(Error::InvalidState))
    );
    let e = f.execution_unbound(10, &hash);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    assert_eq!(f.client().try_execute(&e), Err(Ok(Error::InvalidState)));
    assert_eq!(f.history(), AccountingHistory::default());
    let mut fixed = f.deployment();
    fixed.source_digest = standard_prefix_digest(
        &f.env,
        &Symbol::new(&f.env, "common_policy_engine"),
        &hash,
        &f.asset,
        &fixed.rules,
    );
    f.auth(
        &[&f.owner],
        "deploy_policy",
        (fixed.clone(),).into_val(&f.env),
    );
    f.client().deploy_policy(&fixed);
    assert_eq!(f.client().policy_binding().module_digest, hash);
    assert_eq!(f.transfer(10).amount, 10);
}

#[test]
fn upgraded_tiers_validate_retained_rules_and_owner_can_correct_configuration() {
    for target in [SIMPLE, CUSTOM, COMMON] {
        let f = Fixture::new(COMMON, false);
        let mut p = f.deployment();
        p.wasm_hash = Some(
            f.env
                .deployer()
                .upload_contract_wasm(Bytes::from_slice(&f.env, target)),
        );
        if target == CUSTOM {
            p.source_digest = f
                .env
                .crypto()
                .sha256(&Bytes::from_slice(
                    &f.env,
                    include_bytes!("../../custom-policy/policy/policy.rs"),
                ))
                .to_bytes();
        }
        if target == COMMON {
            p.grant.day_spent_cap = Some(-1);
        }
        if target == SIMPLE {
            p.source_digest = standard_prefix_digest(
                &f.env,
                &Symbol::new(&f.env, "simple_policy_engine"),
                p.wasm_hash.as_ref().unwrap(),
                &f.asset,
                &p.rules,
            );
        }
        f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
        if target == COMMON {
            assert_eq!(
                f.client().try_deploy_policy(&p),
                Err(Ok(Error::InvalidGrant))
            );
            f.transfer(10);
            continue;
        }
        f.client().deploy_policy(&p);
        let e = f.execution(10);
        f.auth(
            &[&f.agent, &f.server],
            "execute",
            (e.clone(),).into_val(&f.env),
        );
        assert_eq!(f.client().try_execute(&e), Err(Ok(Error::InvalidGrant)));
        let mut fixed = f.deployment();
        if target == COMMON {
            fixed.grant.day_spent_cap = Some(150);
        } else {
            fixed.rules = Vec::new(&f.env);
            if target == SIMPLE {
                let Some(Executable::Wasm(module)) = f.wallet.executable() else {
                    panic!("Expected Wasm")
                };
                fixed.source_digest = standard_prefix_digest(
                    &f.env,
                    &Symbol::new(&f.env, "simple_policy_engine"),
                    &module,
                    &f.asset,
                    &fixed.rules,
                );
            }
        }
        f.auth(
            &[&f.owner],
            "deploy_policy",
            (fixed.clone(),).into_val(&f.env),
        );
        f.client().deploy_policy(&fixed);
        f.transfer(10);
        assert_eq!(f.balance(), 990);
    }
}

#[test]
fn issuer_burn_destinations_reject_in_direct_recovery_and_x402() {
    for enabled in [false, true] {
        let mut f = Fixture::new(SIMPLE, enabled);
        let name = token::Client::new(&f.env, &f.asset).name();
        let mut bytes = std::vec![0u8; name.len() as usize];
        name.copy_into_slice(&mut bytes);
        let name = std::str::from_utf8(&bytes).unwrap();
        f.recipient =
            Address::from_string(&String::from_str(&f.env, name.rsplit(':').next().unwrap()));
        let e = f.execution(10);
        if enabled {
            let payload = BytesN::from_array(&f.env, &[77; 32]);
            assert_eq!(
                f.env.try_invoke_contract_check_auth::<Error>(
                    &f.wallet,
                    &payload,
                    f.authorization(e.clone(), &payload).into_val(&f.env),
                    &vec![&f.env, transfer_context(&f, 10)]
                ),
                Err(Ok(Error::InvalidRecipient))
            );

            f.env.set_auths(&[f.host_entry(e, 10, 1)]);
            assert!(
                token::Client::new(&f.env, &f.asset)
                    .try_transfer(&f.wallet, &f.recipient, &10)
                    .is_err()
            );
        } else {
            f.auth(
                &[&f.agent, &f.server],
                "execute",
                (e.clone(),).into_val(&f.env),
            );
            assert_eq!(f.client().try_execute(&e), Err(Ok(Error::InvalidRecipient)));
            f.auth(
                &[&f.owner],
                "recover",
                (f.recipient.clone(), 10i128).into_val(&f.env),
            );
            assert_eq!(
                f.client().try_recover(&f.recipient, &10),
                Err(Ok(Error::InvalidRecipient))
            );
        }
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
}

#[test]
fn issuer_identity_decodes_real_sac_symbols_and_rejects_malformed_cache() {
    let f = Fixture::new(SIMPLE, true);
    let name = token::Client::new(&f.env, &f.asset).name();
    let mut bytes = std::vec![0u8;name.len() as usize];
    name.copy_into_slice(&mut bytes);
    let text = std::str::from_utf8(&bytes).unwrap();
    let issuer = Address::from_string(&String::from_str(&f.env, text.rsplit(':').next().unwrap()));
    for code in [
        &[b'A', 0, 0, 0][..],
        &[b'A', b'B', b'C', b'D', b'E', 0, 0, 0, 0, 0, 0, 0][..],
        b"ABCDEFGHIJKL",
    ] {
        let mut asset = Bytes::from_array(
            &f.env,
            &(if code.len() == 4 { 1u32 } else { 2u32 }).to_be_bytes(),
        );
        asset.append(&Bytes::from_slice(&f.env, code));
        asset.append(&Bytes::from_array(&f.env, &[0; 4]));
        asset.append(&public_key(&f.env, &issuer).unwrap().into());
        let deployed = f.env.deployer().with_stellar_asset(asset).deploy();
        let mut state = f.client().state();
        state.asset = deployed.clone();
        state.token = token::Client::new(&f.env, &deployed).symbol();
        assert_eq!(
            issuer_destination(&f.env, &state.token, &state.asset, &issuer),
            Ok(true)
        );
        assert_eq!(
            issuer_destination(&f.env, &state.token, &state.asset, &f.server),
            Ok(false)
        );
    }
    for malformed in ["", r"\xZZ", r"\q", "ABCDEFGHIJKLM"] {
        let mut state = f.client().state();
        state.token = String::from_str(&f.env, malformed);
        f.env.as_contract(&f.wallet, || {
            f.env.storage().instance().set(&STATE_KEY, &state)
        });
        let payload = BytesN::from_array(&f.env, &[4; 32]);
        assert_eq!(
            f.env.try_invoke_contract_check_auth::<Error>(
                &f.wallet,
                &payload,
                f.authorization(f.execution(10), &payload).into_val(&f.env),
                &vec![&f.env, transfer_context(&f, 10)]
            ),
            Err(Ok(Error::InvalidState))
        );
    }
}

#[test]
fn native_master_weight_rotation_does_not_revoke_owner_enabled_raw_key_x402() {
    use soroban_sdk::xdr;
    use std::rc::Rc;
    let f = Fixture::new(SIMPLE, true);
    let id = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
        f.akey.verifying_key().to_bytes(),
    )));
    let key = Rc::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
        account_id: id.clone(),
    }));
    let entry = Rc::new(xdr::LedgerEntry {
        data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
            account_id: id,
            balance: 0,
            flags: 0,
            home_domain: Default::default(),
            inflation_dest: None,
            num_sub_entries: 0,
            seq_num: xdr::SequenceNumber(0),
            thresholds: xdr::Thresholds([0, 1, 1, 1]),
            signers: Default::default(),
            ext: xdr::AccountEntryExt::V0,
        }),
        last_modified_ledger_seq: 0,
        ext: xdr::LedgerEntryExt::V0,
    });
    f.env.host().add_ledger_entry(&key, &entry, None).unwrap();
    f.env.set_auths(&[f.host_entry(f.execution(10), 10, 1)]);
    token::Client::new(&f.env, &f.asset).transfer(&f.wallet, &f.recipient, &10);
    let mut p = f.deployment();
    p.x402_enabled = false;
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    f.env.set_auths(&[f.host_entry(f.execution(10), 10, 2)]);
    assert!(
        token::Client::new(&f.env, &f.asset)
            .try_transfer(&f.wallet, &f.recipient, &10)
            .is_err()
    );
    assert_eq!(f.balance(), 990);
}

#[test]
fn common_empty_rule_constructor_is_an_explicit_simple_configuration() {
    let mut f = Fixture::new(COMMON, false);
    let state = f.client().state();
    let config = PolicyConfig {
        owner: state.owner,
        agent: state.agent,
        server: state.server,
        asset: state.asset,
        policy_instance: state.policy_instance,
        source_digest: standard_prefix_digest(
            &f.env,
            &Symbol::new(&f.env, "common_policy_engine"),
            &f.env
                .crypto()
                .sha256(&Bytes::from_slice(&f.env, COMMON))
                .to_bytes(),
            &f.asset,
            &Vec::new(&f.env),
        ),
        rules: Vec::new(&f.env),
        grant: state.grant,
        x402_enabled: false,
    };
    f.env.mock_all_auths_allowing_non_root_auth();
    f.wallet = f.env.register(COMMON, (config,));
    StellarAssetClient::new(&f.env, &f.asset).mint(&f.wallet, &1000);
    f.env.mock_auths(&[]);
    f.transfer(200);
    assert_eq!(f.balance(), 800);
    assert_eq!(f.history().calls, 1);
    assert_eq!(f.client().state().nonce, 1);
}

#[test]
fn replaced_agent_key_cannot_authorize_fresh_x402_execution() {
    let f = Fixture::new(SIMPLE, true);
    let mut p = f.deployment();
    p.agent = address(&f.env, &SigningKey::from_bytes(&[99; 32]));
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    let payload = BytesN::from_array(&f.env, &[4; 32]);
    assert_eq!(
        f.env.try_invoke_contract_check_auth::<Error>(
            &f.wallet,
            &payload,
            f.authorization(f.execution(10), &payload).into_val(&f.env),
            &vec![&f.env, transfer_context(&f, 10)]
        ),
        Err(Err(soroban_sdk::InvokeError::Abort))
    );
    assert_eq!(f.client().state().nonce, 0);
    assert_eq!(f.balance(), 1000);
}

#[test]
fn full_source_identity_is_covered_by_x402_approvals_and_custom_binding() {
    let f = Fixture::new(SIMPLE, true);
    let e = f.execution(10);
    let payload = BytesN::from_array(&f.env, &[71; 32]);
    let mut authorization = f.authorization(e, &payload);
    authorization.execution.source_hash = BytesN::from_array(&f.env, &[72; 32]);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.wallet,
                &payload,
                authorization.into_val(&f.env),
                &vec![&f.env, transfer_context(&f, 10)]
            )
            .is_err()
    );
    assert_eq!(f.balance(), 1000);
    assert_eq!(f.client().state().nonce, 0);
    let f = Fixture::new(CUSTOM, false);
    let mut e = f.execution(10);
    e.source_hash = BytesN::from_array(&f.env, &[72; 32]);
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    assert_eq!(
        f.client().try_execute(&e),
        Err(Ok(Error::InvalidInvocation))
    );
}

fn execute_as_actors(f: &Fixture, e: &ExecutionRequest) -> Result<TransferReceipt, Error> {
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    match f.client().try_execute(e) {
        Ok(receipt) => Ok(receipt.unwrap()),
        Err(error) => Err(error.unwrap()),
    }
}

#[test]
fn replayed_operation_with_changed_amount_or_expense_is_rejected_without_charging() {
    for wasm in [COMMON, CUSTOM] {
        let f = Fixture::new(wasm, false);
        let first = f.execution(10);
        execute_as_actors(&f, &first).unwrap();
        let before = f.client().state();
        for changed_expense in [false, true] {
            // A fresh nonce cannot reuse the consumed logical operation with other economic facts.
            let mut e = f.execution(if changed_expense { 10 } else { 11 });
            e.operation_id = first.operation_id.clone();
            if changed_expense {
                let mut cost =
                    ExpenseBounds::from_xdr(&f.env, e.expense.as_ref().unwrap()).unwrap();
                cost.gas_units = 1;
                cost.max_fee_stroops = 1;
                cost.spent_units = 11;
                e.expense = Some(cost.to_xdr(&f.env));
            }
            assert_eq!(execute_as_actors(&f, &e), Err(Error::Replay));
            assert_eq!(f.client().state(), before);
            assert_eq!(f.balance(), 990);
        }
    }
}

#[test]
fn repeated_prefix_rules_read_one_proposed_history_and_charge_once() {
    let f = Fixture::new(COMMON, false);
    let mut p = f.deployment();
    p.rules = Vec::new(&f.env);
    for rule in [
        Rule::spent_cap,
        Rule::spent_cap,
        Rule::day_total_cap,
        Rule::call_cap,
        Rule::call_cap,
    ] {
        p.rules.push_back(rule);
    }
    p.source_digest = standard_prefix_digest(
        &f.env,
        &Symbol::new(&f.env, "common_policy_engine"),
        &f.env
            .crypto()
            .sha256(&Bytes::from_slice(&f.env, COMMON))
            .to_bytes(),
        &f.asset,
        &p.rules,
    );
    p.grant.spent_cap = Some(30);
    f.auth(&[&f.owner], "deploy_policy", (p.clone(),).into_val(&f.env));
    f.client().deploy_policy(&p);
    f.transfer(20);
    // The boundary passes although spent_cap runs twice.
    f.transfer(10);
    assert_eq!(f.history().spent, 30);
    assert_eq!(f.history().day_total, 30);
    assert_eq!(f.history().calls, 2);
    let before = f.client().state();
    assert_eq!(
        execute_as_actors(&f, &f.execution(1)),
        Err(Error::PolicyDenied)
    );
    assert_eq!(f.client().state(), before);
}

#[test]
fn clock_regression_and_cross_day_expense_reject_before_rules_run() {
    let f = Fixture::new(COMMON, false);
    f.transfer(10);
    let before = f.client().state();
    assert_eq!(before.history.day, 1);
    // Rules never see accounting of another day: the kernel rejects a backward ledger day.
    f.env.ledger().with_mut(|l| l.timestamp -= 86_400);
    assert_eq!(
        execute_as_actors(&f, &f.execution(10)),
        Err(Error::InvalidState)
    );
    assert_eq!(f.client().state(), before);
    f.env.ledger().with_mut(|l| l.timestamp += 86_400);
    let mut e = f.execution(10);
    let mut cost = ExpenseBounds::from_xdr(&f.env, e.expense.as_ref().unwrap()).unwrap();
    cost.day += 1;
    e.expense = Some(cost.to_xdr(&f.env));
    assert_eq!(execute_as_actors(&f, &e), Err(Error::InvalidInvocation));
    assert_eq!(f.client().state(), before);
}
