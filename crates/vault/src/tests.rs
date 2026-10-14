const POLICY_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_policy.wasm");
extern crate std;
use super::*;
use allowit_policy::NativePolicyClient;
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    Bytes, IntoVal, Val,
    auth::ContractContext,
    testutils::{Address as _, Events as _, Ledger},
    token::{Client as TokenClient, StellarAssetClient},
};
use std::string::ToString;

struct Fixture {
    env: Env,
    owner: Address,
    executor: Address,
    authority: Address,
    recipient: Address,
    vault: Address,
    asset: Address,
}
fn account(env: &Env, seed: u8) -> Address {
    use soroban_sdk::xdr;
    use std::rc::Rc;
    let key = SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    let id = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(key)));
    env.host()
        .add_ledger_entry(
            &Rc::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
                account_id: id.clone(),
            })),
            &Rc::new(xdr::LedgerEntry {
                last_modified_ledger_seq: env.ledger().sequence(),
                ext: xdr::LedgerEntryExt::V0,
                data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
                    account_id: id,
                    balance: 0,
                    flags: 0,
                    home_domain: Default::default(),
                    inflation_dest: None,
                    num_sub_entries: 0,
                    seq_num: xdr::SequenceNumber(0),
                    thresholds: xdr::Thresholds([1; 4]),
                    signers: Default::default(),
                    ext: xdr::AccountEntryExt::V0,
                }),
            }),
            None,
        )
        .unwrap();
    Address::from_payload(
        env,
        AddressPayload::AccountIdPublicKeyEd25519(BytesN::from_array(
            env,
            &SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )),
    )
}
impl Fixture {
    fn new() -> Self {
        Self::with_wasm(false)
    }
    fn with_wasm(compiled: bool) -> Self {
        let env = Env::default();
        if compiled {
            // Test-only setup permission for host deployment -> Wasm constructor.
            // The payment below replaces this with exact signed set_auths entries.
            env.mock_all_auths_allowing_non_root_auth();
        } else {
            env.mock_all_auths();
        }
        let network_id = env
            .crypto()
            .sha256(&Bytes::from_slice(
                &env,
                b"Test SDF Network ; September 2015",
            ))
            .to_bytes()
            .to_array();
        env.ledger().with_mut(|l| {
            l.timestamp = 86_401;
            l.sequence_number = 100;
            l.network_id = network_id;
        });
        let owner = Address::generate(&env);
        let recipient = Address::generate(&env);
        let executor = account(&env, 2);
        let authority = account(&env, 3);
        let admin = Address::generate(&env);
        let sac = env.register_stellar_asset_contract_v2(admin);
        sac.issuer()
            .set_flag(soroban_sdk::testutils::IssuerFlags::RevocableFlag);
        let asset = sac.address();
        StellarAssetClient::new(&env, &asset).mint(&owner, &1_000_000_000);
        let policy = env.register(POLICY_WASM, ());
        let source = NativePolicyClient::new(&env, &policy).source_hash();
        let constructor = (
            owner.clone(),
            executor.clone(),
            authority.clone(),
            asset.clone(),
            policy,
            source,
            env.crypto()
                .sha256(&soroban_sdk::Bytes::from_slice(&env, POLICY_WASM))
                .to_bytes(),
            25_000_000u64,
        );
        let vault = if compiled {
            let wasm = std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../target/wasm32v1-none/release/allowit_vault.wasm"
            ))
            .expect("Build the vault with stellar contract build first");
            env.register(wasm.as_slice(), constructor)
        } else {
            env.register(Vault, constructor)
        };
        VaultClient::new(&env, &vault).deposit(&owner, &100_000_000);
        Self {
            env,
            owner,
            executor,
            authority,
            recipient,
            vault,
            asset,
        }
    }
    fn client(&self) -> VaultClient<'_> {
        VaultClient::new(&self.env, &self.vault)
    }
    fn native_transfer_auth(&self, seed: u8) -> soroban_sdk::xdr::SorobanAuthorizationEntry {
        use soroban_sdk::{
            Map,
            xdr::{self, WriteXdr},
        };
        let args: Vec<Val> = (self.recipient.clone(), 1u64, 0u64, 1u64).into_val(&self.env);
        let invocation = xdr::SorobanAuthorizedInvocation {
            function: xdr::SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
                contract_address: self.vault.clone().into(),
                function_name: "transfer".try_into().unwrap(),
                args: args
                    .iter()
                    .map(|v| xdr::ScVal::try_from_val(&self.env, &v).unwrap())
                    .collect::<std::vec::Vec<_>>()
                    .try_into()
                    .unwrap(),
            }),
            sub_invocations: Default::default(),
        };
        let nonce = 6_000 + i64::from(seed);
        let expiry = self.env.ledger().sequence() + 100;
        let preimage =
            xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
                network_id: xdr::Hash(self.env.ledger().network_id().to_array()),
                nonce,
                signature_expiration_ledger: expiry,
                invocation: invocation.clone(),
            })
            .to_xdr(xdr::Limits::none())
            .unwrap();
        let digest = self
            .env
            .crypto()
            .sha256(&Bytes::from_slice(&self.env, &preimage))
            .to_bytes();
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut signature = Map::<Symbol, Val>::new(&self.env);
        signature.set(
            Symbol::new(&self.env, "public_key"),
            BytesN::from_array(&self.env, &key.verifying_key().to_bytes()).into_val(&self.env),
        );
        signature.set(
            Symbol::new(&self.env, "signature"),
            BytesN::from_array(&self.env, &key.sign(&digest.to_array()).to_bytes())
                .into_val(&self.env),
        );
        let signature: Vec<Val> = soroban_sdk::vec![&self.env, signature.into_val(&self.env)];
        let val: Val = signature.into_val(&self.env);
        xdr::SorobanAuthorizationEntry {
            credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                address: account(&self.env, seed).into(),
                nonce,
                signature_expiration_ledger: expiry,
                signature: xdr::ScVal::try_from_val(&self.env, &val).unwrap(),
            }),
            root_invocation: invocation,
        }
    }
    fn context(&self, asset: &Address, recipient: &Address, amount: i128) -> Context {
        Context::Contract(ContractContext {
            contract: asset.clone(),
            fn_name: Symbol::new(&self.env, "transfer"),
            args: (self.vault.clone(), recipient.clone(), amount).into_val(&self.env),
        })
    }
    /// Independent host authorization hash, exactly the preimage used for Address credentials.
    fn auth_entry(
        &self,
        asset: &Address,
        recipient: &Address,
        amount: i128,
    ) -> (
        soroban_sdk::xdr::SorobanAuthorizationEntry,
        PaymentAuthorization,
        BytesN<32>,
    ) {
        use soroban_sdk::xdr::{self, WriteXdr};
        let invocation = xdr::SorobanAuthorizedInvocation {
            function: xdr::SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
                contract_address: asset.clone().into(),
                function_name: "transfer".try_into().unwrap(),
                args: std::vec![
                    xdr::ScVal::Address(self.vault.clone().into()),
                    xdr::ScVal::Address(recipient.clone().into()),
                    xdr::ScVal::I128(xdr::Int128Parts {
                        hi: (amount >> 64) as i64,
                        lo: amount as u64
                    })
                ]
                .try_into()
                .unwrap(),
            }),
            sub_invocations: std::vec![].try_into().unwrap(),
        };
        let auth_nonce = 5_000;
        let signature_expiration_ledger = self.env.ledger().sequence() + 12;
        let preimage =
            xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
                network_id: xdr::Hash(self.env.ledger().network_id().to_array()),
                nonce: auth_nonce,
                signature_expiration_ledger,
                invocation: invocation.clone(),
            })
            .to_xdr(xdr::Limits::none())
            .unwrap();
        let payload = self
            .env
            .crypto()
            .sha256(&Bytes::from_slice(&self.env, &preimage))
            .to_bytes();
        let s = self.client().state();
        let mut auth = PaymentAuthorization {
            nonce: s.nonce,
            revision: s.revision,
            expires_at: self.env.ledger().timestamp() + 120,
            request_hash: BytesN::from_array(&self.env, &[9; 32]),
            executor_signature: BytesN::from_array(&self.env, &[0; 64]),
            authority_signature: BytesN::from_array(&self.env, &[0; 64]),
        };
        self.sign(&payload, &mut auth);
        let val: Val = auth.clone().into_val(&self.env);
        let entry = xdr::SorobanAuthorizationEntry {
            credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                address: self.vault.clone().into(),
                nonce: auth_nonce,
                signature_expiration_ledger,
                signature: xdr::ScVal::try_from_val(&self.env, &val).unwrap(),
            }),
            root_invocation: invocation,
        };
        (entry, auth, payload)
    }
    fn sign(&self, payload: &BytesN<32>, auth: &mut PaymentAuthorization) {
        let preimage = (
            Symbol::new(&self.env, "allowit_x402_v1"),
            self.vault.clone(),
            payload.clone(),
            auth.nonce,
            auth.revision,
            auth.expires_at,
            auth.request_hash.clone(),
        )
            .to_xdr(&self.env);
        let digest = self.env.crypto().sha256(&preimage).to_bytes().to_array();
        auth.executor_signature = BytesN::from_array(
            &self.env,
            &SigningKey::from_bytes(&[2; 32]).sign(&digest).to_bytes(),
        );
        auth.authority_signature = BytesN::from_array(
            &self.env,
            &SigningKey::from_bytes(&[3; 32]).sign(&digest).to_bytes(),
        );
    }
    fn check(
        &self,
        payload: &BytesN<32>,
        auth: &PaymentAuthorization,
        contexts: &Vec<Context>,
    ) -> bool {
        self.env
            .try_invoke_contract_check_auth::<Error>(
                &self.vault,
                payload,
                auth.clone().into_val(&self.env),
                contexts,
            )
            .is_ok()
    }
}
#[test]
fn custody_transfer_daily_boundary_and_atomic_denial() {
    let f = Fixture::new();
    let c = f.client();
    assert!(c.try_transfer(&f.recipient, &1, &0, &0).is_err());
    c.approve(&true, &0);
    c.transfer(&f.recipient, &20_000_000, &0, &1);
    assert_eq!(f.env.auths()[0].0, f.executor);
    let before = c.state();
    assert!(c.try_transfer(&f.recipient, &6_000_000, &1, &1).is_err());
    assert_eq!(c.state(), before);
    assert_eq!(
        TokenClient::new(&f.env, &f.asset).balance(&f.recipient),
        200_000_000
    );
    c.transfer(&f.recipient, &5_000_000, &1, &1);
    assert_eq!(c.state().spent, 25_000_000);
    assert!(c.try_transfer(&f.recipient, &1, &2, &1).is_err());
    f.env.ledger().with_mut(|l| l.timestamp = 172_800);
    c.transfer(&f.recipient, &25_000_000, &2, &1);
    assert_eq!(c.state().spent, 25_000_000);
    assert_eq!(c.state().nonce, 3);
}
#[test]
fn deposits_tuning_and_policy_switch_preserve_spending() {
    let f = Fixture::new();
    let c = f.client();
    c.approve(&true, &0);
    c.transfer(&f.recipient, &20_000_000, &0, &1);
    assert_eq!(f.env.auths()[0].0, f.executor);
    // Mint a top-up because the initial owner balance was fully deposited.
    StellarAssetClient::new(&f.env, &f.asset).mint(&f.owner, &100_000_000);
    c.deposit(&f.owner, &10_000_000);
    assert_eq!(c.state().spent, 20_000_000);
    let before = c.state();
    assert!(c.try_set_daily_limit(&50_000_001, &1).is_err());
    assert_eq!(c.state(), before);
    c.set_daily_limit(&40_000_000, &1);
    assert_eq!(c.state().spent, 20_000_000);
    assert!(c.try_transfer(&f.recipient, &1, &1, &1).is_err());
    c.transfer(&f.recipient, &20_000_000, &1, &2);
    let s = c.state();
    let policy = f.env.register(POLICY_WASM, ());
    c.set_policy(
        &policy,
        &NativePolicyClient::new(&f.env, &policy).source_hash(),
        &f.env
            .crypto()
            .sha256(&soroban_sdk::Bytes::from_slice(&f.env, POLICY_WASM))
            .to_bytes(),
        &2,
    );
    assert_eq!(c.state().spent, s.spent);
    assert_eq!(c.state().nonce, s.nonce);
    assert!(!c.state().approved);
    assert!(c.try_transfer(&f.recipient, &1, &2, &3).is_err());
}
#[test]
fn revocation_withdrawal_and_unsupported_leave_counter_intact() {
    let f = Fixture::new();
    let c = f.client();
    c.approve(&true, &0);
    c.transfer(&f.recipient, &10_000_000, &0, &1);
    c.approve(&false, &1);
    assert!(c.try_transfer(&f.recipient, &1, &1, &2).is_err());
    c.withdraw(&90_000_000);
    assert_eq!(c.balance(), 0);
    assert_eq!(c.state().spent, 10_000_000);
    assert_eq!(c.try_unsupported(&1), Err(Ok(Error::UnsupportedMethod)));
}
#[test]
fn owner_and_executor_authorization_are_required() {
    let f = Fixture::new();
    f.env.mock_auths(&[]);
    assert!(f.client().try_approve(&true, &0).is_err());
    assert!(f.client().try_withdraw(&1).is_err());
    assert_eq!(f.client().state().revision, 0);
}

#[test]
fn wrong_policy_artifact_is_rejected_without_resetting_state() {
    let f = Fixture::new();
    let c = f.client();
    let s = c.state();
    assert_eq!(
        c.try_set_policy(
            &s.policy,
            &s.policy_source,
            &BytesN::from_array(&f.env, &[0; 32]),
            &0
        ),
        Err(Ok(Error::SourceChanged))
    );
    assert_eq!(c.state(), s);
    f.env.mock_auths(&[]);
    assert!(c.try_transfer(&f.recipient, &1, &0, &0).is_err());
    assert!(c.try_deposit(&f.owner, &1).is_err());
    assert!(c.try_set_daily_limit(&1, &0).is_err());
    assert!(
        c.try_set_policy(&s.policy, &s.policy_source, &s.policy_wasm, &0)
            .is_err()
    );
}

#[test]
fn executor_alone_cannot_bypass_the_policy_authority() {
    let f = Fixture::new();
    f.client().approve(&true, &0);
    let before = f.client().state();
    f.env.set_auths(&[f.native_transfer_auth(2)]);
    assert!(f.client().try_transfer(&f.recipient, &1, &0, &1).is_err());
    assert_eq!(f.client().state(), before);
}

#[test]
fn standard_sac_transfer_runs_custom_auth_with_real_signatures_and_one_token_event() {
    for compiled in [false, true] {
        let f = Fixture::with_wasm(compiled);
        f.client().approve(&true, &0);
        let (entry, auth, payload) = f.auth_entry(&f.asset, &f.recipient, 10_000_000);
        f.env.set_auths(&[entry.clone()]);
        TokenClient::new(&f.env, &f.asset).transfer(&f.vault, &f.recipient, &10_000_000);
        let events = f.env.events().all();
        assert_eq!(events.events().len(), 1);
        let soroban_sdk::xdr::ScAddress::Contract(id) = f.asset.clone().into() else {
            unreachable!()
        };
        assert_eq!(events.events()[0].contract_id, Some(id));
        if compiled {
            if let Ok(path) = std::env::var("ALLOWIT_STELLAR_X402_VECTOR_OUT") {
                export_host_proof(&f, &entry, &auth, &payload, &events.events()[0], &path);
            }
        }
        assert_eq!(f.client().state().spent, 1_000_000);
        assert_eq!(f.client().state().nonce, 1);
        assert_eq!(
            TokenClient::new(&f.env, &f.asset).balance(&f.recipient),
            10_000_000
        );
        let before = f.client().state();
        f.env.set_auths(&[entry]);
        assert!(
            TokenClient::new(&f.env, &f.asset)
                .try_transfer(&f.vault, &f.recipient, &10_000_000)
                .is_err()
        );
        assert_eq!(f.client().state(), before);
    }
}

fn export_host_proof(
    f: &Fixture,
    entry: &soroban_sdk::xdr::SorobanAuthorizationEntry,
    auth: &PaymentAuthorization,
    payload: &BytesN<32>,
    event: &soroban_sdk::xdr::ContractEvent,
    path: &str,
) {
    use soroban_sdk::xdr::{self, WriteXdr};
    fn hex(bytes: &[u8]) -> std::string::String {
        bytes.iter().map(|b| std::format!("{b:02x}")).collect()
    }
    let diagnostic = xdr::DiagnosticEvent {
        in_successful_contract_call: true,
        event: event.clone(),
    };
    let signature = match &entry.credentials {
        xdr::SorobanCredentials::Address(c) => c.signature.clone(),
        _ => unreachable!(),
    };
    let output = std::format!(
        "{{\"networkPassphrase\":\"Test SDF Network ; September 2015\",\"networkId\":\"{}\",\"latestLedger\":{},\"timestamp\":{},\"asset\":\"{}\",\"from\":\"{}\",\"recipient\":\"{}\",\"amountToken\":\"10000000\",\"nonce\":{},\"revision\":{},\"expiresAt\":{},\"requestHash\":\"{}\",\"executorPublicKey\":\"{}\",\"authorityPublicKey\":\"{}\",\"hostPayloadHex\":\"{}\",\"entryXdrHex\":\"{}\",\"rootInvocationXdrHex\":\"{}\",\"signatureXdrHex\":\"{}\",\"diagnosticEventXdrHex\":\"{}\"}}",
        hex(&f.env.ledger().network_id().to_array()),
        f.env.ledger().sequence(),
        f.env.ledger().timestamp(),
        f.asset.to_string().to_string(),
        f.vault.to_string().to_string(),
        f.recipient.to_string().to_string(),
        auth.nonce,
        auth.revision,
        auth.expires_at,
        hex(&auth.request_hash.to_array()),
        hex(&signer_key(&f.executor).unwrap().to_array()),
        hex(&signer_key(&f.authority).unwrap().to_array()),
        hex(&payload.to_array()),
        hex(&entry.to_xdr(xdr::Limits::none()).unwrap()),
        hex(&entry.root_invocation.to_xdr(xdr::Limits::none()).unwrap()),
        hex(&xdr::WriteXdr::to_xdr(&signature, xdr::Limits::none()).unwrap()),
        hex(&diagnostic.to_xdr(xdr::Limits::none()).unwrap())
    );
    std::fs::write(path, output).expect("write public host authorization proof");
}

#[test]
fn x402_signatures_bind_every_metadata_field_and_both_configured_keys() {
    let f = Fixture::new();
    f.client().approve(&true, &0);
    let (_, original, payload) = f.auth_entry(&f.asset, &f.recipient, 10);
    let contexts = soroban_sdk::vec![&f.env, f.context(&f.asset, &f.recipient, 10)];
    let before = f.client().state();
    for i in 0..8 {
        let mut bad = original.clone();
        match i {
            0 => bad.nonce += 1,
            1 => bad.revision += 1,
            2 => bad.expires_at += 1,
            3 => bad.request_hash = BytesN::from_array(&f.env, &[8; 32]),
            4 => bad.executor_signature = BytesN::from_array(&f.env, &[0; 64]),
            5 => bad.authority_signature = BytesN::from_array(&f.env, &[0; 64]),
            6 => bad.executor_signature = original.authority_signature.clone(),
            _ => bad.authority_signature = original.executor_signature.clone(),
        }
        assert!(!f.check(&payload, &bad, &contexts));
        assert_eq!(f.client().state(), before);
    }
    assert!(!f.check(&BytesN::from_array(&f.env, &[7; 32]), &original, &contexts));
    assert_eq!(f.client().state(), before);
}

#[test]
fn x402_context_limits_expiry_and_revision_fail_without_charging() {
    let f = Fixture::new();
    f.client().approve(&true, &0);
    let (_, original, payload) = f.auth_entry(&f.asset, &f.recipient, 10);
    let valid = f.context(&f.asset, &f.recipient, 10);
    let before = f.client().state();
    let other = Address::generate(&f.env);
    let mut wrong_from = match valid.clone() {
        Context::Contract(c) => c,
        _ => unreachable!(),
    };
    wrong_from.args.set(0, f.owner.clone().into_val(&f.env));
    let mut wrong_method = wrong_from.clone();
    wrong_method.fn_name = Symbol::new(&f.env, "approve");
    let mut wrong_args = wrong_from.clone();
    wrong_args.args.push_back(0u32.into_val(&f.env));
    let cases = [
        Vec::new(&f.env),
        soroban_sdk::vec![&f.env, valid.clone(), valid.clone()],
        soroban_sdk::vec![&f.env, f.context(&other, &f.recipient, 10)],
        soroban_sdk::vec![&f.env, Context::Contract(wrong_from)],
        soroban_sdk::vec![&f.env, Context::Contract(wrong_method)],
        soroban_sdk::vec![&f.env, Context::Contract(wrong_args)],
        soroban_sdk::vec![&f.env, f.context(&f.asset, &f.vault, 10)],
        soroban_sdk::vec![&f.env, f.context(&f.asset, &f.recipient, -10)],
        soroban_sdk::vec![&f.env, f.context(&f.asset, &f.recipient, 0)],
        soroban_sdk::vec![&f.env, f.context(&f.asset, &f.recipient, 11)],
        soroban_sdk::vec![
            &f.env,
            f.context(&f.asset, &f.recipient, (u64::MAX as i128 + 1) * 10)
        ],
        soroban_sdk::vec![&f.env, f.context(&f.asset, &f.recipient, 250_000_010)],
    ];
    for contexts in cases {
        assert!(!f.check(&payload, &original, &contexts));
        assert_eq!(f.client().state(), before);
    }
    let contexts = soroban_sdk::vec![&f.env, valid];
    for i in 0..5 {
        let mut bad = original.clone();
        match i {
            0 => bad.expires_at = f.env.ledger().timestamp(),
            1 => bad.expires_at = f.env.ledger().timestamp() + 301,
            2 => bad.nonce += 1,
            3 => bad.revision += 1,
            _ => bad.request_hash = BytesN::from_array(&f.env, &[0; 32]),
        }
        f.sign(&payload, &mut bad);
        assert!(!f.check(&payload, &bad, &contexts));
        assert_eq!(f.client().state(), before);
    }
    f.env.mock_all_auths();
    f.client().set_daily_limit(&30_000_000, &1);
    assert!(!f.check(&payload, &original, &contexts));
    f.env.mock_all_auths();
    f.client().approve(&false, &2);
    assert!(!f.check(&payload, &original, &contexts));
}

#[test]
fn sac_failure_rolls_back_authorization_and_owner_can_withdraw_after_revoke() {
    let f = Fixture::new();
    f.client().approve(&true, &0);
    let (entry, _, _) = f.auth_entry(&f.asset, &f.recipient, 10_000_000);
    // Freeze the contract balance: auth executes before SAC rejects the token movement.
    f.env.mock_all_auths();
    StellarAssetClient::new(&f.env, &f.asset).set_authorized(&f.vault, &false);
    let before = f.client().state();
    f.env.set_auths(&[entry.clone()]);
    assert!(
        TokenClient::new(&f.env, &f.asset)
            .try_transfer(&f.vault, &f.recipient, &10_000_000)
            .is_err()
    );
    assert_eq!(f.client().state(), before);
    assert_eq!(TokenClient::new(&f.env, &f.asset).balance(&f.recipient), 0);
    f.env.mock_all_auths();
    StellarAssetClient::new(&f.env, &f.asset).set_authorized(&f.vault, &true);
    f.env.set_auths(&[entry]);
    TokenClient::new(&f.env, &f.asset).transfer(&f.vault, &f.recipient, &10_000_000);
    assert_eq!(f.client().state().nonce, 1);
    f.env.mock_all_auths();
    f.client().approve(&false, &1);
    f.client().withdraw(&99_000_000);
    assert_eq!(f.client().balance(), 0);
    assert_eq!(f.client().state().spent, 1_000_000);
}

#[test]
fn payment_digest_matches_independent_official_stellar_sdk_vector() {
    let env = Env::default();
    let vault = Address::from_payload(
        &env,
        AddressPayload::ContractIdHash(BytesN::from_array(&env, &[7; 32])),
    );
    let auth = PaymentAuthorization {
        nonce: 3,
        revision: 4,
        expires_at: 172_900,
        request_hash: BytesN::from_array(&env, &[9; 32]),
        executor_signature: BytesN::from_array(&env, &[0; 64]),
        authority_signature: BytesN::from_array(&env, &[0; 64]),
    };
    let digest = payment_digest(&env, &vault, &BytesN::from_array(&env, &[8; 32]), &auth);
    assert_eq!(
        digest.to_array(),
        [
            0x52, 0x62, 0x0b, 0xe3, 0x97, 0xb4, 0x5c, 0x20, 0x72, 0xdd, 0xab, 0xe0, 0x17, 0xc6,
            0xa4, 0x83, 0x38, 0xab, 0xfd, 0x2c, 0x94, 0x5f, 0xf1, 0xd1, 0x84, 0xcb, 0x7f, 0xbe,
            0x47, 0x3b, 0x2e, 0x53
        ]
    );
}

#[test]
fn signer_roles_are_distinct_classic_ed25519_accounts() {
    for variant in 0..4 {
        let f = Fixture::new();
        let s = f.client().state();
        let (executor, authority) = match variant {
            0 => (f.owner.clone(), f.authority.clone()),
            1 => (f.executor.clone(), f.owner.clone()),
            2 => (f.executor.clone(), f.executor.clone()),
            _ => (Address::generate(&f.env), f.authority.clone()),
        };
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                f.env.register(
                    Vault,
                    (
                        f.owner.clone(),
                        executor,
                        authority,
                        f.asset.clone(),
                        s.policy,
                        s.policy_source,
                        s.policy_wasm,
                        1_000_000u64,
                    ),
                );
            }))
            .is_err()
        );
    }
}

#[test]
fn direct_transfer_requires_exact_auth_from_both_roles() {
    let f = Fixture::new();
    f.client().approve(&true, &0);
    f.env.set_auths(&[f.native_transfer_auth(3)]);
    assert!(f.client().try_transfer(&f.recipient, &1, &0, &1).is_err());
    f.env
        .set_auths(&[f.native_transfer_auth(2), f.native_transfer_auth(3)]);
    assert!(f.client().try_transfer(&f.owner, &1, &0, &1).is_err());
    f.client().transfer(&f.recipient, &1, &0, &1);
    assert_eq!(f.client().state().nonce, 1);
}

#[test]
fn actual_host_auth_rejects_changed_transfer_and_expired_ledger() {
    let f = Fixture::new();
    f.client().approve(&true, &0);
    let (entry, _, _) = f.auth_entry(&f.asset, &f.recipient, 10);
    let before = f.client().state();
    f.env.set_auths(&[entry.clone()]);
    assert!(
        TokenClient::new(&f.env, &f.asset)
            .try_transfer(&f.vault, &f.owner, &10)
            .is_err()
    );
    assert_eq!(f.client().state(), before);
    let mut changed = entry.clone();
    if let soroban_sdk::xdr::SorobanAuthorizedFunction::ContractFn(args) =
        &mut changed.root_invocation.function
    {
        args.args = std::vec![
            soroban_sdk::xdr::ScVal::Address(f.vault.clone().into()),
            soroban_sdk::xdr::ScVal::Address(f.recipient.clone().into()),
            soroban_sdk::xdr::ScVal::I128(soroban_sdk::xdr::Int128Parts { hi: 0, lo: 20 })
        ]
        .try_into()
        .unwrap();
    }
    f.env.set_auths(&[changed]);
    assert!(
        TokenClient::new(&f.env, &f.asset)
            .try_transfer(&f.vault, &f.recipient, &20)
            .is_err()
    );
    assert_eq!(f.client().state(), before);
    f.env.ledger().with_mut(|l| l.sequence_number += 101);
    f.env.set_auths(&[entry]);
    assert!(
        TokenClient::new(&f.env, &f.asset)
            .try_transfer(&f.vault, &f.recipient, &10)
            .is_err()
    );
    assert_eq!(f.client().state(), before);
}
