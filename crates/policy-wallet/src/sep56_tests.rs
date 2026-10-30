//! Deposit tests execute compiled custody and hostile vault Wasm through the native host.
use super::tests::*;
use super::*;
use soroban_sdk::{IntoVal, testutils::Address as _, vec};

use allowit_sep56_test_vault::VaultClient;
const VAULT: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_sep56_test_vault.wasm");

fn vault(f: &Fixture, behavior: u32, underlying: Option<Address>) -> Address {
    f.env.register(
        VAULT,
        (underlying.unwrap_or_else(|| f.asset.clone()), behavior),
    )
}
fn allow_recipient(f: &Fixture, vault: &Address) {
    if f.client().state().rules.is_empty() {
        return;
    }
    let mut d = f.deployment();
    // Common's explicitly selected recipient rule must also allow the deposit target.
    d.grant.set(
        String::from_str(&f.env, "recipients"),
        vec![&f.env, vault.clone(), f.recipient.clone()].into_val(&f.env),
    );
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
}
fn request(f: &Fixture, vault: &Address, assets: i128, min_shares: i128) -> ExecutionRequest {
    let mut e = f.execution(assets);
    e.invocation.argument_schema_digest = schema_digest(&f.env, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR);
    e.invocation.arguments = Sep56DepositArgs {
        vault: vault.clone(),
        assets,
        min_shares,
        from: f.wallet.clone(),
        receiver: f.wallet.clone(),
        operator: f.wallet.clone(),
    }
    .to_xdr(&f.env);
    e
}
fn execute(
    f: &Fixture,
    e: &ExecutionRequest,
) -> Result<
    Result<TransferReceipt, soroban_sdk::ConversionError>,
    Result<Error, soroban_sdk::InvokeError>,
> {
    f.auth(
        &[&f.agent, &f.server],
        "execute",
        (e.clone(),).into_val(&f.env),
    );
    f.client().try_execute(e)
}
fn assert_unchanged(
    f: &Fixture,
    vault: &Address,
    op: &BytesN<32>,
    before: &State,
    spent: &Option<Spent>,
) {
    assert_eq!(f.balance(), 1000);
    assert_eq!(VaultClient::new(&f.env, vault).balance(&f.wallet), 0);
    assert_eq!(f.client().state().nonce, before.nonce);
    assert_eq!(f.client().policy_spent(), *spent);
    assert_eq!(f.client().deposit_receipt(op), None);
}

#[test]
fn deposit_compiled_simple_and_common_wallets_bind_and_retain_actual_effects() {
    for wasm in [SIMPLE, COMMON] {
        let f = Fixture::new(wasm, false);
        let vault = vault(&f, 0, None);
        allow_recipient(&f, &vault);
        let e = request(&f, &vault, 50, 50);
        let binding = f
            .client()
            .policy_binding_for(&e.invocation.argument_schema_digest);
        assert_eq!(
            binding.argument_schema_digest,
            e.invocation.argument_schema_digest
        );
        let receipt = execute(&f, &e).unwrap().unwrap();
        assert_eq!(receipt.amount, 50);
        assert_eq!(receipt.to, vault);
        assert_eq!(f.balance(), 950);
        assert_eq!(VaultClient::new(&f.env, &vault).balance(&f.wallet), 50);
        let deposited = f.client().deposit_receipt(&e.operation_id).unwrap();
        assert_eq!(deposited.assets, 50);
        assert_eq!(deposited.shares, 50);
        assert_eq!(deposited.vault, vault);
        assert_eq!(deposited.asset, f.asset);
        assert_eq!(deposited.receiver, f.wallet);
        assert_eq!(f.client().state().nonce, 1);
        if wasm == COMMON {
            assert_eq!(f.used("total"), 50);
            assert_eq!(f.used("daily"), 50);
            assert_eq!(f.used("calls"), 1);
        }
        assert_eq!(execute(&f, &e), Err(Ok(Error::Replay)));
        assert_eq!(f.balance(), 950);
        assert_eq!(f.client().deposit_receipt(&e.operation_id), Some(deposited));
    }
}

#[test]
fn deposit_vault_target_is_controlled_only_by_authored_recipient_rule() {
    let f = Fixture::new(COMMON, false);
    let vault = vault(&f, 0, None);
    let e = request(&f, &vault, 50, 50);
    assert_eq!(execute(&f, &e), Err(Ok(Error::PolicyDenied)));
    assert_eq!(f.balance(), 1000);
    assert_eq!(f.client().state().nonce, 0);
    allow_recipient(&f, &vault);
    let e = request(&f, &vault, 50, 50);
    assert!(execute(&f, &e).is_ok());
    assert!(
        !f.client()
            .state()
            .grant
            .contains_key(String::from_str(&f.env, "sep56_vaults"))
    );
}

#[test]
fn deposit_rejects_wrong_wallet_parties_nonpositive_bounds_and_noncanonical_bytes() {
    let f = Fixture::new(SIMPLE, false);
    let vault = vault(&f, 0, None);
    allow_recipient(&f, &vault);
    for field in ["from", "receiver", "operator"] {
        let mut e = request(&f, &vault, 50, 50);
        let mut args = Sep56DepositArgs::from_xdr(&f.env, &e.invocation.arguments).unwrap();
        match field {
            "from" => args.from = f.recipient.clone(),
            "receiver" => args.receiver = f.recipient.clone(),
            _ => args.operator = f.recipient.clone(),
        }
        e.invocation.arguments = args.to_xdr(&f.env);
        assert_eq!(execute(&f, &e), Err(Ok(Error::InvalidInvocation)));
    }
    for (assets, shares) in [(0, 1), (-1, 1), (1, 0), (1, -1)] {
        assert_eq!(
            execute(&f, &request(&f, &vault, assets, shares)),
            Err(Ok(Error::InvalidAmount))
        );
    }
    let mut e = request(&f, &vault, 50, 50);
    e.invocation
        .arguments
        .append(&Bytes::from_array(&f.env, &[0; 4]));
    assert!(execute(&f, &e).is_err());
    assert_eq!(f.balance(), 1000);
}

#[test]
fn deposit_wrong_asset_under_mint_lied_credit_and_changed_asset_roll_back_everything() {
    for behavior in [1, 2, 6] {
        let f = Fixture::new(COMMON, false);
        let vault = vault(&f, behavior, None);
        allow_recipient(&f, &vault);
        let e = request(&f, &vault, 50, 50);
        let before = f.client().state();
        let spent = f.client().policy_spent();
        assert_eq!(execute(&f, &e), Err(Ok(Error::InvalidEffects)));
        assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
    }
    let f = Fixture::new(COMMON, false);
    let wrong = f
        .env
        .register_stellar_asset_contract_v2(Address::generate(&f.env))
        .address();
    let vault = vault(&f, 0, Some(wrong));
    allow_recipient(&f, &vault);
    let e = request(&f, &vault, 50, 50);
    let before = f.client().state();
    let spent = f.client().policy_spent();
    assert_eq!(execute(&f, &e), Err(Ok(Error::UnsupportedAsset)));
    assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
}

#[test]
fn deposit_exact_nested_authorization_rejects_extra_debit_short_debit_and_allowance() {
    for behavior in [3, 4, 5, 7] {
        let f = Fixture::new(COMMON, false);
        let vault = vault(&f, behavior, None);
        allow_recipient(&f, &vault);
        let e = request(&f, &vault, 50, 50);
        let before = f.client().state();
        let spent = f.client().policy_spent();
        assert!(execute(&f, &e).is_err());
        assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
    }
}

#[test]
fn deposit_cannot_inherit_transfer_only_custom_source_schema() {
    let f = Fixture::new(CUSTOM, false);
    let vault = vault(&f, 0, None);
    allow_recipient(&f, &vault);
    let e = request(&f, &vault, 50, 50);
    assert_eq!(execute(&f, &e), Err(Ok(Error::UnsupportedOperation)));
    assert_eq!(
        f.client()
            .try_policy_binding_for(&e.invocation.argument_schema_digest),
        Err(Ok(Error::UnsupportedOperation))
    );
    assert_eq!(f.balance(), 1000);
}

#[test]
fn deposit_vault_upgrade_cannot_hide_inconsistent_effects_and_rolls_back_all_usage() {
    let f = Fixture::new(COMMON, false);
    let vault = vault(&f, 8, None);
    allow_recipient(&f, &vault);
    let original_code = vault.executable();
    let hash = f
        .env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&f.env, SIMPLE));
    VaultClient::new(&f.env, &vault).set_upgrade(&hash);
    let e = request(&f, &vault, 50, 50);
    let before = f.client().state();
    let spent = f.client().policy_spent();
    assert!(execute(&f, &e).is_err());
    assert_eq!(vault.executable(), original_code);
    assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
}

#[test]
fn qualified_operation_names_survive_native_context_without_symbol_coercion() {
    let f = Fixture::new(SIMPLE, false);
    let request = EngineRequest {
        wallet: f.wallet.clone(),
        agent: f.agent.clone(),
        asset: f.asset.clone(),
        token: String::from_str(&f.env, "XLM"),
        decimals: 7,
        recipient: f.recipient.clone(),
        amount: 1,
        operation_id: BytesN::from_array(&f.env, &[1; 32]),
        nonce: 0,
        deployment_version: 0,
        expires_at: 1_000_000,
        now: 86_410,
    };
    assert_eq!(
        context(&request).operation,
        String::from_str(&f.env, "stellar::sep41_transfer")
    );
    let name = String::from_str(&f.env, "stellar::sep56_deposit");
    assert_eq!(context_for_operation(&request, &name).operation, name);
}

#[test]
fn ordinary_recipient_allowlist_admits_multiple_vaults_and_denies_other_targets() {
    let f = Fixture::new(COMMON, false);
    let a = vault(&f, 0, None);
    let b = vault(&f, 0, None);
    let denied = vault(&f, 0, None);
    let mut d = f.deployment();
    d.grant.set(
        String::from_str(&f.env, "recipients"),
        vec![&f.env, a.clone(), b.clone()].into_val(&f.env),
    );
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    for target in [&a, &b] {
        assert!(execute(&f, &request(&f, target, 40, 40)).is_ok());
    }
    let e = request(&f, &denied, 40, 40);
    assert_eq!(execute(&f, &e), Err(Ok(Error::PolicyDenied)));
    assert_eq!(f.balance(), 920);
    assert_eq!(f.client().state().nonce, 2);
    assert_eq!(f.used("total"), 80);
    assert_eq!(f.client().deposit_receipt(&e.operation_id), None);
}
