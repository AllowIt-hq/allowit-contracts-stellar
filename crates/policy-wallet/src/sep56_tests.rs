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
    d.grant.recipients = Some(vec![&f.env, vault.clone(), f.recipient.clone()]);
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
}
fn request(
    f: &Fixture,
    vault: &Address,
    assets: i128,
    min_shares: i128,
) -> AllowitExecutionRequest {
    let mut e = f.execution(assets);
    e.expense = Some(
        AllowitExpenseBounds {
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
    e.invocation.argument_schema_digest = schema_digest(&f.env, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR);
    e.invocation.arguments = AllowitSep56DepositArgs {
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
    e: &AllowitExecutionRequest,
) -> Result<
    Result<AllowitTransferReceipt, soroban_sdk::ConversionError>,
    Result<AllowitWalletError, soroban_sdk::InvokeError>,
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
    before: &AllowitState,
    history: &AllowitAccountingHistory,
) {
    assert_eq!(f.balance(), 1000);
    assert_eq!(VaultClient::new(&f.env, vault).balance(&f.wallet), 0);
    assert_eq!(f.client().state().nonce, before.nonce);
    assert_eq!(f.history(), *history);
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
        assert_eq!(f.history().spent, 0);
        assert_eq!(f.history().day_spent, 0);
        assert_eq!(f.history().day_total, 50);
        assert_eq!(f.history().calls, 1);
        assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::Replay)));
        assert_eq!(f.balance(), 950);
        assert_eq!(f.client().deposit_receipt(&e.operation_id), Some(deposited));
    }
}

#[test]
fn deposit_vault_target_is_controlled_only_by_authored_recipient_rule() {
    let f = Fixture::new(COMMON, false);
    let vault = vault(&f, 0, None);
    let e = request(&f, &vault, 50, 50);
    assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::PolicyDenied)));
    assert_eq!(f.balance(), 1000);
    assert_eq!(f.client().state().nonce, 0);
    allow_recipient(&f, &vault);
    let e = request(&f, &vault, 50, 50);
    assert!(execute(&f, &e).is_ok());
}

#[test]
fn deposit_rejects_wrong_wallet_parties_nonpositive_bounds_and_noncanonical_bytes() {
    let f = Fixture::new(SIMPLE, false);
    let vault = vault(&f, 0, None);
    allow_recipient(&f, &vault);
    for field in ["from", "receiver", "operator"] {
        let mut e = request(&f, &vault, 50, 50);
        let mut args = AllowitSep56DepositArgs::from_xdr(&f.env, &e.invocation.arguments).unwrap();
        match field {
            "from" => args.from = f.recipient.clone(),
            "receiver" => args.receiver = f.recipient.clone(),
            _ => args.operator = f.recipient.clone(),
        }
        e.invocation.arguments = args.to_xdr(&f.env);
        assert_eq!(
            execute(&f, &e),
            Err(Ok(AllowitWalletError::InvalidInvocation))
        );
    }
    // The wallet asset is never its own vault.
    let e = request(&f, &f.asset, 50, 50);
    assert_eq!(
        execute(&f, &e),
        Err(Ok(AllowitWalletError::InvalidInvocation))
    );
    for (assets, shares) in [(0, 1), (-1, 1), (1, 0), (1, -1)] {
        assert_eq!(
            execute(&f, &request(&f, &vault, assets, shares)),
            Err(Ok(AllowitWalletError::InvalidAmount))
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
        let spent = f.history();
        assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::InvalidEffects)));
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
    let spent = f.history();
    assert_eq!(
        execute(&f, &e),
        Err(Ok(AllowitWalletError::UnsupportedAsset))
    );
    assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
}

#[test]
fn deposit_under_mint_within_the_valuation_bound_still_requires_min_shares() {
    let f = Fixture::new(COMMON, false);
    let vault = vault(&f, 1, None);
    allow_recipient(&f, &vault);
    // One unit of conversion cost admits the vault's valuation of 49 shares; min_shares does not.
    let mut e = request(&f, &vault, 50, 50);
    set_cost(&f, &mut e, 0, 1);
    let before = f.client().state();
    let spent = f.history();
    assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::InvalidEffects)));
    assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
    let mut e = request(&f, &vault, 50, 49);
    set_cost(&f, &mut e, 0, 1);
    assert_eq!(execute(&f, &e).unwrap().unwrap().amount, 50);
}

#[test]
fn deposit_exact_nested_authorization_rejects_extra_debit_short_debit_and_allowance() {
    for behavior in [3, 4, 5, 7] {
        let f = Fixture::new(COMMON, false);
        let vault = vault(&f, behavior, None);
        allow_recipient(&f, &vault);
        let e = request(&f, &vault, 50, 50);
        let before = f.client().state();
        let spent = f.history();
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
    assert_eq!(
        execute(&f, &e),
        Err(Ok(AllowitWalletError::UnsupportedOperation))
    );
    assert_eq!(
        f.client()
            .try_policy_binding_for(&e.invocation.argument_schema_digest),
        Err(Ok(AllowitWalletError::UnsupportedOperation))
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
    let spent = f.history();
    assert!(execute(&f, &e).is_err());
    assert_eq!(vault.executable(), original_code);
    assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
}

#[test]
fn rule_input_carries_typed_operations_and_the_vault_as_recipient() {
    let f = Fixture::new(COMMON, false);
    let vault = vault(&f, 0, None);
    let state = f.client().state();
    let deposit = NativeOperation::Deposit(AllowitSep56DepositArgs {
        vault: vault.clone(),
        assets: 5,
        receiver: f.wallet.clone(),
        from: f.wallet.clone(),
        operator: f.wallet.clone(),
        min_shares: 5,
    });
    let history = AllowitAccountingHistory {
        calls: 1,
        day: 1,
        ..Default::default()
    };
    let ctx = rule_input(
        &f.env,
        &state,
        &history,
        deposit.kind(),
        &deposit.transfer(&state.asset),
        86_410,
        86_500,
    );
    assert_eq!(ctx.request.operation, AllowitOperation::sep56_deposit);
    assert_eq!(ctx.request.recipient, vault);
    assert_eq!(ctx.request.asset, f.asset);
    assert_eq!(ctx.request.amount, 5);
    assert_eq!(ctx.state, history);
    assert_eq!(ctx.grant, state.grant);
    let transfer = NativeOperation::Transfer(AllowitSep41TransferArgs {
        token: f.asset.clone(),
        from: f.wallet.clone(),
        to: f.recipient.clone(),
        amount: 1,
    });
    assert_eq!(transfer.kind(), AllowitOperation::sep41_transfer);
}

#[test]
fn ordinary_recipient_allowlist_admits_multiple_vaults_and_denies_other_targets() {
    let f = Fixture::new(COMMON, false);
    let a = vault(&f, 0, None);
    let b = vault(&f, 0, None);
    let denied = vault(&f, 0, None);
    let mut d = f.deployment();
    d.grant.recipients = Some(vec![&f.env, a.clone(), b.clone()]);
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    for target in [&a, &b] {
        assert!(execute(&f, &request(&f, target, 40, 40)).is_ok());
    }
    let e = request(&f, &denied, 40, 40);
    assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::PolicyDenied)));
    assert_eq!(f.balance(), 920);
    assert_eq!(f.client().state().nonce, 2);
    assert_eq!(f.history().day_total, 80);
    assert_eq!(f.client().deposit_receipt(&e.operation_id), None);
}

#[test]
fn deposit_untrusted_metadata_getter_cannot_mutate_final_share_or_asset_effects() {
    for behavior in [9, 10] {
        let f = Fixture::new(COMMON, false);
        let vault = vault(&f, behavior, None);
        allow_recipient(&f, &vault);
        let e = request(&f, &vault, 50, 50);
        let before = f.client().state();
        let spent = f.history();
        assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::InvalidEffects)));
        assert_unchanged(&f, &vault, &e.operation_id, &before, &spent);
    }
}

fn set_cost(f: &Fixture, e: &mut AllowitExecutionRequest, gas: i128, conversion: i128) {
    let depositing = e.invocation.argument_schema_digest
        == schema_digest(&f.env, SEP56_DEPOSIT_SCHEMA_DESCRIPTOR);
    let principal = if depositing {
        conversion
    } else {
        AllowitSep41TransferArgs::from_xdr(&f.env, &e.invocation.arguments)
            .unwrap()
            .amount
    };
    e.expense = Some(
        AllowitExpenseBounds {
            asset: f.asset.clone(),
            decimals: 7,
            gas_units: gas,
            conversion_units: conversion,
            spent_units: principal + gas,
            max_fee_stroops: u32::try_from(gas).unwrap(),
            observed_ledger: 100,
            day: f.env.ledger().timestamp() / 86400,
        }
        .to_xdr(&f.env),
    );
}
#[test]
fn native_xlm_expense_caps_separate_deposit_principal_from_costs_and_daily_total() {
    let f = Fixture::new_native(COMMON);
    let v = vault(&f, 11, None);
    allow_recipient(&f, &v);
    let mut e = request(&f, &v, 50, 50);
    set_cost(&f, &mut e, 3, 2);
    assert!(execute(&f, &e).is_ok());
    assert_eq!(f.history().spent, 5);
    assert_eq!(f.history().day_spent, 5);
    assert_eq!(f.history().day_total, 53);
    assert_eq!(f.balance(), 950);
    assert_eq!(
        f.client().deposit_receipt(&e.operation_id).unwrap().shares,
        50
    );
    // A payment spends principal as well as its attributable gas ceiling.
    let f = Fixture::new_native(COMMON);
    let mut e = f.execution(50);
    set_cost(&f, &mut e, 3, 0);
    assert!(execute(&f, &e).is_ok());
    assert_eq!(f.history().spent, 53);
    assert_eq!(f.history().day_total, 53);
}
#[test]
fn expense_and_gross_cap_denials_and_valuation_bound_roll_back_atomic_effects() {
    for (field, limit) in [(0, 4i128), (1, 4), (2, 52)] {
        let f = Fixture::new_native(COMMON);
        let v = vault(&f, 11, None);
        allow_recipient(&f, &v);
        let mut d = f.deployment();
        *[
            &mut d.grant.spent_cap,
            &mut d.grant.day_spent_cap,
            &mut d.grant.day_total_cap,
        ][field] = Some(limit);
        f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
        f.client().deploy_policy(&d);
        let mut e = request(&f, &v, 50, 50);
        set_cost(&f, &mut e, 3, 2);
        let before = f.client().state();
        let spent = f.history();
        assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::PolicyDenied)));
        assert_unchanged(&f, &v, &e.operation_id, &before, &spent);
    }
    for (behavior, conversion) in [(11, 1), (12, 0)] {
        let f = Fixture::new_native(COMMON);
        let v = vault(&f, behavior, None);
        allow_recipient(&f, &v);
        let mut e = request(&f, &v, 50, 50);
        set_cost(&f, &mut e, 3, conversion);
        let before = f.client().state();
        let spent = f.history();
        assert_eq!(execute(&f, &e), Err(Ok(AllowitWalletError::InvalidEffects)));
        assert_unchanged(&f, &v, &e.operation_id, &before, &spent);
    }
}
#[test]
fn economic_class_denomination_gas_and_observation_facts_cannot_be_forged() {
    let f = Fixture::new_native(COMMON);
    for mutation in 0..7 {
        let mut e = f.execution(50);
        set_cost(&f, &mut e, 3, 0);
        let mut c = AllowitExpenseBounds::from_xdr(&f.env, e.expense.as_ref().unwrap()).unwrap();
        match mutation {
            0 => {
                c.conversion_units = 1;
                c.spent_units = 4;
            } // Ordinary payment cannot claim swap classification.
            1 => c.spent_units = 1,
            2 => c.gas_units = 2,
            3 => c.decimals = 6,
            4 => c.day += 1,
            5 => c.observed_ledger = 101,
            _ => c.asset = f.recipient.clone(),
        }
        e.expense = Some(c.to_xdr(&f.env));
        assert_eq!(
            execute(&f, &e),
            Err(Ok(AllowitWalletError::InvalidInvocation))
        );
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
}
#[test]
fn expense_bytes_require_exact_canonical_known_fields_and_bounded_length() {
    use soroban_sdk::xdr::{Limits, ReadXdr, ScMap, ScVal, WriteXdr};
    let f = Fixture::new_native(COMMON);
    let mut e = f.execution(50);
    set_cost(&f, &mut e, 3, 0);
    let original = e.expense.clone().unwrap();
    let mut bytes = [0u8; 1024];
    let n = original.len() as usize;
    original.copy_into_slice(&mut bytes[..n]);
    let ScVal::Map(Some(map)) = <ScVal as ReadXdr>::from_xdr(&bytes[..n], Limits::none()).unwrap()
    else {
        panic!("Expected expense map")
    };
    for mutation in 0..5 {
        let mut fields = map.0.to_vec();
        match mutation {
            0 => fields.swap(0, 1),
            1 => fields.insert(1, fields[0].clone()),
            2 => {
                let mut extra = fields.last().unwrap().clone();
                extra.key = ScVal::Symbol(soroban_sdk::xdr::ScSymbol(
                    b"unknown".to_vec().try_into().unwrap(),
                ));
                fields.push(extra);
            }
            3 => fields[0].val = ScVal::U64(1),
            _ => {}
        }
        let mut encoded = WriteXdr::to_xdr(
            &ScVal::Map(Some(ScMap(fields.try_into().unwrap()))),
            Limits::none(),
        )
        .unwrap();
        if mutation == 4 {
            encoded.extend_from_slice(&[0; 4]);
        }
        e.expense = Some(Bytes::from_slice(&f.env, &encoded));
        assert!(execute(&f, &e).is_err());
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
    e.expense = Some(Bytes::from_slice(&f.env, &[0u8; 1025]));
    assert_eq!(
        execute(&f, &e),
        Err(Ok(AllowitWalletError::InvalidInvocation))
    );
    e.expense = Some(original);
    assert!(execute(&f, &e).is_ok());
}

#[test]
fn standard_prefix_digest_matches_independent_xdr_vector_and_binds_context() {
    let env = Env::default();
    let kind = Symbol::new(&env, "common_policy_engine");
    let module = BytesN::from_array(&env, &[1; 32]);
    let asset = Address::from_str(
        &env,
        "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ",
    );
    let rules = vec![&env, AllowitRule::spent_cap, AllowitRule::recipients];
    let expected = BytesN::from_array(
        &env,
        &[
            66, 101, 232, 202, 129, 105, 213, 21, 159, 38, 227, 129, 92, 65, 30, 68, 142, 108, 9,
            16, 21, 190, 226, 11, 50, 204, 7, 142, 89, 244, 155, 255,
        ],
    );
    assert_eq!(
        standard_prefix_digest(&env, &kind, &module, &asset, &rules),
        expected
    );
    let reversed = vec![&env, AllowitRule::recipients, AllowitRule::spent_cap];
    assert_ne!(
        standard_prefix_digest(&env, &kind, &module, &asset, &reversed),
        expected
    );
    assert_ne!(
        standard_prefix_digest(
            &env,
            &kind,
            &BytesN::from_array(&env, &[3; 32]),
            &asset,
            &rules
        ),
        expected
    );
    assert_ne!(
        standard_prefix_digest(&env, &kind, &module, &Address::generate(&env), &rules),
        expected
    );
}
#[test]
fn owner_grant_update_preserves_prefix_code_usage_and_revokes_old_revision() {
    let f = Fixture::new(COMMON, false);
    f.transfer(50);
    let original = f.client().state();
    let code = f.wallet.executable();
    let inflight = f.execution(1);
    let mut d = f.deployment();
    d.grant.spent_cap = None;
    d.grant.day_spent_cap = None;
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    assert_eq!(f.wallet.executable(), code);
    assert_eq!(f.client().state().source_digest, original.source_digest);
    assert_eq!(f.client().state().nonce, original.nonce);
    assert_eq!(
        execute(&f, &inflight),
        Err(Ok(AllowitWalletError::StaleRequest))
    );
    f.transfer(20);
    // Protected history counts every success, including those while a cap was unset.
    assert_eq!(f.history().spent, 70);
    assert_eq!(f.history().day_spent, 70);
    assert_eq!(f.history().day_total, 70);
    assert_eq!(f.client().state().history.calls, 2);
    let mut d = f.deployment();
    d.grant.spent_cap = Some(75);
    d.grant.day_spent_cap = Some(75);
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    let next = f.execution(6);
    assert_eq!(
        execute(&f, &next),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    assert_eq!(f.balance(), 930);
    assert_eq!(f.history().spent, 70);
    assert_eq!(f.client().state().nonce, 2);
    assert_eq!(f.client().state().source_digest, original.source_digest);
}

#[test]
fn disabled_caps_keep_unpriced_history_and_daily_unknown_expires_only_at_rollover() {
    use soroban_sdk::testutils::Ledger;
    let f = Fixture::new(COMMON, false);
    let mut d = f.deployment();
    d.grant.spent_cap = None;
    d.grant.day_spent_cap = None;
    d.grant.day_total_cap = None;
    d.grant.call_cap = None;
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    let mut e = f.execution(20);
    e.expense = None;
    execute(&f, &e).unwrap().unwrap();
    let history = f.client().state().history;
    assert_eq!(history.calls, 1);
    assert_eq!(history.day_total, 20);
    assert_eq!(history.spent, 0); // Unpriced is an explicit liability, never a zero-cost assertion.
    assert!(history.unpriced && history.day_unpriced);
    let mut d = f.deployment();
    d.grant.spent_cap = Some(1000);
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    assert_eq!(
        execute(&f, &f.execution(1)),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    assert_eq!(f.client().state().history, history);
    let mut d = f.deployment();
    d.grant.spent_cap = None;
    d.grant.day_spent_cap = Some(1000);
    d.grant.day_total_cap = Some(1000);
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    assert_eq!(
        execute(&f, &f.execution(1)),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    f.env.ledger().with_mut(|l| l.timestamp += 86_400);
    execute(&f, &f.execution(1)).unwrap().unwrap();
    let history = f.client().state().history;
    assert_eq!(history.calls, 2);
    assert_eq!(history.day_total, 1);
    assert_eq!(history.day_spent, 1);
    assert!(!history.day_unpriced && history.unpriced);
}
#[test]
fn reenabled_call_cap_counts_operations_while_disabled() {
    let f = Fixture::new(COMMON, false);
    let mut d = f.deployment();
    d.grant.call_cap = None;
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    f.transfer(1);
    f.transfer(1);
    let mut d = f.deployment();
    d.grant.call_cap = Some(2);
    f.auth(&[&f.owner], "deploy_policy", (d.clone(),).into_val(&f.env));
    f.client().deploy_policy(&d);
    assert_eq!(
        execute(&f, &f.execution(1)),
        Err(Ok(AllowitWalletError::PolicyDenied))
    );
    assert_eq!(f.client().state().history.calls, 2);
}

#[test]
fn issued_asset_normalized_gas_is_signed_and_keeps_native_amount_checks() {
    let f = Fixture::new(COMMON, false);
    let v = vault(&f, 11, None);
    allow_recipient(&f, &v);
    let mut e = request(&f, &v, 50, 50);
    set_cost(&f, &mut e, 3, 2);
    let mut cost = AllowitExpenseBounds::from_xdr(&f.env, e.expense.as_ref().unwrap()).unwrap();
    cost.max_fee_stroops = 100;
    e.expense = Some(cost.to_xdr(&f.env));
    assert!(execute(&f, &e).is_ok());
    assert_eq!(f.history().spent, 5);
    assert_eq!(f.history().day_total, 53);
    assert_eq!(f.balance(), 950);
    for mutation in 0..5 {
        let f = Fixture::new(COMMON, false);
        let mut e = f.execution(50);
        set_cost(&f, &mut e, 3, 0);
        let mut cost = AllowitExpenseBounds::from_xdr(&f.env, e.expense.as_ref().unwrap()).unwrap();
        cost.max_fee_stroops = 100;
        match mutation {
            0 => cost.asset = f.recipient.clone(),
            1 => cost.decimals = 6,
            2 => cost.gas_units = -1,
            3 => cost.gas_units = 0,
            _ => cost.max_fee_stroops = 0,
        };
        e.expense = Some(cost.to_xdr(&f.env));
        assert_eq!(
            execute(&f, &e),
            Err(Ok(AllowitWalletError::InvalidInvocation))
        );
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
    for missing_server in [false, true] {
        let f = Fixture::new(COMMON, false);
        let mut e = f.execution(50);
        set_cost(&f, &mut e, 3, 0);
        let mut cost = AllowitExpenseBounds::from_xdr(&f.env, e.expense.as_ref().unwrap()).unwrap();
        cost.max_fee_stroops = 100;
        e.expense = Some(cost.to_xdr(&f.env));
        f.auth(
            &[if missing_server { &f.agent } else { &f.server }],
            "execute",
            (e.clone(),).into_val(&f.env),
        );
        assert!(f.client().try_execute(&e).is_err());
        assert_eq!(f.balance(), 1000);
        assert_eq!(f.client().state().nonce, 0);
    }
}
