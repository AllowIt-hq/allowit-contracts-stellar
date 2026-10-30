// Shared backend-neutral vectors of the portability test. Plain Rust without dependencies, so the
// std-only host smoke (`policy-smoke.rs`) and the Soroban contract test in `allowit-policy-wallet`
// include the same file. Addresses are indices into a shared address universe.

/// Address universe indices.
pub const ASSET: usize = 0;
pub const RECIPIENT: usize = 1;
pub const VAULT: usize = 2;
pub const OTHER: usize = 3;
/// Universe size.
pub const ADDRESSES: usize = 4;
/// UTC day length in seconds.
const SECONDS_PER_DAY: u64 = 86_400;
/// Request time of the base vector.
pub const NOW: u64 = 2 * SECONDS_PER_DAY + 100;

/// One rule input: Grant, proposed history and request.
#[derive(Clone, Debug)]
pub struct Vector {
    pub name: &'static str,
    /// `transaction_cap`, `spent_cap`, `day_spent_cap` and `day_total_cap`.
    pub caps: [Option<i128>; 4],
    pub call_cap: Option<u64>,
    pub recipients: Option<Vec<usize>>,
    pub tokens: Option<Vec<usize>>,
    pub expiry: Option<u64>,
    pub calls: u64,
    pub spent: i128,
    pub unpriced: bool,
    pub day: u64,
    pub day_spent: i128,
    pub day_total: i128,
    pub day_unpriced: bool,
    pub deposit: bool,
    pub asset: usize,
    pub recipient: usize,
    pub amount: i128,
    pub now: u64,
    pub expires_at: u64,
}

/// A vector that passes every rule with headroom left.
pub fn base() -> Vector {
    Vector {
        name: "base",
        caps: [Some(100), Some(1000), Some(500), Some(600)],
        call_cap: Some(3),
        recipients: Some(vec![RECIPIENT, VAULT]),
        tokens: Some(vec![ASSET]),
        expiry: Some(NOW + 1000),
        calls: 1,
        spent: 45,
        unpriced: false,
        day: NOW / SECONDS_PER_DAY,
        day_spent: 45,
        day_total: 43,
        day_unpriced: false,
        deposit: false,
        asset: ASSET,
        recipient: RECIPIENT,
        amount: 40,
        now: NOW,
        expires_at: NOW + 400,
    }
}

fn edit(name: &'static str, change: fn(&mut Vector)) -> Vector {
    let mut v = base();
    v.name = name;
    change(&mut v);
    v
}

/// The shared vector set. Some vectors are host-only because the wallet kernel cannot produce
/// them, such as another UTC day or a deposit into the transfer-only custom contract.
pub fn vectors() -> Vec<Vector> {
    vec![
        base(),
        edit("boundary", |v| {
            v.caps = [Some(40), Some(45), Some(45), Some(43)];
            v.call_cap = Some(1);
            v.expiry = Some(v.expires_at);
        }),
        edit("to_vault", |v| v.recipient = VAULT),
        edit("deposit", |v| {
            v.deposit = true;
            v.recipient = VAULT;
        }),
        edit("deposit_over_spent_cap", |v| {
            v.deposit = true;
            v.recipient = VAULT;
            v.caps[1] = Some(44);
        }),
        edit("deposit_unset_spent_cap", |v| {
            v.deposit = true;
            v.recipient = VAULT;
            v.caps[1] = None;
        }),
        edit("over_transaction_cap", |v| v.caps[0] = Some(39)),
        edit("over_spent_cap", |v| v.caps[1] = Some(44)),
        edit("over_day_spent_cap", |v| v.caps[2] = Some(44)),
        edit("over_day_total_cap", |v| v.caps[3] = Some(42)),
        edit("zero_call_cap", |v| v.call_cap = Some(0)),
        edit("over_call_cap", |v| v.calls = 4),
        edit("unpriced_lifetime", |v| v.unpriced = true),
        edit("unpriced_today", |v| {
            v.unpriced = true;
            v.day_unpriced = true;
        }),
        edit("another_day", |v| v.day -= 1),
        edit("empty_allowlists", |v| {
            v.recipients = Some(Vec::new());
            v.tokens = Some(Vec::new());
        }),
        edit("other_recipient", |v| v.recipient = OTHER),
        edit("other_asset", |v| v.asset = OTHER),
        edit("grant_expired", |v| {
            v.now = NOW + 1000;
            v.expires_at = NOW + 1001;
        }),
        edit("request_outlives_grant", |v| {
            v.expiry = Some(v.expires_at - 1)
        }),
        edit("negative_cap", |v| v.caps[0] = Some(-1)),
        edit("zero_amount", |v| v.amount = 0),
        edit("negative_spent", |v| v.spent = -1),
        edit("unset_transaction_cap", |v| v.caps[0] = None),
        edit("unset_spent_cap", |v| v.caps[1] = None),
        edit("unset_day_spent_cap", |v| v.caps[2] = None),
        edit("unset_day_total_cap", |v| v.caps[3] = None),
        edit("unset_call_cap", |v| v.call_cap = None),
        edit("unset_recipients", |v| v.recipients = None),
        edit("unset_tokens", |v| v.tokens = None),
        edit("unset_expiry", |v| v.expiry = None),
        edit("unset_everything", |v| {
            v.caps = [None; 4];
            v.call_cap = None;
            v.recipients = None;
            v.tokens = None;
            v.expiry = None;
        }),
    ]
}

/// Text of one result, identical on both backends: `ok:<value>` or `err:<code>`.
pub fn show<T: std::fmt::Display>(result: Result<T, u32>) -> String {
    match result {
        Ok(value) => format!("ok:{value}"),
        Err(code) => format!("err:{code}"),
    }
}

/// Every outcome a policy author can observe on one vector: the sample, branch and catching
/// policies through `allowit::run`, each rule, and the standard preflight runner.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    pub policy: Result<(), u32>,
    pub branch: Result<(), u32>,
    pub catching: Result<(), u32>,
    /// Rule results in Grant field order. Address pass values are `@<index>`.
    pub rules: Vec<Result<String, u32>>,
    /// Preflight results in Grant field order.
    pub preflight: Vec<Result<(), u32>>,
}

impl Outcome {
    /// One output line of the host smoke.
    pub fn line(&self, name: &str) -> String {
        let list = |items: Vec<String>| items.join(",");
        format!(
            "vector {name} policy={} branch={} catching={} rules={} preflight={}",
            show(self.policy.map(|()| "()")),
            show(self.branch.map(|()| "()")),
            show(self.catching.map(|()| "()")),
            list(self.rules.iter().cloned().map(show).collect()),
            list(
                self.preflight
                    .iter()
                    .map(|r| show(r.map(|()| "()")))
                    .collect()
            ),
        )
    }
}
