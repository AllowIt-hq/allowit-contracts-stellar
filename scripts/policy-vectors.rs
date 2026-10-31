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
/// State key that the catching policy counts its caught daily cap errors in.
pub const OVER: &str = "over_day_cap";
/// Custom param key that the catching policy reads with `transaction_cap`.
pub const INVOICE_CAP: &str = "invoice_cap";
/// Execution param key that makes the catching policy apply its invoice cap.
pub const INVOICE: &str = "invoice";

/// One rule input: params, current state before the operation, and request with its args.
/// A `None` param is absent.
#[derive(Clone, Debug)]
pub struct Vector {
    pub name: &'static str,
    /// `transaction_cap`, `spent_cap`, `day_spent_cap` and `day_total_cap`.
    pub caps: [Option<i128>; 4],
    pub call_cap: Option<u64>,
    pub recipients: Option<Vec<usize>>,
    pub tokens: Option<Vec<usize>>,
    pub expiry: Option<u64>,
    /// The custom `invoice_cap` param, which only Custom wallets admit.
    pub invoice_cap: Option<i128>,
    pub calls: u64,
    pub spent: i128,
    pub unpriced: bool,
    pub day: u64,
    pub day_spent: i128,
    pub day_total: i128,
    pub day_unpriced: bool,
    /// The catching policy's own state key, if set.
    pub over: Option<u64>,
    pub deposit: bool,
    pub asset: usize,
    pub recipient: usize,
    pub amount: i128,
    pub now: u64,
    pub expires_at: u64,
    pub spent_units: i128,
    pub gas_units: i128,
    /// The request carries expense bounds.
    pub priced: bool,
    /// The agent's args carry the `invoice` execution param.
    pub invoice: bool,
}

/// A vector that passes every rule with headroom left. After it, spent and day_spent are 45 and
/// day_total is 43.
pub fn base() -> Vector {
    Vector {
        name: "base",
        caps: [Some(100), Some(1000), Some(500), Some(600)],
        call_cap: Some(3),
        recipients: Some(vec![RECIPIENT, VAULT]),
        tokens: Some(vec![ASSET]),
        expiry: Some(NOW + 1000),
        invoice_cap: None,
        calls: 0,
        spent: 5,
        unpriced: false,
        day: NOW / SECONDS_PER_DAY,
        day_spent: 5,
        day_total: 3,
        day_unpriced: false,
        over: None,
        deposit: false,
        asset: ASSET,
        recipient: RECIPIENT,
        amount: 40,
        now: NOW,
        expires_at: NOW + 400,
        spent_units: 40,
        gas_units: 0,
        priced: true,
        invoice: false,
    }
}

fn edit(name: &'static str, change: fn(&mut Vector)) -> Vector {
    let mut v = base();
    v.name = name;
    change(&mut v);
    v
}

/// The shared vector set. Some vectors are host-only because the wallet kernel cannot produce
/// them, such as a deposit into the transfer-only custom contract.
pub fn vectors() -> Vec<Vector> {
    vec![
        base(),
        edit("boundary", |v| {
            v.caps = [Some(40), Some(45), Some(45), Some(43)];
            v.call_cap = Some(1);
            v.expiry = Some(v.expires_at);
        }),
        edit("with_gas", |v| {
            v.gas_units = 3;
            v.spent_units = 43;
            v.caps = [Some(40), Some(48), Some(48), Some(46)];
        }),
        edit("with_gas_over_day_total_cap", |v| {
            v.gas_units = 3;
            v.spent_units = 43;
            v.caps[3] = Some(45);
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
        edit("over_day_spent_cap_counted_once", |v| {
            v.caps[2] = Some(44);
            v.over = Some(1);
        }),
        edit("over_day_spent_cap_counted_twice", |v| {
            v.caps[2] = Some(44);
            v.over = Some(2);
        }),
        edit("over_day_total_cap", |v| v.caps[3] = Some(42)),
        edit("zero_call_cap", |v| v.call_cap = Some(0)),
        edit("over_call_cap", |v| v.calls = 3),
        edit("unpriced_lifetime", |v| v.unpriced = true),
        edit("unpriced_today", |v| {
            v.unpriced = true;
            v.day_unpriced = true;
        }),
        edit("unpriced_request", |v| {
            v.priced = false;
            v.spent_units = 0;
        }),
        edit("unpriced_request_without_cost_caps", |v| {
            v.priced = false;
            v.spent_units = 0;
            v.caps = [Some(100), None, None, None];
        }),
        edit("earlier_day_rolls_over", |v| {
            v.day -= 1;
            v.day_spent = 499;
            v.day_total = 599;
            v.day_unpriced = true;
        }),
        edit("later_day", |v| v.day += 1),
        edit("empty_allowlists", |v| {
            v.recipients = Some(Vec::new());
            v.tokens = Some(Vec::new());
        }),
        edit("other_recipient", |v| v.recipient = OTHER),
        edit("other_asset", |v| v.asset = OTHER),
        edit("params_expired", |v| {
            v.now = NOW + 1000;
            v.expires_at = NOW + 1001;
        }),
        edit("request_outlives_params", |v| {
            v.expiry = Some(v.expires_at - 1)
        }),
        edit("negative_cap", |v| v.caps[0] = Some(-1)),
        edit("zero_amount", |v| v.amount = 0),
        edit("negative_spent", |v| v.spent = -1),
        edit("negative_request_units", |v| v.spent_units = -1),
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
        // A custom param alone changes nothing; an `invoice` arg applies the invoice cap.
        edit("invoice_cap_without_invoice", |v| v.invoice_cap = Some(39)),
        edit("invoice_within_cap", |v| {
            v.invoice = true;
            v.invoice_cap = Some(40);
        }),
        edit("invoice_over_cap", |v| {
            v.invoice = true;
            v.invoice_cap = Some(39);
        }),
        edit("invoice_without_cap", |v| v.invoice = true),
    ]
}

/// Text of one result, identical on both backends: `ok:<value>` or `err:<code>`.
pub fn show<T: std::fmt::Display>(result: Result<T, u32>) -> String {
    match result {
        Ok(value) => format!("ok:{value}"),
        Err(code) => format!("err:{code}"),
    }
}

/// Text of a state map's standard values and the catching policy's key, identical on both backends.
#[allow(clippy::too_many_arguments)]
pub fn state_line(
    calls: u64,
    spent: i128,
    unpriced: bool,
    day: u64,
    day_spent: i128,
    day_total: i128,
    day_unpriced: bool,
    over: Option<u64>,
) -> String {
    let over = over.map_or(String::from("-"), |n| format!("{n}"));
    format!("{calls}/{spent}/{unpriced}/{day}/{day_spent}/{day_total}/{day_unpriced}/{over}")
}

/// Every outcome a policy author can observe on one vector: the sample, branch and catching
/// policies, each rule, the standard preflight runner, the post-flight state without policy
/// writes, and the catching policy's evaluation for a Custom and a standard wallet.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    pub policy: Result<(), u32>,
    pub branch: Result<(), u32>,
    pub catching: Result<(), u32>,
    /// Rule results in canonical key order. Address pass values are `@<index>`.
    pub rules: Vec<Result<String, u32>>,
    /// Preflight results in canonical key order.
    pub preflight: Vec<Result<(), u32>>,
    /// `post_flight` with no policy writes, as `state_line`; the same for every tier.
    pub next: Result<String, u32>,
    /// `evaluate` of the catching policy for a Custom wallet, which stores its key.
    pub catching_next: Result<String, u32>,
    /// `evaluate` of the catching policy for a standard wallet, which denies any write.
    pub catching_standard: Result<String, u32>,
}

impl Outcome {
    /// One output line of the host smoke.
    pub fn line(&self, name: &str) -> String {
        let list = |items: Vec<String>| items.join(",");
        let unit = |r: &Result<(), u32>| show(r.map(|()| "()"));
        format!(
            "vector {name} policy={} branch={} catching={} rules={} preflight={} next={} catching_next={} catching_standard={}",
            unit(&self.policy),
            unit(&self.branch),
            unit(&self.catching),
            list(self.rules.iter().cloned().map(show).collect()),
            list(self.preflight.iter().map(unit).collect()),
            show(self.next.clone()),
            show(self.catching_next.clone()),
            show(self.catching_standard.clone()),
        )
    }
}
