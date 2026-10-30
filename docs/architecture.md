# Policy wallet engines

Wallets keep one immutable underlying Stellar Asset Contract (SAC). The owner selects code, agent,
independent server signer and Grant. SimplePolicyEngine relies on agent/server authorization.
CommonPolicyEngine is the standard implementation for an owner-approved initial preflight prefix.
CustomPolicy artifacts retain an explicit compiled-source binding. Shared checkers have no custody.

## One policy and its standard prefix

Source uses one matching Grant argument: `allowit::spent_cap(grant::spent_cap)?;`.
The SDK extracts only consecutive initial top-level canonical calls. Any subset is valid.
Conditional calls and other custom logic run offchain within the same policy.
The standard contract receives the exact owner-approved ordered prefix, never caller selectors.

| Rule and same-named Grant key | Native value and meaning |
| --- | --- |
| `transaction_cap` | Nonnegative I128/U64 gross underlying units for one operation |
| `spent_cap` | Nonnegative cumulative irreversible-expense ceiling |
| `day_spent_cap` | Nonnegative UTC-day irreversible-expense ceiling |
| `day_total_cap` | Nonnegative UTC-day gross amount plus separate attributable gas |
| `call_cap` | U64 successful operation count ceiling |
| `recipients` | `Vec<Address>` permitted destinations, including vaults |
| `expiry` | U64 exclusive Unix timestamp |
| `tokens` | `Vec<Address>` exact permitted SAC identities |

Missing or Null owner parameters disable that selected check. Wrong non-Null types reject.
Unreadable state never becomes absence. Unmentioned checks do not activate through Grant keys.
Repeated rules retain exact order and use independent operation markers to avoid duplicate charges.
Changed economic facts cannot reuse a prior operation marker. Grant changes preserve accounting.
Protected `State.history` records every delegated success independently of selected or disabled rules.
Rules read the proposed history through `EngineRequest.history`, separate from mutable business Spent.
With cost bounds it records conservative expenses and gas. Without them it records raw gross and calls
plus an unpriced liability. Active lifetime expense caps reject lifetime unpriced history.
Daily expense/total caps reject unpriced history for that UTC day. Rollover clears only daily liability.
No owner reconciliation or refund method silently clears this protected history.

## Source and configuration binding

Fixed standard `source_digest` is SHA-256 of canonical XDR containing the domain
`allowit_std_prefix`, implementation kind, actual module hash, immutable SAC, transfer/deposit schema
hashes and ordered `(rule, matching Grant reference)` pairs. It excludes Grant values and full
source. The constructor and binding getter check it against the actual runtime module.
Custom `source_digest` remains its exact compiled source hash.

The complete source has separate offline owner authorization, scoped to wallet, network, policy,
prefix and monotonic source revision. Changing only that offchain suffix needs no chain call.
Each execution separately carries `source_hash`, covered by agent/server authorization and the x402
digest. Offline updates do not replace already signed operation bytes or their recovery identity.

`deploy_policy` changes owner configuration at exactly the next `deployment_version`.
With `wasm_hash=None`, Grant values change without code redeployment. Prefix, Spent, custody,
execution nonce and pause remain intact when only Grant changes. The new revision rejects old
inflight packets. A changed prefix or executable requires a new owner binding.

## Expenses and native effects

An external payment spends principal plus attributable gas. A deposit retains principal as shares.
Its conversion cost plus attributable gas counts toward spent limits. Daily total includes principal
plus separate gas; embedded conversion fees are not counted twice. Underlying units use seven
decimals. Share units retain their independent native scale.

`ExecutionRequest.expense` is optional bounded canonical XDR of `ExpenseBounds`: asset, decimals,
gas units, conversion units, spent units, attributable fee ceiling, observation ledger and UTC day.
Unknown fields, wrong types, noncanonical maps, extra data and oversized bytes reject.
The server approves exact conservative economic ceilings. The kernel checks denomination, day,
ledger and operation-class identities. It cannot observe final transaction gas. XLM/stroop identity
conversion is intrinsic; other gas conversions need an admitted trusted source.
Onchain counters retain ceilings. The server separately settles actual expenses and temporary loss.
No automatic onchain refund authority follows from that accounting.

`execute` and the owner-enabled x402 transfer hook require agent and server authority. The kernel
checks source/module/schema, immutable asset, exact parties/amount, positive debit, pause, expiry,
configuration version, execution nonce and single-use operation ID independently of business checks.
State, effects and receipts commit atomically. Denials and native failures roll them back.

SEP-56 deposits bind vault, assets, minimum shares and wallet source/operator/share receiver.
Ordinary `recipients` controls destination vaults; no separate vault list or code-hash pin applies.
The vault must report the immutable underlying SAC. Custody authorizes one exact deeper
`transfer(wallet, vault, assets)`. Extra debits, including a second debit later refunded, lack authority.
Returned shares must match the observed balance credit and meet the minimum. Any conversion-loss
ceiling also checks `preview_redeem(actual_shares)`. Foreign reads precede final balances.
The immutable SAC balance read is last. A vault getter cannot mutate already-checked effects.

`TransferReceipt` retains the underlying leg. `deposit_receipt(operation_id)` and `sep56_deposit`
record the observed share output. Vault code can misreport ownership, valuation or redeemability.
The wrapper bounds SAC spending and interface observations; it cannot prove investment value.
Owner `invoke` can redeem shares independently. The server reconciles actual settled redemptions.

## Owner authority and public metadata

Owner pause, configuration, recovery, upgrades and exact `invoke` bypass agent/server business checks
and never call an engine. Owner authorization binds exact target, arguments and supplied subtrees.
`policy_binding()` reports the default profile; `policy_binding_for(schema_digest)` checks another
admitted profile. `policy_spent()` returns the complete raw map without a public setter.
Unknown stored layouts reject. Upgrades do not migrate state implicitly.

Classic G-address multisig has no contract prefix enforcement. Owner-selected signer thresholds
control native transactions. Its policy source and economic checks run offchain before signing.
