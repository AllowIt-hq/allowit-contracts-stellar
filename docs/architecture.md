# Policy wallet engines

Policy wallets hold one immutable native Stellar Asset Contract (SAC) asset. The owner chooses
wallet code, agent, independent server signer and policy configuration. The server signer is not a
shared checker contract or its parent administrator.

| Implementation | Delegated authorization | Local policy |
| --- | --- | --- |
| `SimplePolicyEngine` | Agent and server | Custody invariants only. The server checks the authored policy offchain. |
| `CommonPolicyEngine` | Agent and server | Ordered owner-selected canonical checks using Grant and current Spent. |
| `CustomPolicy` | Agent and server | Bespoke compiled local policy using wallet mixins. |

All implementations use a direct owner-selected Wasm executable. A system-managed reference cannot
replace wallet custody code. The [engine parent](engine-parent.md) manages shared checker code
only. Policy compilation recommends an implementation compatible with the selected rail and the
complete policy semantics. Wallet policies run their selected checks locally, with no shared fallback.

## Common and custom policy

Common's `rules` is an ordered list of zero-extra-parameter function names: `transaction_cap`,
`daily_cap`, `total_cap`, `call_cap`, `recipient`, `expiry`, and `token`. Each receives the normalized
request, owner Grant and current Spent. There are no extra authored arguments. Unknown or duplicate selectors reject. An empty list explicitly selects no local business checks, like Simple. The wallet enforces only the rules that the owner selects explicitly.

| Rule | Required Grant values | Updated Spent |
| --- | --- | --- |
| `transaction_cap` | Positive `per_transfer` in native units | None |
| `daily_cap` | Positive `daily_limit` in native units | UTC `day`, `daily`, `daily_operation` |
| `total_cap` | Positive `total_limit` in native units | `total`, `total_operation` |
| `call_cap` | U64 `max_calls`; zero denies every call | `calls`, `call_operation` |
| `recipient` | `recipients: Vec<Address>` | None |
| `expiry` | `expires_at: u64`, exclusive Unix seconds | None |
| `token` | `token: String`, authenticated asset label | None |

Amount limits accept positive native I128 or U64 values. Each canonical rule checks its selected
parameters and usage values. Invalid values or a denied check reject execution. Checks pass their
resulting Spent map to the next selected check. Operation markers prevent duplicate charges for
one operation. All rules preserve unrelated native values without coercion.

Simple requires an empty rule list. Grant fields alone do not create local enforcement. Custom
also uses an empty selector list because its compiled code defines the complete check sequence. The sample
calls local daily, total and call rules, then increments its own `custom_count`. Its source digest
must equal the compiled source. Mixins protect authority and execution mechanics independently of
that business state. Custom code is owner-selected code and therefore remains trusted for custody.

## Configuration and effects

`PolicyConfig` contains `owner`, `agent`, `server`, `asset`, `policy_instance`, `source_digest`,
`rules`, `grant`, and `x402_enabled`. Owner, agent and server must differ. The asset is an admitted
native SAC. The nonzero policy identity and asset stay fixed. Source digests bind the owner-approved
policy. The exact wallet Wasm hash identifies implementation code.

Grant is an owner-signed map of UTF-8 names to native values. Spent is a separate persistent map
under the stable policy identity. Only the final policy result commits. An unused empty map creates
no entry, and unchanged data avoids another write. Archived persistent records require restoration.
The wallet never treats archival as a fresh allowance. Normal calls do not migrate stored state.

The kernel checks the complete invocation, installed module and schema, source wallet, immutable
asset, positive amount, recipient, pause, expiry, deployment version, execution nonce and replay.
Direct execution requires native authorization from both agent and server. Sender debit and
recipient credit must match the exact transfer. Delegated execution and recovery reject issuer destinations because these burn tokens. The owner can explicitly burn through `invoke`. Usage, nonce, receipt and effects commit atomically.

`policy_binding()` reports `engine_kind`, `contract_version`, logical identity, exact module hash,
source digest, argument schema digest and private `_execute` selector. Its tier identifier does not
replace verification of the executable hash. `policy_spent()` returns the full raw map.

## x402 and owner operations

The owner explicitly enables x402. Both agent and server must then be G-addresses. The wallet derives
their raw Ed25519 master public keys and requires both signatures over SHA-256 of XDR
`(Symbol("allowit_wallet_v1"), host_payload, execution)`. The host payload binds network, native
nonce, expiry and invocation tree. The hook admits one exact installed-SAC transfer context and
uses the same local policy, replay and usage checks as direct execution. The wallet caches asset metadata before the active token call. Native SAC effects and hook state changes roll back together.

Changing a classic account signer or master weight does not revoke this explicit raw-key x402 delegation. The wallet owner must disable x402, pause the wallet, or replace the agent/server address through `deploy_policy`. Direct `execute` follows native account signer thresholds.

`deploy_policy` atomically signs owner, agent, server, source digest, rules, Grant, x402 enablement,
optional wallet Wasm hash and the next deployment version. A changed owner must accept the packet.
Deployment preserves pause, Spent and execution nonce. Only `set_pause` changes pause.

Owner recovery and `invoke(contract, function, args, auth)` require the current owner. They bypass
delegated business limits and preserve delegated Spent and nonce. Passthrough authorization binds
the exact target, function, arguments and all supplied nested authorization trees. The owner can
therefore authorize token allowances or other general operations deliberately. Agent and server
cannot use that path. Native transaction sequencing and Soroban authorization nonces prevent replay
of an owner's signed authorization. No automatic shared checker participates in owner operations.

Wallet release/layout, owner deployment sequence and parent administration version are distinct.
Unknown stored formats reject. Simple, Common and Custom share the version-1 layout. Tier changes must install matching rules and source digest; delegated admission validates the active tier after an upgrade. For an incompatible layout, the owner must select reviewed code that reads the retained layout and performs the explicit migration. Installing code that cannot read that layout can disable owner recovery and upgrades. Pausing alone does not prevent this. Contract upgrades require explicit owner authorization.

## Classic Stellar accounts

A classic G-address account can implement Simple-style authorization with owner weight 3, agent
and server weights 1, low/medium thresholds 2 and high threshold 3. The owner can act alone, while
the agent and server must jointly authorize delegated transfers. Admission must reject extra
signers and preserve the owner-only high-threshold path.

This route has no Soroban custody contract or contract storage rent. Classic account and subentry
reserves still apply. Policy checks run in the server before signing. Common onchain rules and
bespoke CustomPolicy code require a compatible contract rail.
