# AllowIt native Stellar contracts

Private hackathon MVP: native Rust policy Wasm, stable vault instances and an owner-bound factory. Shared Wasm is uploaded once. This MVP uses regular Wasm instances, not CAP-85 executable references.

Funding changes only the token balance; it never recompiles policy or resets spending. Daily limits use UTC calendar days and six-decimal policy units (one token = `1_000_000`). The owner can tune the explicitly declared `daily_limit` within `0..=50_000_000`; zero pauses spending. Custody independently enforces that compiled ceiling. No generic setter exists for other parameters.

Owner approval is standing approval, while each transfer requires the designated executor's signature, native Rust evaluation, asset checks, daily accounting, nonce and current revision. Tuning preserves standing approval; switching policy clears it. Funding, tuning, approval/revocation and policy switches preserve counters. Owner withdrawal and revocation work independently of policy execution. The cap is per vault. Delegation, semantic evaluation, per-action permits, optimizer authority and PaySH are not implemented. The explicit Unsupported method returns error 100; unknown selectors use the chain's invalid-instruction/host errors.

The sibling repositories compile byte-identical `policy/policy.rs` and `policy/policy_api.rs`. Their bundle identity is SHA-256 of `allowit-policy-source-v1` followed by NUL, then each file in that order: filename, NUL, eight-byte little-endian length and contents. The build fails on a stale generated identity. This source identity differs from the executable artifact hash. Clients must pin the approved artifact, chain, ABI, vault/program/factory, asset, owner, executor and revision; a reported source hash alone is not proof of deployed code. Check copies using `python3 scripts/check-policy.py --peer ../OTHER_REPO`.

Persist signed transaction bytes and hash/signature before broadcast. Query that transaction after uncertain results; do not automatically re-sign deposits. Refresh state before retrying a finalized failed or expired request. Finalized token movement proves settlement, separately from service delivery.

## Build and test

Pinned versions: Rust 1.98.0, Soroban SDK 28.0.0, Stellar CLI 28.1.0. The CLI performs SDK 28 contract-spec processing; plain Cargo Wasm compilation is insufficient.

```sh
python3 scripts/check-policy.py
stellar contract build
cargo test --workspace --locked
python3 scripts/artifacts.py
```

Tests execute compiled policy Wasm, token custody and factory deployment of compiled vault Wasm. Run `python3 -u scripts/testnet.py` with funded secure-store identities `allowit-native-owner`, `allowit-native-executor`, `allowit-native-recipient`. The driver is hardcoded to Stellar Testnet and native XLM through its Stellar Asset Contract. It checks recipient token deltas and exercises funding, approval, daily limits, nonce/revision rejection, bounded tuning, revocation, unsupported calls and recovery. This is not USDC or frontend/CLI E2E acceptance.

## ABI and deployment

The exported contract spec and `crates/vault/src/lib.rs` define the ABI. Constructor: owner, executor, asset, policy, source bundle, policy Wasm hash, daily limit. Factory create adds a salt hashed with the authenticated owner. SetPolicy requires the new policy address, source bundle, Wasm hash and expected revision. Approval and tuning require expected revision; transfer requires nonce and revision.

Only seven-decimal Stellar Asset Contracts are accepted. Amounts convert to token units by multiplying by ten. Balance reads floor sub-unit dust; withdrawal cannot recover dust smaller than ten native units.

Every policy use verifies its resolved executable matches the selected Wasm hash, separately from its reported source bundle. The factory pins one vault Wasm at construction. Clients pin an approved factory address, factory/vault/policy Wasm, policy source and authorities. A look-alike factory is not trustworthy just because its ABI matches. None of these contracts exposes a code-upgrade entrypoint. New immutable policy versions coexist; an owner can switch a vault to a new module, clearing approval. Global shared custody patching is not implemented.

Vault/factory storage TTL extends during use. Operators must maintain or restore policy instance/code lifetime; archived policy can block evaluation while owner recovery remains independent. Obtain a fresh RPC simulation for upload, instance, resource and TTL fees before commercial deployment. No Mainnet deployment is included; this MVP is not a production audit.

## Independent review

Claude Code Opus 5.5 found no remaining material blockers for the hackathon MVP. The raw report and exact reviewed code revisions are in `evidence/opus-review.json`. Remaining test gaps and production/governance limitations are retained there. This review did not independently rerun builds or tests.

## Policy entrypoint and system functions

`policy/policy.rs` contains one generated function, `execute`. It calls `require_approval` and `enforce_daily_limit` from `policy/policy_api.rs`. Approval, daily rollover, clock checks, overflow checks and the compiled parameter ceiling belong to this standard library. Custody commits the returned next daily spend atomically with token movement. Both files are included in the pinned source bundle; clients display the literal compiled policy source and can show the exact system-function implementation separately. Chain adapters retain their version-1 ABI.

The existing review record covers the preceding release. The entrypoint refactor was independently reviewed through Claude Code Opus 5.5 with no blocking or material findings. The report and exact reviewed revisions are in `evidence/execute-system-review.json`. Public Solana Testnet acceptance remains pending.
