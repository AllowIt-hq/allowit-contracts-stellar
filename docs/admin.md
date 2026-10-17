# Wallet administration

These tools prepare transactions. They do not fund accounts, sign, submit or retry them. Use existing funded accounts. Native preparation reads current sequence and signer state from Horizon. Contract preparation uses Stellar CLI 28.1.0 and RPC. Its `--build-only` flag returns raw, unassembled XDR. The contract tool adds five-minute time bounds, then runs `stellar tx simulate` to assemble resource fees, footprint and authorization entries. It rejects changes to transaction intent or unexpected signatures. Its output is assembled unsigned XDR. `--send=no` returns a read simulation result, not unsigned XDR.

Use Python 3.10 or later (below 4.0) and Stellar CLI 28.1.0. Install the pinned Python SDK in a local virtual environment:

```sh
python3 -m venv /tmp/allowit-admin
/tmp/allowit-admin/bin/pip install -r scripts/requirements-admin.txt
/tmp/allowit-admin/bin/python -m unittest discover -s scripts/tests -v
```

Select `--network testnet` explicitly. Mainnet preparation additionally requires `--allow-mainnet`. Public addresses and hashes belong in arguments. Never pass secret seeds. Use Stellar CLI identities backed by the OS secure store for manual signing. `STELLAR_BIN` selects the CLI executable for contract tooling. Contract subprocesses ignore inherited Stellar signing and network overrides.

## Native wallet and engine administrator

The native wallet owner is its account master key. Setup admits only an existing account with master weight 1, no other signers and default thresholds. It atomically adds agent/engine weight 1, changes owner weight to 3, and sets thresholds 2/2/3. Setup never silently replaces existing authority. Signer verification rejects unexpected signers, hash/preauthorized signers and threshold drift.

```sh
python scripts/wallet_admin.py setup-wallet --network testnet --account "$OWNER" --agent "$AGENT" --engine "$ENGINE" > /tmp/setup.xdr
python scripts/wallet_admin.py verify-wallet --network testnet --account "$OWNER" --agent "$AGENT" --engine "$ENGINE"
```

Verification succeeds only after the configuration transaction settles. To disable automation, use `shutdown-wallet` with the same addresses. It atomically removes agent and engine and raises all thresholds to 3. Only the owner can authorize it. Prefer `--transaction-source OTHER_OWNER_ACCOUNT` to use an independent owner-only fee/sequence account. All shutdown operations still name the wallet as their source. Sign with both wallet owner and transaction source. This prevents the agent pair from invalidating shutdown through the wallet sequence, although admission and offer checks can still race ledger changes. Verification rejects open Horizon offers. Shutdown reports offers but still prepares signer removal. Revoke signers first, then reconcile offers and allowances. Removing signers does not revoke persistent SAC allowances, liquidity positions or prior issuer changes. Horizon cannot enumerate all SAC allowances. Read and zero allowances for every known spender separately. Treat unknown prior delegations as unresolved. This native profile grants broad low/medium authority, so shutdown cannot promise complete revocation.

Prepare a separate native engine administrator with `setup-admin --account "$ADMIN" --member "$A" --member "$B" --member "$C"`. The three distinct members receive weight 1. All thresholds become 2. The account master becomes weight 0 unless it is one of those members. `verify-admin` checks that exact configuration. Keep the necessary master and member secure-store identities available before setup.

Review and sign the exact XDR manually:

```sh
stellar tx decode /tmp/setup.xdr
stellar tx sign --network testnet --sign-with-key owner-secure-identity /tmp/setup.xdr > /tmp/setup-signed.xdr
stellar tx send --network testnet /tmp/setup-signed.xdr
```

The source account signs initial setup under its existing master authority. Later admin operations need two member signatures on the same envelope. Native envelopes expire after five minutes and bind the next account sequence. Do not reuse them after other transactions consume that sequence. After an uncertain submission, check the original transaction hash and ledger state before preparing a replacement.

## Contract setup and owner administration

Run `scripts/build-contracts.sh` before contract tests or deployment preparation. It builds the deny-engine test fixture, then restores default production artifacts. Do not deploy a test-feature artifact.

Use `contract_admin.py upload --source "$OWNER" --wasm PATH` separately for `allowit_wallet_engine.wasm`, `allowit_engine_parent.wasm` and `allowit_odc.wasm`. Review, sign and submit each prepared upload manually. Record its resulting Wasm hash.

Prepare `deploy-parent --source "$ADMIN" --admin "$ADMIN" --engine-wasm HASH --wasm target/wasm32v1-none/release/allowit_engine_parent.wasm --wasm-hash PARENT_HASH`, with three `--member` values. The script verifies the exact native admin quorum. Constructor preparation requires the local Wasm and its expected uploaded hash. The tool checks the local bytes and the raw transaction executable against that hash. It passes only `--wasm` to CLI 28.1.0 so constructor arguments work. The constructor creates the shared engine. Read its address with `read --contract PARENT_ADDRESS --source "$ADMIN" --method engine`.

Prepare `deploy-odc --source "$OWNER" --owner "$OWNER" --agent "$AGENT" --engine ENGINE_ADDRESS --wasm target/wasm32v1-none/release/allowit_odc.wasm --wasm-hash ODC_HASH --grant JSON`. Grant JSON contains `asset`, `recipients`, `per_transfer`, `daily_limit`, `total_limit`, `max_calls` and `expires_at`. Amounts are native asset units, not the legacy vault's six-decimal units. Fund the resulting ODC through an exact SAC transfer after deployment.

`admin --family odc --contract ADDRESS --source "$OWNER" --method METHOD --arguments JSON` admits only owner administration and recovery methods. Parent administration uses `--family parent`, the native admin source and three `--member` values. Arguments must match the method exactly, including `expected_revision`. Parent `set_admin` requires a native G candidate and three `--candidate-member` values. The script checks its exact 2-of-3 configuration. Contract administrator candidates remain outside this MVP. The script checks current authority and revision before preparation. ODC deployment and administration also require a native owner account with only its master signer active and satisfiable thresholds. A 3/1/1 native agent wallet cannot serve as that owner. Owner handoff applies the same admission to the candidate. These checks inspect current ledger state. Keep owner signer configuration independent of agent authority afterward. It never admits agent transfers or arbitrary calls.

Owner/admin handoffs require both authorities. Envelope signing alone does not fill independent Soroban authorization entries. Collect and verify those authorizations with the corresponding wallets before submission. Preparation does not establish candidate acceptance. Nested grant i128 fields are encoded as decimal strings for the CLI. Simulation authorization permits matching roots, source credentials and the exact handoff candidate. Invocation roots have no children. Deployment permits one exact source-authorized `__constructor` child at the address derived from the creation preimage and network, with identical arguments and no deeper calls. `--max-fee` caps total and resource fees in stroops (default 1 XLM). Always inspect simulated authorization trees, quoted resource fees and the exact contract identity. The assembled transaction binds its account sequence and expires after five minutes. Archive signed bytes before broadcast. After uncertain submission, reconcile its original hash before preparing a replacement. Archived state requires a separate reviewed restoration transaction. This tool does not restore or retry automatically. Owner pause, recovery, engine binding and code upgrades remain independent of engine approval.
