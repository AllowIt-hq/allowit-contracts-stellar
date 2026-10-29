# Mainnet contract preparation

`mainnet_release.py` prepares one bounded ODC smoke deployment. It never signs, submits, funds or retries transactions. Python dependencies and Stellar CLI versions follow [administration](admin.md). Use a private directory for plans and packets. Never place seeds in these files.

The tool admits default contracts at `304bbd61dd211f516d7449716a980fe02fd87194` only. It checks every build-source digest, compiler pin, reviewed artifact manifest and the three default Wasm hashes. Custom policies and test-feature artifacts require a separately reviewed release. The default policy returns `Ok(())`. Owner grant limits and shared-engine veto still apply.

## Prepare the plan

Build the selected revision with `scripts/build-contracts.sh`. Generate its manifest with `python scripts/artifacts.py --output /PRIVATE/manifest.json`. A tooling revision descended from the selected contract revision is admitted when every build-source digest still matches that contract revision. Copy [the plan template](../scripts/mainnet-plan.example.json) to that directory. Replace all `REPLACE` values. Use absolute artifact paths or paths relative to the plan. Set expiry to a reviewed future Unix time.

The owner and agent must each have only their native master key active. The parent administrator must have exactly three weight-one Ed25519 members and thresholds 2/2/2. Keep these accounts separate. Fund them independently before preparation. Keep each source above its classic reserve plus all assigned stage fee caps. Keep the owner above those amounts plus the funding principal. Check liabilities and other pending transactions separately. Preflight checks authority but does not calculate spendable balances. This tool does not create accounts or change signers.

Example fee caps total 50 XLM. They are planning ceilings, not fee quotations. Payment principal is 0.001 XLM, with initial ODC funding capped at 0.002 XLM. Review all caps before use. Classic reserves and other account funding remain separate.

```sh
python scripts/mainnet_release.py check --plan /PRIVATE/plan.json --allow-mainnet --output /PRIVATE/check.json
python scripts/mainnet_release.py preflight --plan /PRIVATE/plan.json --allow-mainnet --output /PRIVATE/preflight.json
```

`check` is offline. Its output gives the unique packet directory for the plan digest. `preflight` reads public account and network state. Every CLI request uses the explicit endpoint and passphrase selected by the tool.

## Deployment and smoke execution

Obtain explicit approval before exporting private Wasm or transaction arguments to the public RPC. Add `--allow-payload-export` only after that approval. This flag authorizes preparation, not signing or payment.

Prepare stages in this order: `upload-engine`, `upload-parent`, `upload-odc`, `deploy-parent`, `deploy-odc`, `fund`, `execute`. Each stage requires successful settlement of all previous original packets. The parent constructor creates the engine. Select `--parent` from the settled parent packet and `--wallet` from the settled ODC packet.

```sh
python scripts/mainnet_release.py prepare --plan /PRIVATE/plan.json --allow-mainnet --allow-payload-export --stage upload-engine --output /PRIVATE/packets-PLAN_DIGEST/upload-engine.json
python scripts/mainnet_release.py settle --plan /PRIVATE/plan.json --allow-mainnet --prepared /PRIVATE/packets-PLAN_DIGEST/upload-engine.json --output /PRIVATE/upload-engine-status.json
```

Between these commands, inspect the first packet's `unsigned_xdr`, exact Wasm/contract identity, constructor arguments, fee, expiry and authorization tree. Copy its `unsigned_xdr` value to a private XDR file. Use an independent secure wallet to authorize that exact packet. Complete any required Soroban authorization entries. Archive the signed bytes before the operator broadcasts them. These scripts provide no broadcast command.

Do not overwrite packets or prepare a replacement under the same plan. One immutable packet exists per stage. The sum of the seven fee bids cannot exceed the plan cap. One funding packet and one execution packet limit the smoke principal. A copied plan or another signing tool is outside this local cap. An expired, failed or uncertain packet requires explicit reconciliation and a separately reviewed plan before replacement.

For `deploy-odc`, add `--parent C...`. For `fund` and `execute`, add both `--parent C...` and `--wallet C...`. Execution also requires a retained nonzero 32-byte `--operation-id HEX`. Use the unique stage packet path printed by `check`. Deploy sequentially because constructors need settled dependencies and each packet expires after five minutes.

After funding settles, prepare rejection simulations before the single real smoke execution:

```sh
python scripts/mainnet_release.py simulate-e2e --plan /PRIVATE/plan.json --allow-mainnet --allow-payload-export --parent C... --wallet C... --operation-id HEX --output /PRIVATE/e2e.json
```

This checks a positive receipt, forbidden recipient, excess amount, stale revision and expiry. After execution settles, use a new operation ID and `--replay-id ORIGINAL_HEX` to test replay rejection. No simulated effects settle or extend TTL. Repeated execution simulations require sufficient remaining grant capacity.

`settle` queries the original transaction hash. `NOT_FOUND` and other uncertain states remain unresolved. Never release reservations or sign replacements from those results. Successful settlement reports the charged fee and rejects charges above the prepared bid or stage cap. Funding requires zero initial ODC XLM balance and checks its exact settled increase. Successful execution checks the exact receipt, current wallet/recipient XLM balances and calls/total counters against the prepared snapshot. Concurrent owner activity can prevent that exact comparison and needs reconciliation. Use a new status-output filename for each observation.

## Release acceptance

These commands cover ODC contract deployment and a direct transfer smoke test. Repeat integrated native and ODC Testnet settlement/restart acceptance at the selected SDK, CLI, service and app revisions before a release decision. Formal audit, lifetime maintenance, account reserves and owner approval remain separate release requirements. Monitor every code/state dependency TTL. A read simulation does not renew it. Follow [administration](admin.md) for submitted TTL maintenance and restoration.
