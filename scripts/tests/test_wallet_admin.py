import copy
import argparse
import subprocess
from io import BytesIO, StringIO
import json
import hashlib
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wallet_admin as wa
import contract_admin as ca
from stellar_sdk import Keypair, TransactionEnvelope, Account, TransactionBuilder, Address, StrKey, xdr, scval

KEYS = [Keypair.from_raw_ed25519_seed(bytes([n]) * 32).public_key for n in range(1, 6)]
ROOT = Path(__file__).resolve().parents[2]
HEAD = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n"


def source(body, head=HEAD):
    return head + body + "    Ok(())\n}\n"


def leb128(value):
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def meta_wasm(*entries):
    """Minimal Wasm module with one `contractmetav0` section of XDR ScMetaEntry V0 entries."""
    meta = b""
    for key, value in entries:
        meta += bytes(4)
        for field in (key, value):
            meta += len(field).to_bytes(4, "big") + field + bytes(-len(field) % 4)
    name = b"contractmetav0"
    body = leb128(len(name)) + name + meta
    return b"\0asm\x01\0\0\0" + b"\0" + leb128(len(body)) + body


def state():
    return {"account_id": KEYS[0], "sequence": "42", "signers": [
        {"key": KEYS[0], "weight": 1, "type": "ed25519_public_key"}],
        "thresholds": {"low_threshold": 0, "med_threshold": 0, "high_threshold": 0}}


class NativeAdmin(unittest.TestCase):
    def test_owner_only_admission(self):
        wa.owner_only(state())
        value = state()
        value["signers"][0]["weight"] = 3
        value["thresholds"] = dict(zip(("low_threshold", "med_threshold", "high_threshold"), (2, 2, 3)))
        wa.owner_only(value)
        value["signers"] += [{"key": k, "weight": 1, "type": "ed25519_public_key"} for k in KEYS[1:3]]
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            wa.owner_only(value)
        for change in ("zero", "drift", "hash"):
            value = state()
            if change == "zero":
                value["signers"][0]["weight"] = 0
            elif change == "drift":
                value["thresholds"]["high_threshold"] = 2
            else:
                value["signers"].append({"key": "hash", "weight": 1, "type": "sha256_hash"})
            with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                wa.owner_only(value)

    def test_setup_unsigned_atomic_exact(self):
        envelope = wa.prepare(state(), "setup-wallet", "testnet", agent=KEYS[1], engine=KEYS[2], now=1000)
        tx = TransactionEnvelope.from_xdr(envelope.to_xdr(), wa.PASSPHRASE["testnet"])
        self.assertEqual(tx.signatures, [])
        self.assertEqual(tx.transaction.sequence, 43)
        self.assertEqual(tx.transaction.fee, 300)
        self.assertEqual(tx.transaction.preconditions.time_bounds.min_time, 0)
        self.assertEqual(tx.transaction.preconditions.time_bounds.max_time, 1300)
        ops = tx.transaction.operations
        self.assertEqual(len(ops), 3)
        self.assertEqual(ops[0].signer, wa.Signer.ed25519_public_key(KEYS[1], 1))
        self.assertEqual(ops[1].signer, wa.Signer.ed25519_public_key(KEYS[2], 1))
        self.assertEqual((ops[2].master_weight, ops[2].low_threshold, ops[2].med_threshold, ops[2].high_threshold), (3, 2, 2, 3))
        self.assertTrue(all(op.source is None for op in ops))

    def test_setup_rejects_existing_authority(self):
        for malformed in ("threshold", "signer", "preauth", "duplicate"):
            value = state()
            if malformed == "threshold":
                value["thresholds"]["high_threshold"] = 1
            else:
                extra = {"key": KEYS[3], "weight": 1, "type": "ed25519_public_key"}
                if malformed == "preauth":
                    extra["type"] = "preauth_tx"
                if malformed == "duplicate":
                    extra["key"] = KEYS[0]
                value["signers"].append(extra)
            with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                wa.prepare(value, "setup-wallet", "testnet", agent=KEYS[1], engine=KEYS[2])

    def test_shutdown_removes_both_and_raises_thresholds(self):
        value = state()
        value["signers"][0]["weight"] = 3
        value["signers"] += [{"key": k, "weight": 1, "type": "ed25519_public_key"} for k in KEYS[1:3]]
        value["thresholds"] = dict(zip(("low_threshold", "med_threshold", "high_threshold"), (2, 2, 3)))
        wa.wallet(value, KEYS[1], KEYS[2])
        tx = wa.prepare(value, "shutdown-wallet", "testnet", agent=KEYS[1], engine=KEYS[2])
        self.assertEqual([op.signer.weight for op in tx.transaction.operations[:2]], [0, 0])
        self.assertEqual(tx.transaction.operations[-1].med_threshold, 3)
        value["signers"].append({"key": KEYS[4], "weight": 1, "type": "ed25519_public_key"})
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            wa.wallet(value, KEYS[1], KEYS[2])

    def test_shutdown_separate_sequence_and_operation_source(self):
        value = state()
        value["signers"][0]["weight"] = 3
        value["signers"] += [{"key": k, "weight": 1, "type": "ed25519_public_key"} for k in KEYS[1:3]]
        value["thresholds"] = dict(zip(("low_threshold", "med_threshold", "high_threshold"), (2, 2, 3)))
        fee_source = state()
        fee_source["account_id"] = KEYS[4]
        fee_source["sequence"] = "100"
        fee_source["signers"][0]["key"] = KEYS[4]
        tx = wa.prepare(value, "shutdown-wallet", "testnet", agent=KEYS[1], engine=KEYS[2], source_state=fee_source)
        self.assertEqual(tx.transaction.source.account_id, KEYS[4])
        self.assertEqual(tx.transaction.sequence, 101)
        self.assertTrue(all(op.source.account_id == KEYS[0] for op in tx.transaction.operations))
        for delegated in KEYS[1:3]:
            fee_source["account_id"] = delegated
            fee_source["signers"][0]["key"] = delegated
            with self.assertRaises(ValueError):
                wa.prepare(value, "shutdown-wallet", "testnet", agent=KEYS[1], engine=KEYS[2], source_state=fee_source)

    def test_offer_admission(self):
        for records in ([], [{"id": "1"}]):
            payload = json.dumps({"_embedded": {"records": records}}).encode()
            with patch.object(wa, "urlopen", return_value=BytesIO(payload)):
                if records:
                    with self.assertRaises(ValueError):
                        wa.no_offers("testnet", KEYS[0])
                else:
                    wa.no_offers("testnet", KEYS[0])
            if records:
                with patch.object(wa, "urlopen", return_value=BytesIO(payload)), patch.object(sys, "stderr", new_callable=StringIO) as warnings:
                    wa.no_offers("testnet", KEYS[0], reject=False)
                    self.assertIn("Revoke signers first", warnings.getvalue())

    def test_admin_distinct_master_disabled(self):
        tx = wa.prepare(state(), "setup-admin", "testnet", members=KEYS[1:4])
        self.assertEqual(len(tx.transaction.operations), 4)
        last = tx.transaction.operations[-1]
        self.assertEqual((last.master_weight, last.low_threshold, last.med_threshold, last.high_threshold), (0, 2, 2, 2))
        tx2 = wa.prepare(state(), "setup-admin", "testnet", members=KEYS[:3])
        self.assertEqual(tx2.transaction.operations[-1].master_weight, 1)
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            wa.prepare(state(), "setup-admin", "testnet", members=[KEYS[1]] * 3)

    def test_admin_candidate_exact_admission(self):
        value = state()
        with self.assertRaises(ValueError):
            wa.admin(value, KEYS[1:4])
        value["signers"][0]["weight"] = 0
        value["signers"] += [{"key": key, "weight": 1, "type": "ed25519_public_key"} for key in KEYS[1:4]]
        value["thresholds"] = dict.fromkeys(("low_threshold", "med_threshold", "high_threshold"), 2)
        wa.admin(value, KEYS[1:4])
        value["signers"][1]["weight"] = 2
        with self.assertRaises(ValueError):
            wa.admin(value, KEYS[1:4])

    def test_bad_identity_and_fee(self):
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            wa.prepare(state(), "setup-wallet", "testnet", agent=KEYS[0], engine=KEYS[2])
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            wa.prepare(state(), "setup-wallet", "testnet", agent=KEYS[1], engine=KEYS[2], fee=1_000_000)


class ContractAdmin(unittest.TestCase):
    def test_exact_allowlist_and_types(self):
        self.assertEqual(ca.checked_args("set_pause", {"paused": True, "deployment_version": 3}, "wallet")["paused"], True)
        for value in ({"paused": "false", "deployment_version": 3}, {"paused": True, "deployment_version": True}, {"paused": True, "deployment_version": 3, "target": KEYS[1]}):
            with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                ca.checked_args("set_pause", value, "wallet")
        self.assertNotIn("transfer", ca.WALLET)
        self.assertNotIn("approve", ca.WALLET)
        self.assertNotIn("set_grant", ca.PARENT)

    def test_typed_grant_uses_canonical_fields_and_native_ranges(self):
        values = {"spent_cap": 2**127 - 1, "call_cap": 0, "recipients": [KEYS[1]], "tokens": []}
        complete = ca.grant(values)
        self.assertEqual(list(complete), list(ca.GRANT_FIELDS))
        self.assertEqual({k: v for k, v in complete.items() if v is not None}, values)
        self.assertEqual(ca.grant({}), dict.fromkeys(ca.GRANT_FIELDS))
        tagged = json.loads(ca.serialize({"grant": values})[1])
        self.assertEqual(tagged["spent_cap"], str(2**127 - 1))
        self.assertIsNone(tagged["expiry"])
        for invalid in ({"per_transfer": 1}, {"max_calls": 1}, {"daily_limit": 1}, {"spent_cap": -1}, {"spent_cap": 2**127},
                        {"call_cap": 2**64}, {"expiry": True}, {"transaction_cap": "1"}, {"recipients": KEYS[1]},
                        {"tokens": ["not-an-address"]}, {1: 1}):
            with self.assertRaises((ValueError, TypeError)):
                ca.grant(invalid)
        deployment = {"deployment_version": 1, "owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "source_digest": "22" * 32,
                      "rules": ["spent_cap", "recipients"], "grant": values, "x402_enabled": False, "wasm_hash": None}
        ca.deployment(deployment)
        for removed in ("set_cap_per_day", "cap_per_transaction", "require_recipient", "require_asset", "allow_actions", "state_remove", "fail", "daily_cap"):
            with self.assertRaises(ValueError):
                ca.deployment(dict(deployment, rules=[removed]))
        with self.assertRaises(ValueError):
            ca.public_json('{"custom":1,"custom":2}')
        # Owner packets encode the typed layout only; a version 1 Grant-map wallet is refused.
        self.assertEqual(ca.wallet_layout({"contract_version": 2})["contract_version"], 2)
        for state in ({"contract_version": 1}, {"contract_version": 3}, {}):
            with self.assertRaisesRegex(ValueError, "layout"):
                ca.wallet_layout(state)

    def test_assembly_preserves_intent_and_adds_resources(self):
        raw = TransactionBuilder(Account(KEYS[0], 42), wa.PASSPHRASE["testnet"], base_fee=100).append_upload_contract_wasm_op(b"test-wasm").set_timeout(0).build()
        calls = []
        def simulate(arguments, input_data=None):
            calls.append(arguments)
            result = TransactionEnvelope.from_xdr(input_data, wa.PASSPHRASE["testnet"])
            self.assertEqual(result.signatures, [])
            self.assertEqual(result.transaction.preconditions.time_bounds.min_time, 0)
            self.assertEqual(result.transaction.preconditions.time_bounds.max_time, 1300)
            result.transaction.fee += 123
            result.transaction.soroban_data = xdr.SorobanTransactionData(
                xdr.SorobanTransactionDataExt(0),
                xdr.SorobanResources(xdr.LedgerFootprint([], []), xdr.Uint32(100), xdr.Uint32(0), xdr.Uint32(0)),
                xdr.Int64(123))
            return result.to_xdr()
        with patch.object(ca, "cli_run", side_effect=simulate):
            output = ca.prepare_xdr(raw.to_xdr(), KEYS[0], "testnet", now=1000)
        assembled = TransactionEnvelope.from_xdr(output, wa.PASSPHRASE["testnet"])
        self.assertEqual(assembled.signatures, [])
        self.assertIsNotNone(assembled.transaction.soroban_data)
        self.assertEqual(assembled.transaction.source.account_id, KEYS[0])
        self.assertEqual(assembled.transaction.sequence, 43)
        self.assertEqual(assembled.transaction.operations[0].host_function, raw.transaction.operations[0].host_function)
        self.assertEqual(calls, [["tx", "simulate", "--network", "testnet", "--source-account", KEYS[0], "--auth-mode", "root"]])
        for mutation in ("sequence", "bounds", "host", "unsigned_resources", "fee"):
            def altered(arguments, input_data=None):
                result = TransactionEnvelope.from_xdr(simulate(arguments, input_data), wa.PASSPHRASE["testnet"])
                if mutation == "sequence":
                    result.transaction.sequence += 1
                elif mutation == "bounds":
                    result.transaction.preconditions.time_bounds.max_time += 1
                elif mutation == "host":
                    other = TransactionBuilder(Account(KEYS[0], 42), wa.PASSPHRASE["testnet"]).append_upload_contract_wasm_op(b"other-wasm").set_timeout(0).build()
                    result.transaction.operations[0].host_function = other.transaction.operations[0].host_function
                elif mutation == "fee":
                    result.transaction.fee = 10_000_001
                else:
                    result.transaction.soroban_data = None
                return result.to_xdr()
            with patch.object(ca, "cli_run", side_effect=altered):
                with self.assertRaises(ValueError):
                    ca.prepare_xdr(raw.to_xdr(), KEYS[0], "testnet", now=1000)
        with self.assertRaises(ValueError):
            ca.prepare_xdr(raw.to_xdr(), KEYS[1], "testnet", now=1000)

    def test_deployment_constructor_authorization(self):
        create = xdr.CreateContractArgsV2(
            xdr.ContractIDPreimage(xdr.ContractIDPreimageType.CONTRACT_ID_PREIMAGE_FROM_ADDRESS,
                from_address=xdr.ContractIDPreimageFromAddress(Address(KEYS[0]).to_xdr_sc_address(), xdr.Uint256(bytes([5]) * 32))),
            xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM, wasm_hash=xdr.Hash(bytes([6]) * 32)),
            [Address(KEYS[0]).to_xdr_sc_val(), xdr.SCVal(xdr.SCValType.SCV_U64, u64=xdr.Uint64(7))])
        host = xdr.HostFunction(xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2, create_contract_v2=create)
        child = xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(
            xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,
            contract_fn=xdr.InvokeContractArgs(ca.deployment_address(create, "testnet"), xdr.SCSymbol(b"__constructor"), create.constructor_args)), [])
        root = xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(
            xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CREATE_CONTRACT_V2_HOST_FN,
            create_contract_v2_host_fn=create), [child])
        entry = xdr.SorobanAuthorizationEntry(xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT), root)
        operation = ca.InvokeHostFunction(host, auth=[entry])
        ca.validate_auth(operation, network="testnet")
        raw = TransactionBuilder(Account(KEYS[0], 42), wa.PASSPHRASE["testnet"]).append_operation(ca.InvokeHostFunction(host)).set_timeout(0).build()
        def assemble(arguments, input_data=None):
            prepared = TransactionEnvelope.from_xdr(input_data, wa.PASSPHRASE["testnet"])
            prepared.transaction.operations[0].auth = [copy.deepcopy(entry)]
            prepared.transaction.fee += 123
            prepared.transaction.soroban_data = xdr.SorobanTransactionData(xdr.SorobanTransactionDataExt(0), xdr.SorobanResources(xdr.LedgerFootprint([], []), xdr.Uint32(100), xdr.Uint32(0), xdr.Uint32(0)), xdr.Int64(123))
            return prepared.to_xdr()
        with patch.object(ca, "cli_run", side_effect=assemble):
            assembled = TransactionEnvelope.from_xdr(ca.prepare_xdr(raw.to_xdr(), KEYS[0], "testnet", now=1000, expected_wasm="06" * 32), wa.PASSPHRASE["testnet"])
        self.assertEqual(assembled.transaction.operations[0].auth, [entry])
        self.assertEqual(assembled.signatures, [])
        with patch.object(ca, "cli_run") as simulated:
            with self.assertRaises(ValueError):
                ca.prepare_xdr(raw.to_xdr(), KEYS[0], "testnet", expected_wasm="07" * 32)
            simulated.assert_not_called()
        with self.assertRaises(ValueError):
            ca.validate_auth(operation, network="mainnet")
        for mutation in ("address", "name", "args", "deep", "candidate", "duplicate", "extra", "missing"):
            altered = copy.deepcopy(operation)
            node = altered.auth[0].root_invocation.sub_invocations[0]
            if mutation == "address":
                node.function.contract_fn.contract_address = Address(StrKey.encode_contract(bytes([9]) * 32)).to_xdr_sc_address()
            elif mutation == "name":
                node.function.contract_fn.function_name = xdr.SCSymbol(b"transfer")
            elif mutation == "args":
                node.function.contract_fn.args = []
            elif mutation == "deep":
                node.sub_invocations = [copy.deepcopy(child)]
            elif mutation == "candidate":
                altered.auth[0].credentials = xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS, address=xdr.SorobanAddressCredentials(Address(KEYS[1]).to_xdr_sc_address(), xdr.Int64(1), xdr.Uint32(100), xdr.SCVal(xdr.SCValType.SCV_VOID)))
            elif mutation == "duplicate":
                altered.auth.append(copy.deepcopy(entry))
            elif mutation == "extra":
                altered.auth[0].root_invocation.sub_invocations.append(copy.deepcopy(child))
            else:
                altered.auth[0].root_invocation.sub_invocations = []
            with self.assertRaises(ValueError, msg=mutation):
                ca.validate_auth(altered, candidate=KEYS[1], network="testnet")

    def test_simulated_authorization_scope(self):
        contract = StrKey.encode_contract(bytes([8]) * 32)
        tx = TransactionBuilder(Account(KEYS[0], 42), wa.PASSPHRASE["testnet"]).append_invoke_contract_function_op(contract, "set_paused", []).set_timeout(0).build()
        op = tx.transaction.operations[0]
        root = xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN, contract_fn=op.host_function.invoke_contract), [])
        source = xdr.SorobanAuthorizationEntry(xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT), root)
        op.auth = [source]
        ca.validate_auth(op)
        candidate = xdr.SorobanAuthorizationEntry(xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS, address=xdr.SorobanAddressCredentials(Address(KEYS[1]).to_xdr_sc_address(), xdr.Int64(1), xdr.Uint32(100), xdr.SCVal(xdr.SCValType.SCV_VOID))), copy.deepcopy(root))
        op.auth.append(candidate)
        ca.validate_auth(op, KEYS[1])
        with self.assertRaises(ValueError):
            ca.validate_auth(op)
        with self.assertRaises(ValueError):
            ca.validate_auth(op, KEYS[2])
        op.auth = [source, source]
        with self.assertRaises(ValueError):
            ca.validate_auth(op)
        op.auth = [source]
        source.root_invocation.sub_invocations = [copy.deepcopy(root)]
        with self.assertRaises(ValueError):
            ca.validate_auth(op)
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            ca.checked_args("set_admin", {"owner": contract, "version": 0}, "parent")
        with self.assertRaises(ValueError):
            ca.checked_args("recover", {"recipient": KEYS[1], "amount": 0, "version": 0}, "wallet")

    def test_cli_address_errors_do_not_echo_input(self):
        scripts = Path(__file__).resolve().parents[1]
        invalid_input = "invalid-private-input-for-test"
        cases = [
            ("wallet_admin.py", ["inspect", "--account", invalid_input]),
            ("wallet_admin.py", ["setup-wallet", "--account", KEYS[0], "--agent", invalid_input]),
            ("wallet_admin.py", ["setup-admin", "--account", KEYS[0], "--member", invalid_input]),
            ("contract_admin.py", ["read", "--source", invalid_input]),
            ("contract_admin.py", ["deploy-parent", "--source", KEYS[0], "--member", invalid_input]),
        ]
        for script, arguments in cases:
            result = subprocess.run([sys.executable, str(scripts / script)] + arguments, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(invalid_input, result.stdout + result.stderr)
            self.assertIn("Expected a public Stellar G address", result.stderr)

    def test_cli_preparation_cannot_submit(self):
        args = SimpleNamespace(network="testnet", allow_mainnet=False, action="upload", source=KEYS[0], wasm="artifact.wasm")
        command = ca.command(args)
        self.assertIn("--build-only", command)
        self.assertNotIn("--send=yes", command)
        args.network = "mainnet"
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            ca.command(args)
        args.allow_mainnet = True
        self.assertIn("--build-only", ca.command(args))

    def test_parent_arguments_use_owner_and_version(self):
        values = {"owner": KEYS[1], "version": 0}
        self.assertEqual(ca.checked_args("set_admin", values, "parent"), values)
        for old in ({"new_admin": KEYS[1], "expected_revision": 0},
                    {"owner": KEYS[1], "version": -1},
                    {"owner": KEYS[1], "version": 2**64}):
            with self.assertRaises(ValueError):
                ca.checked_args("set_admin", old, "parent")

    def test_deployment_requires_matching_local_wasm(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.wasm"
            path.write_bytes(b"test-wasm")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            options = SimpleNamespace(action="deploy-parent", network="testnet", allow_mainnet=False, source=KEYS[0],
                wasm=str(path), wasm_hash=expected, owner=KEYS[0], engine_wasm="11" * 32)
            command = ca.command(options)
            self.assertIn("--wasm", command)
            self.assertNotIn("--wasm-hash", command)
            options.wasm_hash = "00" * 32
            with self.assertRaises(ValueError):
                ca.command(options)
            options.wasm = None
            with self.assertRaises(ValueError):
                ca.command(options)

    def test_wallet_constructor_requires_explicit_nonzero_policy_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wallet.wasm"
            path.write_bytes(b"reviewed-artifact")
            asset = StrKey.encode_contract(bytes([2]) * 32)
            engine = StrKey.encode_contract(bytes([3]) * 32)
            values = {"expiry": 2000000000}
            config = {"owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "asset": asset,
                "source_digest": "22" * 32, "rules": [], "grant": values, "x402_enabled": False, "policy_instance": "11" * 32}
            policy = Path(directory) / "policy.rs"
            policy.write_text(source(""))
            args = SimpleNamespace(action="deploy-wallet", network="testnet", allow_mainnet=False, tier="simple", policy_source=str(policy),
                source=KEYS[0], config=json.dumps(config), wasm=str(path), wasm_hash=hashlib.sha256(path.read_bytes()).hexdigest())
            command = ca.command(args)
            self.assertEqual(json.loads(command[command.index("--config") + 1])["policy_instance"], "11" * 32)
            for identity in (None, "", "00" * 32, "not-a-policy-id"):
                config["policy_instance"] = identity
                args.config = json.dumps(config)
                with self.assertRaises(ValueError):
                    ca.command(args)

    def test_standard_prefix_is_derived_from_policy_source_statements(self):
        sample = (ROOT / "crates/custom-policy/policy/policy.rs").read_text()
        self.assertEqual(ca.standard_prefix(sample), list(ca.GRANT_FIELDS))
        call = "    allowit::{0}(ctx, &ctx.grant.{0})?;\n".format
        vectors = [
            # A mismatched Grant reference ends the prefix; later calls run offchain or in Custom.
            (call("recipients") + "    allowit::spent_cap(ctx, &ctx.grant.day_spent_cap)?;\n" + call("expiry"), ["recipients"]),
            # Statements, not lines: a split call, two calls on one line and comments.
            ("    allowit::spent_cap(\n        ctx,\n        &ctx.grant.spent_cap,\n    )?;\n" + call("expiry").rstrip() + call("tokens"), ["spent_cap", "expiry", "tokens"]),
            ("    // limits\n" + call("call_cap") + "    /* then */ " + call("call_cap"), ["call_cap", "call_cap"]),
            # Any other statement ends the prefix.
            ("    let left = allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;\n" + call("expiry"), []),
            (call("expiry") + "    if ctx.request.operation == AllowitOperation::sep56_deposit {\n" + call("spent_cap") + "    }\n", ["expiry"]),
            (call("expiry") + "    allowit::spent_cap(ctx, &ctx.grant.spent_cap);\n" + call("tokens"), ["expiry"]),
        ]
        vectors += [(call(name) + call("expiry"), []) for name in
                    ("set_cap_per_day", "cap_per_transaction", "require_recipient", "require_asset", "allow_actions", "state_remove", "fail")]
        for body, expected in vectors:
            with self.subTest(body=body):
                self.assertEqual(ca.standard_prefix(source(body)), expected)
        explicit = HEAD.replace("allowit::Result {", "allowit::Result<()> {")
        self.assertEqual(ca.standard_prefix(source(call("tokens"), explicit)), ["tokens"])
        # Calls in other functions are not part of execute.
        helper = "fn helper(ctx: &AllowitContext) -> allowit::Result {\n" + call("tokens") + "    Ok(())\n}\n"
        self.assertEqual(ca.standard_prefix(helper + source(call("expiry"))), ["expiry"])
        for invalid in (helper, source("") + source("")):
            with self.assertRaisesRegex(ValueError, "execute"):
                ca.standard_prefix(invalid)

    def test_standard_prefix_lexes_comments_and_literals_like_rust(self):
        call = "    allowit::{0}(ctx, &ctx.grant.{0})?;\n".format
        # Block comments nest: the whole span is a comment, so recipients runs first.
        nested = "    /* outer /* inner */ allowit::spent_cap(ctx, &ctx.grant.spent_cap)?; */\n" + call("recipients")
        self.assertEqual(ca.standard_prefix(source(nested)), ["recipients"])
        # Literals cannot add, hide or end calls; a quote char and lifetimes are not strings.
        helper = "fn quote<'a>(x: &'a str) -> char { let _ = x; '\"' }\nconst C: char = '\\'';\n"
        raw = 'const R: &str = r#"*/ /* "quoted" "#;\nconst B: &[u8] = b"//";\n'
        self.assertEqual(ca.standard_prefix(helper + raw + source(call("expiry") + "    let s = \"/*\";\n" + call("tokens"))), ["expiry"])
        self.assertEqual(ca.standard_prefix(helper + source("    // \" /*\n" + call("expiry"))), ["expiry"])
        # A header inside a literal is not code. With the real header in prelude form, none matches.
        fake = 'const S: &str = "pub fn execute(ctx: &AllowitContext) -> allowit::Result { ' + call("spent_cap").strip() + '";\n'
        for invalid in (fake + source(call("recipients"), HEAD.replace("allowit::Result {", "Result {")),
                        fake.replace('"', "r#\"", 1).replace('";', '"#;') + source("", HEAD.replace("allowit::Result {", "Result {")),
                        "/* pub fn execute(ctx: &AllowitContext) -> allowit::Result {\n" + call("spent_cap") + "*/\npub fn r#execute(ctx: &AllowitContext) -> Result {\n    Ok(())\n}\n",
                        source(call("expiry")) + "pub use execute as r#execute;\n"):
            with self.subTest(source=invalid), self.assertRaisesRegex(ValueError, "execute"):
                ca.standard_prefix(invalid)
        for unterminated in ("/* /* */", 'const S: &str = "', 'const R: &str = r#"x"'):
            with self.subTest(source=unterminated), self.assertRaisesRegex(ValueError, "unterminated"):
                ca.standard_prefix(source(call("expiry")) + unterminated)

    def test_owner_packets_bind_rules_derived_from_the_policy_source(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            text = source("    allowit::recipients(ctx, &ctx.grant.recipients)?;\n    allowit::expiry(ctx, &ctx.grant.expiry)?;\n")
            policy.write_text(text)
            digest = hashlib.sha256(text.encode()).hexdigest()
            packet = {"rules": ["recipients", "expiry"], "source_digest": "22" * 32}
            self.assertEqual(ca.policy_rules(packet, "common", str(policy)), packet)
            for tier, rules, source_digest in (("common", ["recipients"], "22" * 32), ("common", ["expiry", "recipients"], "22" * 32),
                                               ("simple", ["recipients", "expiry"], "22" * 32), ("custom", [], "22" * 32),
                                               (None, ["recipients", "expiry"], "22" * 32)):
                with self.assertRaises(ValueError):
                    ca.policy_rules({"rules": rules, "source_digest": source_digest}, tier, str(policy))
            self.assertEqual(ca.policy_rules({"rules": [], "source_digest": digest}, "custom", str(policy))["rules"], [])
            self.assertEqual(ca.policy_rules({"rules": [], "source_digest": "22" * 32}, "simple", str(policy))["rules"], [])
            with self.assertRaises(ValueError):
                ca.policy_rules(packet, "common", None)
            # The admin packet path applies the same binding.
            deployment = {"deployment_version": 1, "owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "source_digest": "22" * 32,
                          "rules": ["expiry"], "grant": {}, "x402_enabled": False, "wasm_hash": None}
            args = SimpleNamespace(action="admin", network="testnet", allow_mainnet=False, source=KEYS[0], family="wallet",
                                   contract=StrKey.encode_contract(bytes([2]) * 32), method="deploy_policy", tier="common",
                                   policy_source=str(policy), arguments=json.dumps({"deployment": deployment}))
            with self.assertRaisesRegex(ValueError, "standard prefix"):
                ca.command(args)
            deployment["rules"] = ["recipients", "expiry"]
            args.arguments = json.dumps({"deployment": deployment})
            self.assertIn("deploy_policy", ca.command(args))

    def test_policy_source_cannot_rebind_allowit(self):
        call = "    allowit::{0}(ctx, &ctx.grant.{0})?;\n".format
        body = call("recipients") + call("expiry")
        self.assertEqual(ca.standard_prefix(source(body)), ["recipients", "expiry"])
        # A local `allowit` would make the trusted prefix call a different function.
        fake = "pub fn recipients(_: &AllowitContext, _: &Option<()>) -> allowit::Result<()> { Ok(()) }"
        rebinds = (
            "mod allowit { " + fake + " }\n",
            "pub mod allowit {}\n",
            "mod r#allowit {}\n",
            "use core as allowit;\n",
            "use core::{self as allowit};\n",
            "use self::inner::allowit;\n",
            "use inner::{allowit, other};\n",
            "extern crate core as allowit;\n",
            "macro_rules! allowit { () => {} }\n",
            "fn allowit() {}\n",
            "struct allowit;\n",
            "enum allowit {}\n",
            "trait allowit {}\n",
            "type allowit = u8;\n",
            "const allowit: u8 = 0;\n",
            "static allowit: u8 = 0;\n",
            "macro_rules! m { ($i:ident) => { mod $i {} } }\nm!(allowit);\n",
        )
        for rebind in rebinds:
            for text in (rebind + source(body), source(body) + rebind):
                with self.subTest(source=text), self.assertRaisesRegex(ValueError, "rebind"):
                    ca.standard_prefix(text)
        # Inside execute too, and through the owner packet path of every tier.
        with self.assertRaisesRegex(ValueError, "rebind"):
            ca.standard_prefix(source("    let allowit = 0;\n" + body))
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            policy.write_text(rebinds[0] + source(body))
            digest = hashlib.sha256(policy.read_bytes()).hexdigest()
            for tier, rules, source_digest in (("common", ["recipients", "expiry"], "22" * 32), ("custom", [], digest), ("simple", [], "22" * 32)):
                with self.subTest(tier=tier), self.assertRaisesRegex(ValueError, "rebind"):
                    ca.policy_rules({"rules": rules, "source_digest": source_digest}, tier, str(policy))
        # Comments, literals and longer identifiers are not bindings.
        allowed = '// mod allowit {}\nconst S: &str = "use x as allowit;";\nfn allowit_helper() {}\n'
        self.assertEqual(ca.standard_prefix(allowed + source(body)), ["recipients", "expiry"])

    def test_policy_source_is_one_self_contained_file(self):
        call = "    allowit::{0}(ctx, &ctx.grant.{0})?;\n".format
        body = call("expiry")
        outside = (
            'include!("more.rs");\n',
            'const S: &str = include_str!("secret.txt");\n',
            'const B: &[u8] = core::include_bytes!("data.bin");\n',
            'const E: &str = env!("HOME");\n',
            'const O: Option<&str> = option_env!("POLICY");\n',
            "use core::include as inline;\n",
            '#[path = "other.rs"]\nmod other {}\n',
            '#[cfg_attr(all(), path = "other.rs")]\nmod other {}\n',
            "mod other;\n",
            "pub(crate) mod r#other ;\n",
            "macro_rules! m { ($i:ident) => { mod $i; } }\n",
            "extern crate core;\n",
            # Code that can behave differently in CustomPolicy and on the host.
            'const W: bool = cfg!(target_family = "wasm");\n',
            '#[cfg(target_family = "wasm")]\nconst W: bool = true;\n',
            "#[ cfg (test)]\nfn t() {}\n",
            "const M: &str = module_path!();\n",
            "const F: &str = file ! ();\n",
            "fn n() -> &'static str { core::any::type_name::<AllowitContext>() }\n",
            "fn n(c: &AllowitContext) -> &str { core::any::type_name_of_val(c) }\n",
            "use core::any::type_name as n;\n",
            # Paths into the including crate, and global paths.
            "const H: [u8; 32] = super::SOURCE_HASH;\n",
            "use crate::policy as p;\n",
            "fn s() -> u8 { self :: inner() }\n",
            "macro_rules! m { () => { $crate::x } }\n",
            "const N: u32 = ::core::u32::MAX;\n",
            "fn g(x: ::core::primitive::u8) {}\n",
            "fn g() -> u8 { (|| ::core::primitive::u8::MAX)() }\n",
        )
        for code in outside:
            for text in (code + source(body), source(body) + code):
                with self.subTest(source=text), self.assertRaisesRegex(ValueError, "self-contained"):
                    ca.standard_prefix(text)
        with self.assertRaisesRegex(ValueError, "self-contained"):
            ca.standard_prefix(source('    let _ = include_str!("x");\n' + body))
        for inner in ("#![allow(unused)]\n", "# ! [allow(unused)]\n", "//! Policy\n", "/*! Policy */\n"):
            with self.subTest(source=inner), self.assertRaisesRegex(ValueError, "inner"):
                ca.standard_prefix(inner + source(body))
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            policy.write_text(source(body) + outside[0])
            digest = hashlib.sha256(policy.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "self-contained"):
                ca.policy_rules({"rules": [], "source_digest": digest}, "custom", str(policy))
        # Inline modules and mentions in comments or literals stay valid.
        allowed = ('mod helpers { pub fn one() -> u8 { 1 } }\n// include!("x")\nconst S: &str = "mod other;";\n'
                   "const T: &str = \"crate::x cfg!(test) ::core\";\npub(crate) fn two() -> u8 { Vec::<u8>::new().len() as u8 + 2 }\n"
                   "fn three(file: u8, x: core :: primitive :: u8) -> u8 { <u8 as Default>::default() + file + x }\n")
        self.assertEqual(ca.standard_prefix(allowed + source(body)), ["expiry"])
        # The CustomPolicy sources pass the same check.
        for path in ("crates/custom-policy/policy/policy.rs", "crates/custom-policy/src/branch_policy.rs"):
            ca.checked_code((ROOT / path).read_text())
        result = subprocess.run([sys.executable, str(ROOT / "scripts/check-policy-bindings.py")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wallet_code_changes_require_custody_layout_2(self):
        self.assertEqual(ca.custody_layout(meta_wasm((b"rsver", b"1.98.0"), (ca.CUSTODY_LAYOUT_KEY, b"2"))), 2)
        # The version 1 release declares only SDK metadata.
        self.assertIsNone(ca.custody_layout(meta_wasm((b"rsver", b"1.98.0"))))
        self.assertIsNone(ca.custody_layout(b"\0asm\x01\0\0\0"))
        for invalid in (meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"2"), (ca.CUSTODY_LAYOUT_KEY, b"2")),
                        meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"02")), meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"x")),
                        meta_wasm((b"rsver", b"1"))[:-2], b"not-wasm"):
            with self.subTest(wasm=invalid), self.assertRaises(ValueError):
                ca.custody_layout(invalid)
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            policy.write_text(source("    allowit::expiry(ctx, &ctx.grant.expiry)?;\n"))
            deployment = {"deployment_version": 1, "owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "source_digest": "22" * 32,
                          "rules": ["expiry"], "grant": {}, "x402_enabled": False, "wasm_hash": None}
            args = SimpleNamespace(action="admin", network="testnet", allow_mainnet=False, source=KEYS[0], family="wallet",
                                   contract=StrKey.encode_contract(bytes([2]) * 32), method="deploy_policy", tier="common",
                                   policy_source=str(policy), wasm=None)

            def prepare(wasm_bytes, wasm_hash=None):
                path = Path(directory) / "wallet.wasm"
                path.write_bytes(wasm_bytes)
                deployment["wasm_hash"] = wasm_hash or hashlib.sha256(wasm_bytes).hexdigest()
                args.wasm, args.arguments = str(path), json.dumps({"deployment": deployment})
                return ca.command(args)

            self.assertIn("deploy_policy", prepare(meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"2"))))
            # The old Map-Grant release, a future layout and an unpinned file reject.
            for wasm_bytes, wasm_hash in ((meta_wasm((b"rsver", b"1.98.0")), None), (meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"1")), None),
                                          (meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"3")), None), (meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"2")), "11" * 32)):
                with self.subTest(wasm=wasm_bytes), self.assertRaises(ValueError):
                    prepare(wasm_bytes, wasm_hash)
            args.wasm = None
            with self.assertRaisesRegex(ValueError, "--wasm"):
                ca.command(args)
            # Unchanged code needs no Wasm.
            deployment["wasm_hash"] = None
            args.arguments = json.dumps({"deployment": deployment})
            self.assertIn("deploy_policy", ca.command(args))

    @unittest.skipUnless((ROOT / "target/wasm32v1-none/release/allowit_common_policy_engine.wasm").exists(), "contracts not built")
    def test_built_wallet_wasm_declares_custody_layout_2(self):
        for name in ("simple_policy_engine", "common_policy_engine", "custom_policy"):
            wasm = (ROOT / "target/wasm32v1-none/release" / ("allowit_" + name + ".wasm")).read_bytes()
            self.assertEqual(ca.custody_layout(wasm), ca.WALLET_CONTRACT_VERSION)
        self.assertIsNone(ca.custody_layout((ROOT / "target/wasm32v1-none/release/allowit_wallet_engine.wasm").read_bytes()))

    def test_recover_prepares_without_reading_state(self):
        contract = StrKey.encode_contract(bytes([2]) * 32)
        calls = []

        def cli(args, input_data=None):
            calls.append(args)
            if args[-1] == "state":
                # A version 1 State under version 2 code: state() fails with InvalidState.
                raise subprocess.CalledProcessError(1, args, stderr="Error(Contract, #1)")
            return "raw-xdr"

        argv = ["contract_admin.py", "admin", "--source", KEYS[0], "--contract", contract, "--method", "recover",
                "--arguments", json.dumps({"recipient": KEYS[1], "amount": 5})]
        with patch.object(sys, "argv", argv), patch.object(ca, "fetch", return_value=state()), \
                patch.object(ca, "cli_run", side_effect=cli), patch.object(ca, "prepare_xdr", return_value="assembled") as prepared, \
                patch.object(sys, "stdout", new_callable=StringIO) as output:
            ca.main()
        self.assertEqual(output.getvalue().strip(), "assembled")
        self.assertEqual([call[-1] for call in calls], ["5"])
        self.assertEqual(prepared.call_args.kwargs["candidate"], None)
        # Other owner methods still check the current state and fail closed.
        argv[argv.index("recover")] = "set_pause"
        argv[-1] = json.dumps({"paused": True, "deployment_version": 1})
        with patch.object(sys, "argv", argv), patch.object(ca, "fetch", return_value=state()), \
                patch.object(ca, "cli_run", side_effect=cli), self.assertRaises(subprocess.CalledProcessError):
            ca.main()

    def test_secrets_and_hashes_reject(self):
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            ca.account("owner-key-alias")
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            ca.code_hash("123")
        self.assertEqual(ca.serialize({"paused": False}), ["--paused", "false"])


if __name__ == "__main__":
    unittest.main()
