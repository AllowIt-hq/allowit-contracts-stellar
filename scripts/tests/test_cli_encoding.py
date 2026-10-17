"""Real CLI spec encoding against a local, read-only RPC fixture."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import contract_admin as ca
from stellar_sdk import Address, Keypair, Network, StrKey, TransactionEnvelope, xdr

CLI = os.environ.get("STELLAR_BIN") or shutil.which("stellar")
WASM = Path(__file__).resolve().parents[2] / "target/wasm32v1-none/release/allowit_odc.wasm"


@unittest.skipUnless(CLI and WASM.exists(), "Build ODC Wasm and set STELLAR_BIN to test CLI encoding")
class RealCliEncoding(unittest.TestCase):
    def test_grant_i128_encoding(self):
        code = WASM.read_bytes()
        digest = hashlib.sha256(code).digest()
        account = Keypair.from_raw_ed25519_seed(bytes([1]) * 32).public_key
        contract = StrKey.encode_contract(bytes([2]) * 32)
        recipient = Keypair.from_raw_ed25519_seed(bytes([3]) * 32).public_key
        grant = {"asset": contract, "recipients": [recipient], "per_transfer": 10, "daily_limit": 20, "total_limit": 30, "max_calls": 5, "expires_at": 1000}
        class Rpc(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                method = request["method"]
                if method == "getNetwork":
                    result = {"passphrase": Network.TESTNET_NETWORK_PASSPHRASE, "protocolVersion": 28}
                elif method == "getLedgerEntries":
                    entries = []
                    for key_xdr in request["params"]["keys"]:
                        key = xdr.LedgerKey.from_xdr(key_xdr)
                        if key.type == xdr.LedgerEntryType.CONTRACT_DATA:
                            instance = xdr.SCContractInstance(xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM, wasm_hash=xdr.Hash(digest)), None)
                            data = xdr.LedgerEntryData(key.type, contract_data=xdr.ContractDataEntry(xdr.ExtensionPoint(0), key.contract_data.contract, key.contract_data.key, key.contract_data.durability, xdr.SCVal(xdr.SCValType.SCV_CONTRACT_INSTANCE, instance=instance)))
                        elif key.type == xdr.LedgerEntryType.CONTRACT_CODE:
                            data = xdr.LedgerEntryData(key.type, contract_code=xdr.ContractCodeEntry(xdr.ContractCodeEntryExt(0), xdr.Hash(digest), code))
                        elif key.type == xdr.LedgerEntryType.ACCOUNT:
                            entry = xdr.AccountEntry(key.account.account_id, xdr.Int64(1000000000), xdr.SequenceNumber(xdr.Int64(42)), xdr.Uint32(0), None, xdr.Uint32(0), xdr.String32(b""), xdr.Thresholds(bytes([1,0,0,0])), [], xdr.AccountEntryExt(0))
                            data = xdr.LedgerEntryData(key.type, account=entry)
                        else:
                            raise AssertionError("Unexpected RPC ledger key")
                        entries.append({"key": key_xdr, "xdr": data.to_xdr(), "lastModifiedLedgerSeq": 10, "liveUntilLedgerSeq": 100000})
                    result = {"entries": entries, "latestLedger": 20}
                else:
                    raise AssertionError("No simulation, signing or submission is expected: " + method)
                body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = HTTPServer(("127.0.0.1", 0), Rpc)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as config:
                cmd = [CLI, "--config-dir", config, "contract", "invoke", "--id", contract, "--source-account", account, "--rpc-url", f"http://127.0.0.1:{server.server_port}", "--network-passphrase", Network.TESTNET_NETWORK_PASSPHRASE, "--build-only", "--", "set_grant"]
                result = subprocess.run(cmd + ca.serialize({"grant": grant, "expected_revision": 0}), check=True, capture_output=True, text=True, timeout=30)
                tx = TransactionEnvelope.from_xdr(result.stdout.strip(), Network.TESTNET_NETWORK_PASSPHRASE)
                self.assertEqual(tx.signatures, [])
                args = tx.transaction.operations[0].host_function.invoke_contract.args
                values = {entry.key.sym.sc_symbol.decode(): entry.val for entry in args[0].map.sc_map}
                self.assertEqual(values["per_transfer"].type, xdr.SCValType.SCV_I128)
                self.assertEqual(values["per_transfer"].i128.lo.uint64, 10)
                self.assertEqual(values["max_calls"].u64.uint64, 5)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()
