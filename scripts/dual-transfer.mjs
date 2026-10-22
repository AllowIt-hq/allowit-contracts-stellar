// Testnet acceptance helper; private keys stay inside this short-lived process.
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {Address, Contract, Keypair, Networks, TransactionBuilder, authorizeEntry, nativeToScVal, rpc} from '@stellar/stellar-sdk';

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const server = new rpc.Server('https://soroban-testnet.stellar.org');
const network = Networks.TESTNET;
function cli(args) {
  const linux = process.platform === 'win32' && input.cli.startsWith('/');
  const command = linux ? 'wsl.exe' : input.cli;
  const argv = linux ? ['-d', input.distro || 'Ubuntu', '--', input.cli, ...args] : args;
  const r = spawnSync(command, argv, {encoding: 'utf8', timeout: 30000});
  if (r.status !== 0) throw new Error('The configured Stellar identity could not be loaded.');
  return r.stdout.trim();
}
function integer(value) {
  if (!/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) > 18446744073709551615n) throw new Error('Invalid u64 transfer argument.');
  return nativeToScVal(BigInt(value), {type: 'u64'});
}
async function confirmed(hash) {
  for (let i = 0; i < 45; ++i) {
    const r = await server.getTransaction(hash);
    if (r.status === 'SUCCESS') return;
    if (r.status === 'FAILED') throw new Error(`The original Testnet transaction failed (${hash}).`);
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  throw new Error(`Testnet settlement is unknown; retain the saved proof and reconcile ${hash} before another payment.`);
}
async function main() {
  const intent = {network, vault: input.vault, recipient: input.recipient, amount: input.amount, nonce: input.nonce, revision: input.revision};
  if (fs.existsSync(input.proofPath)) {
    const saved = JSON.parse(fs.readFileSync(input.proofPath, 'utf8'));
    if (JSON.stringify(saved.intent) !== JSON.stringify(intent)) throw new Error('The earlier signed operation has a different intent.');
    await confirmed(saved.hash); // Reconcile only; never sign or broadcast a replacement.
    console.error(`transaction: ${saved.hash}`);
    console.log('null');
    return;
  }
  const executorAddress = cli(['keys', 'address', 'allowit-native-executor']);
  const authorityAddress = cli(['keys', 'address', 'allowit-native-authority']);
  if (executorAddress === authorityAddress) throw new Error('Executor and authority must differ.');
  const account = await server.getAccount(executorAddress);
  const transaction = new TransactionBuilder(account, {fee: '100', networkPassphrase: network})
    .addOperation(new Contract(input.vault).call('transfer', Address.fromString(input.recipient).toScVal(), integer(input.amount), integer(input.nonce), integer(input.revision)))
    .setTimeout(120).build();
  const simulation = await server.simulateTransaction(transaction);
  if (rpc.Api.isSimulationError(simulation)) throw new Error(`The exact transfer was rejected by Testnet simulation: ${simulation.error}`);
  const assembled = rpc.assembleTransaction(transaction, simulation).build();
  const envelope = assembled.toEnvelope();
  const operation = envelope.v1().tx().operations()[0].body().invokeHostFunctionOp();
  const keys = new Map();
  for (const alias of ['allowit-native-executor', 'allowit-native-authority']) {
    const key = Keypair.fromSecret(cli(['keys', 'secret', alias])); // Never logged, written, or passed as a process argument.
    keys.set(key.publicKey(), key);
  }
  const latest = await server.getLatestLedger();
  const entries = [];
  for (const entry of operation.auth()) {
    const credentials = entry.credentials();
    if (credentials.switch().name === 'sorobanCredentialsSourceAccount') { entries.push(entry); continue; }
    const address = credentials.switch().name === 'sorobanCredentialsAddressV2' ? credentials.addressV2().address() : credentials.address().address();
    const key = keys.get(Address.fromScAddress(address).toString());
    if (!key) throw new Error('The exact invocation requested an unexpected signing identity.');
    entries.push(await authorizeEntry(entry, key, latest.sequence + 12, network));
  }
  // Enforcing simulation includes native-account signature verification and its
  // real footprint/resource fee. Start from the original base-fee transaction.
  const authorizedEnvelope = transaction.toEnvelope();
  authorizedEnvelope.v1().tx().operations()[0].body().invokeHostFunctionOp().auth(entries);
  const signed = await server.prepareTransaction(TransactionBuilder.fromXDR(authorizedEnvelope, network));
  signed.sign(keys.get(executorAddress));
  const hash = signed.hash().toString('hex');
  // Durable public proof before the first broadcast. The proof contains no private keys.
  const proof = fs.openSync(input.proofPath, 'wx', 0o600);
  try {
    fs.writeFileSync(proof, JSON.stringify({intent, hash, signedXdr: signed.toXDR()}, null, 2));
    fs.fsyncSync(proof);
  } finally { fs.closeSync(proof); }
  if (process.platform !== 'win32') {
    const directory = fs.openSync(path.dirname(input.proofPath), 'r');
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  }
  const sent = await server.sendTransaction(signed);
  if (sent.status === 'ERROR') throw new Error(`Testnet rejected the original signed transaction (${hash}).`);
  if (sent.hash !== hash) throw new Error('Testnet returned a different transaction hash. Retain the original proof.');
  await confirmed(hash);
  console.error(`transaction: ${hash}`);
  console.log('null');
}
main().catch(error => { console.error(String(error.message).replace(/S[A-Z2-7]{55}/g, '[redacted]')); process.exitCode = 1; });
