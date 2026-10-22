// Recompute the poidh v2 per-wallet dataset straight from contract state and
// (optionally) diff it against a candidate CSV wallet by wallet.
//
//   node verify_v2_state.js base
//   node verify_v2_state.js arbitrum
//   node verify_v2_state.js base candidate.csv
//
// No API key, no indexer: read-only eth_call/Multicall3 against public RPCs.
const fs = require('fs');
const { createPublicClient, http, parseAbi } = require('viem');
const { base, arbitrum } = require('viem/chains');

const CFG = {
  base: {
    chain: base,
    main: '0xb502c5856f7244dccdd0264a541cc25675353d39',
    nft: '0xddfb1a53e7b73dba09f79fca24765c593d447a80',
    rpcs: ['https://base.gateway.tenderly.co', 'https://base-mainnet.public.blastapi.io',
           'https://base.drpc.org', 'https://base-rpc.publicnode.com'],
  },
  arbitrum: {
    chain: arbitrum,
    main: '0x0aa50ce0d724cc28f8f7af4630c32377b4d5c27d',
    nft: '0xddfb1a53e7b73dba09f79fca24765c593d447a80',
    rpcs: ['https://arbitrum-one-rpc.publicnode.com', 'https://arb1.arbitrum.io/rpc',
           'https://arbitrum.drpc.org', 'https://arbitrum.gateway.tenderly.co'],
  },
};

const ABI = parseAbi([
  'function bountyCounter() view returns (uint256)',
  'function claimCounter() view returns (uint256)',
  'function bounties(uint256) view returns (uint256 id, address issuer, string name, string description, uint256 amount, address claimer, uint256 createdAt, uint256 claimId)',
  'function getParticipants(uint256 bountyId) view returns (address[] addresses, uint256[] amounts)',
]);
const NFT_ABI = parseAbi([
  'function totalSupply() view returns (uint256)',
  'function ownerOf(uint256 tokenId) view returns (address)',
]);

// The Dec 8 2025 exploit and the later single-bounty abuse: every bounty settled
// in these transactions is fraudulent and is excluded.
const EXPLOIT_TXS = [
  '0x0545a4e5800632ba2194fb9349264ff7f3d3bb18d28ee168d57369b14422f11f',
  '0xc29091802e4e95eafe0b8b3be53736ccce6dab6928fc978b5876c6c9be2539c4',
];
const EXTRA_FRAUD_BOUNTIES = new Set([450]);

const ZERO = '0x0000000000000000000000000000000000000000';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function chunked(clients, address, abi, fn, ids, batch) {
  const out = new Array(ids.length);
  const jobs = [];
  for (let i = 0; i < ids.length; i += batch) for (let k = 0; k < clients.length; k++) jobs.push({ i, k });
  let next = 0;
  await Promise.all(clients.map(async (_, wi) => {
    while (true) {
      const idx = next++;
      if (idx >= jobs.length) break;
      const { i, k } = jobs[idx];
      const slice = ids.slice(i, i + batch);
      const contracts = slice.map((id) => ({ address, abi, functionName: fn, args: [id] }));
      let done = false;
      for (let a = 0; a < 3 && !done; a++) {
        try {
          const res = await clients[(k + a) % clients.length].multicall({ contracts, allowFailure: false });
          for (let j = 0; j < slice.length; j++) out[i + j] = res[j];
          done = true;
        } catch (e) { await sleep(300); }
      }
      if (!done) throw new Error('multicall ' + fn + ' failed at ' + i);
    }
  }));
  return out;
}

async function exploitBountyIds(cfg) {
  // Read the exploit transactions' logs from any public RPC (eth_getLogs for a
  // single tx is not possible, so we scan the ClaimAccepted events of the two
  // known attack transactions through Blockscout's transaction endpoint).
  const ids = new Set();
  for (const tx of EXPLOIT_TXS) {
    try {
      const r = await fetch(`https://${cfg.chain.id === 8453 ? 'base' : 'arbitrum'}.blockscout.com/api/v2/transactions/${tx}/logs`,
        { headers: { accept: 'application/json' } });
      if (!r.ok) continue;
      const j = await r.json();
      for (const l of j.items || []) {
        if (l.topics && l.topics[0] === '0x68669d605f9b1ca0cb82bb6221846a66f289b2f075ad7be1df396d335da38e5a') {
          const d = (l.data || '0x').slice(2);
          ids.add(Number(BigInt('0x' + d.slice(0, 64))));
        }
      }
    } catch (e) { /* blockscout unavailable: the exclusion list below still applies */ }
  }
  for (const b of EXTRA_FRAUD_BOUNTIES) ids.add(b);
  return ids;
}

(async () => {
  const name = process.argv[2] || 'base';
  const cfg = CFG[name];
  const clients = cfg.rpcs.map((u) => createPublicClient({ chain: cfg.chain, transport: http(u, { timeout: 15000 }) }));
  const main = clients[0];
  const [bC, cC, supply] = await Promise.all([
    main.readContract({ address: cfg.main, abi: ABI, functionName: 'bountyCounter' }),
    main.readContract({ address: cfg.main, abi: ABI, functionName: 'claimCounter' }),
    main.readContract({ address: cfg.nft, abi: NFT_ABI, functionName: 'totalSupply' }),
  ]);
  const bIds = Array.from({ length: Number(bC) }, (_, i) => BigInt(i));
  const nIds = Array.from({ length: Number(supply) }, (_, i) => BigInt(i));
  console.log(`${name}: bounties=${bIds.length} claims=${cC} nft_supply=${nIds.length}`);

  const bounties = await chunked(clients, cfg.main, ABI, 'bounties', bIds, 50);
  const owners = await chunked(clients, cfg.nft, NFT_ABI, 'ownerOf', nIds, 100);

  const zero = ZERO;
  const completed = [];
  for (const b of bounties) {
    if (!b) continue;
    const [, issuer, , , amount, claimer] = b;
    if (!claimer || claimer === zero) continue;
    if (claimer.toLowerCase() === issuer.toLowerCase()) continue;   // cancelled + refunded
    completed.push(b);
  }
  const parts = await chunked(clients, cfg.main, ABI, 'getParticipants', completed.map((b) => BigInt(b[0])), 60);
  const exploit = await exploitBountyIds(cfg);
  console.log('  exploit bounty ids excluded:', exploit.size);

  const paid = new Map(), earned = new Map(), received = new Map(), contributed = new Map();
  const add = (m, w, v) => m.set(w, (m.get(w) || 0n) + v);
  let feeTotal = 0n, exploitGross = 0n, exploitCount = 0;
  for (let k = 0; k < completed.length; k++) {
    const b = completed[k];
    const [id, issuer, , , amount, claimer] = b;
    const gross = amount, fee = (gross * 25n) / 1000n;
    if (exploit.has(Number(id))) { exploitCount++; exploitGross += gross; feeTotal += fee; continue; }
    feeTotal += fee;
    const [pA, pAm] = parts[k] || [[], []];
    const contrib = (pA && pA.length) ? pA.map((a, j) => [a.toLowerCase(), pAm[j]]) : [[issuer.toLowerCase(), gross]];
    const tot = contrib.reduce((s, [, a]) => s + a, 0n) || 1n;
    for (const [w, a] of contrib) { add(contributed, w, a); add(paid, w, (gross * a) / tot); }
    add(earned, claimer.toLowerCase(), gross);
    add(received, claimer.toLowerCase(), gross - fee);
  }
  const nft = new Map();
  for (const o of owners) { if (!o || o === zero) continue; const w = o.toLowerCase(); nft.set(w, (nft.get(w) || 0) + 1); }

  const wallets = new Set([...paid.keys(), ...earned.keys(), ...contributed.keys(), ...nft.keys()]);
  const rows = [...wallets].sort().map((w) => ({
    wallet: w,
    paid: (paid.get(w) || 0n).toString(),
    earned: (earned.get(w) || 0n).toString(),
    contributed: (contributed.get(w) || 0n).toString(),
    received: (received.get(w) || 0n).toString(),
    nfts: nft.get(w) || 0,
  }));
  const sum = (m) => [...m.values()].reduce((a, b) => a + b, 0n);
  console.log(`  wallets=${rows.length} completed=${completed.length - exploitCount} exploit_excluded=${exploitCount} (${exploitGross / 1e18} ETH)`);
  console.log(`  sum(eth_earned)=${sum(earned)} sum(eth_paid_out)=${sum(paid)} sum(eth_received_net)=${sum(received)}`);
  console.log(`  protocol fee=${feeTotal} (${(Number(feeTotal) / Number(sum(earned)) * 100).toFixed(6)}% of gross)`);
  console.log(`  NFTs=${[...nft.values()].reduce((a, b) => a + b, 0)} protocol custody=${nft.get(cfg.main) || 0}`);

  if (process.argv[3] && /\.csv$/.test(process.argv[3])) {
    const lines = fs.readFileSync(process.argv[3], 'utf8').split('\n').filter(l => l && !l.startsWith('#'));
    const head = lines[0].split(',');
    const iW = head.indexOf('wallet'), iP = head.indexOf('eth_paid_out_wei'),
      iE = head.indexOf('eth_earned_wei'), iN = head.indexOf('nfts_held');
    const mine = new Map(rows.map((r) => [r.wallet, r]));
    let bad = 0, checked = 0;
    for (const line of lines.slice(1)) {
      const c = line.split(',');
      const r = mine.get((c[iW] || '').toLowerCase());
      if (!r) { console.log('  ' + c[iW] + ': not in recomputed ledger'); bad++; continue; }
      checked++;
      if (iP >= 0 && c[iP] !== r.paid) { console.log('  ' + r.wallet + ': paid_out candidate=' + c[iP] + ' chain=' + r.paid); bad++; }
      if (iE >= 0 && c[iE] !== r.earned) { console.log('  ' + r.wallet + ': earned candidate=' + c[iE] + ' chain=' + r.earned); bad++; }
      if (iN >= 0 && c[iN] !== String(r.nfts)) { console.log('  ' + r.wallet + ': nfts candidate=' + c[iN] + ' chain=' + r.nfts); bad++; }
    }
    console.log(`  diff: ${bad} mismatching cells across ${checked} candidate rows`);
  }
})();
