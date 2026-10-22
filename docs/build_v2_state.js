// Rebuild the poidh v2 dataset from CONTRACT STATE (a truncated log scrape is
// not good enough): every bounty, every participant split and every NFT owner
// is read straight from the chain with Multicall3, spread over several public
// RPCs so the whole thing finishes in seconds.
//
//   node v2_state.js base
//   node v2_state.js arbitrum
const fs = require('fs');
const { createPublicClient, http, parseAbi } = require('viem');
const { base, arbitrum } = require('viem/chains');

const CFG = {
  base: {
    chain: base,
    rpcs: [
      'https://base.gateway.tenderly.co',
      'https://base-mainnet.public.blastapi.io',
      'https://base.drpc.org',
      'https://base-rpc.publicnode.com',
      'https://mainnet.base.org',
    ],
    main: '0xb502c5856f7244dccdd0264a541cc25675353d39',
    nft: '0xddfb1a53e7b73dba09f79fca24765c593d447a80',
    blockscout: 'https://base.blockscout.com',
    // the exploit transactions (whole history of the Dec 8 2025 attack + the
    // later single-bounty abuse); every bounty settled inside them is fraud.
    exploitTxs: [
      '0x0545a4e5800632ba2194fb9349264ff7f3d3bb18d28ee168d57369b14422f11f',
      '0xc29091802e4e95eafe0b8b3be53736ccce6dab6928fc978b5876c6c9be2539c4',
    ],
  },
  arbitrum: {
    chain: arbitrum,
    rpcs: [
      'https://arbitrum-one-rpc.publicnode.com',
      'https://arb1.arbitrum.io/rpc',
      'https://arbitrum.drpc.org',
      'https://arbitrum.gateway.tenderly.co',
    ],
    main: '0x0aa50ce0d724cc28f8f7af4630c32377b4d5c27d',
    nft: '0xddfb1a53e7b73dba09f79fca24765c593d447a80',
    blockscout: 'https://arbitrum.blockscout.com',
    exploitTxs: [],
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
  'function balanceOf(address owner) view returns (uint256)',
  'function ownerOf(uint256 tokenId) view returns (address)',
]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function chunked(clients, address, abi, fn, ids, argsExtra, batch = 250) {
  const out = new Array(ids.length);
  const jobs = [];
  for (let i = 0; i < ids.length; i += batch) {
    for (let k = 0; k < clients.length; k++) jobs.push({ i, k });
  }
  let next = 0;
  const workers = clients.map(async (_, wi) => {
    while (true) {
      const idx = next++;
      if (idx >= jobs.length) break;
      const { i, k } = jobs[idx];
      const slice = ids.slice(i, i + batch);
      const contracts = slice.map((id) => ({
        address,
        abi,
        functionName: fn,
        args: argsExtra ? [id, ...argsExtra] : [id],
      }));
      let done = false;
      const t0 = Date.now();
      for (let attempt = 0; attempt < 3 && !done; attempt++) {
        try {
          const res = await clients[(k + attempt) % clients.length].multicall({
            contracts,
            allowFailure: false,
          });
          for (let j = 0; j < slice.length; j++) out[i + j] = res[j];
          done = true;
          if (Date.now() - t0 > 4000) console.log(`    ${fn} chunk ${i} took ${Date.now() - t0}ms`);
        } catch (e) {
          await sleep(300);
        }
      }
      if (!done) throw new Error('multicall ' + fn + ' failed at ' + i);
    }
  });
  await Promise.all(workers);
  return out;
}

async function txLogs(blockscout, txHash) {
  const r = await fetch(`${blockscout}/api/v2/transactions/${txHash}/logs`, { headers: { accept: 'application/json' } });
  if (!r.ok) return [];
  const j = await r.json();
  return j.items || [];
}

(async () => {
  const name = process.argv[2] || 'base';
  const cfg = CFG[name];
  const clients = cfg.rpcs.map((url) => createPublicClient({ chain: cfg.chain, transport: http(url, { timeout: 12000 }) }));
  const main = clients[0];

  const [bCounter, cCounter, nftSupply, protoBal] = await Promise.all([
    main.readContract({ address: cfg.main, abi: ABI, functionName: 'bountyCounter' }),
    main.readContract({ address: cfg.main, abi: ABI, functionName: 'claimCounter' }),
    main.readContract({ address: cfg.nft, abi: NFT_ABI, functionName: 'totalSupply' }),
    main.readContract({ address: cfg.nft, abi: NFT_ABI, functionName: 'balanceOf', args: [cfg.nft] }),
  ]);
  const bIds = Array.from({ length: Number(bCounter) }, (_, i) => BigInt(i));
  const nIds = Array.from({ length: Number(nftSupply) }, (_, i) => BigInt(i));
  console.log(`${name}: bounties=${bIds.length} claims=${cCounter} nfts=${nIds.length} protocolBalance=${protoBal}`);

  console.log('  reading bounties');
  const bounties = await chunked(clients, cfg.main, ABI, 'bounties', bIds, null, 50);
  console.log('  reading NFT owners');
  const owners = await chunked(clients, cfg.nft, NFT_ABI, 'ownerOf', nIds, null, 100);

  const ZERO = '0x0000000000000000000000000000000000000000';
  const completedIdx = [];
  const excluded = { neverCompleted: 0, cancelled: 0 };
  for (let i = 0; i < bounties.length; i++) {
    const b = bounties[i];
    if (!b) { excluded.neverCompleted++; continue; }
    const [, issuer, , , , claimer] = b;
    if (!claimer || claimer === ZERO) { excluded.neverCompleted++; continue; }
    if (claimer.toLowerCase() === issuer.toLowerCase()) { excluded.cancelled++; continue; }
    completedIdx.push(i);
  }
  console.log(`  completed (claimer set, != issuer): ${completedIdx.length}`);

  console.log('  reading participants');
  const parts = await chunked(clients, cfg.main, ABI, 'getParticipants', completedIdx.map((i) => BigInt(bounties[i][0])), null, 60);

  // exploit fingerprints straight from the attack transactions
  const exploitBounties = new Set();
  const exploitTxsFound = [];
  for (const tx of cfg.exploitTxs) {
    const logs = await txLogs(cfg.blockscout, tx);
    if (!logs.length) { console.log('  no logs for', tx); continue; }
    exploitTxsFound.push(tx);
    for (const l of logs) {
      if (l.topics && l.topics[0] === '0x68669d605f9b1ca0cb82bb6221846a66f289b2f075ad7be1df396d335da38e5a') {
        const d = (l.data || '0x').slice(2);
        exploitBounties.add(Number(BigInt('0x' + d.slice(0, 64))));
      }
    }
  }
  console.log(`  exploit txs=${exploitTxsFound.length} exploit bounty ids=${exploitBounties.size}`);

  // ---- ledger -------------------------------------------------------------
  const paid = new Map(), contributed = new Map(), earned = new Map(), received = new Map();
  let feeTotal = 0n, grossTotal = 0n, exploitGross = 0n, exploitCount = 0;
  const rowsByWallet = new Map();
  const add = (m, w, v) => m.set(w, (m.get(w) || 0n) + v);

  for (let k = 0; k < completedIdx.length; k++) {
    const i = completedIdx[k];
    const b = bounties[i];
    const [id, issuer, name_, desc, amount, claimer, createdAt, claimId] = b;
    const bid = Number(id);
    const gross = amount;
    const fee = (gross * 25n) / 1000n;
    if (exploitBounties.has(bid)) {
      exploitCount++; exploitGross += gross; feeTotal += fee; grossTotal += gross;
      continue;                      // fraudulent completion: excluded from the ledger
    }
    feeTotal += fee; grossTotal += gross;
    const [pAddrs, pAmts] = parts[k] || [[], []];
    const contrib = (pAddrs && pAddrs.length)
      ? pAddrs.map((a, j) => [a.toLowerCase(), pAmts[j]])
      : [[issuer.toLowerCase(), gross]];
    const totalContrib = contrib.reduce((s, [, a]) => s + a, 0n) || 1n;
    for (const [w, a] of contrib) {
      add(contributed, w, a);
      add(paid, w, (gross * a) / totalContrib);
    }
    add(earned, claimer.toLowerCase(), gross);
    add(received, claimer.toLowerCase(), gross - fee);
  }

  const nftHeld = new Map();
  for (const o of owners) {
    if (!o || o === ZERO) continue;
    const w = o.toLowerCase();
    nftHeld.set(w, (nftHeld.get(w) || 0) + 1);
  }
  const protoNft = nftHeld.get(cfg.nft.toLowerCase()) || 0;

  const wallets = new Set([...paid.keys(), ...earned.keys(), ...contributed.keys(), ...nftHeld.keys()]);
  const rows = [...wallets].sort().map((w) => ({
    wallet: w,
    paid: (paid.get(w) || 0n).toString(),
    earned: (earned.get(w) || 0n).toString(),
    contributed: (contributed.get(w) || 0n).toString(),
    received: (received.get(w) || 0n).toString(),
    nfts: nftHeld.get(w) || 0,
  }));
  const protoRow = { wallet: cfg.nft.toLowerCase(), paid: '0', earned: '0', contributed: '0', received: '0', nfts: protoNft };
  if (protoNft) rows.push(protoRow);

  const sum = (m) => [...m.values()].reduce((a, b) => a + b, 0n);
  const totals = {
    paid: sum(paid).toString(),
    earned: sum(earned).toString(),
    contributed: sum(contributed).toString(),
    received: sum(received).toString(),
    fee: feeTotal.toString(),
    gross_all_incl_exploit: grossTotal.toString(),
    exploit_gross: exploitGross.toString(),
    exploit_count: exploitCount,
    exploit_bounties: [...exploitBounties].sort((a, b) => a - b),
    exploit_txs: exploitTxsFound,
    nfts: [...nftHeld.values()].reduce((a, b) => a + b, 0),
    nft_contract: cfg.nft.toLowerCase(),
    nft_contract_held: protoNft,
    nft_contract_balance: protoBal.toString(),
    nft_supply: nIds.length,
    completed: completedIdx.length - exploitCount,
    wallets: rows.length,
    excluded,
    counters: { bounties: bIds.length, claims: Number(cCounter), nft_supply: nIds.length },
  };
  fs.writeFileSync(`v2state_${name}.json`, JSON.stringify({ rows, totals }, null, 1));
  console.log(`\n  wallets=${rows.length} legit_completed=${totals.completed} exploit_excluded=${exploitCount} (${exploitGross / 1e18} ETH)`);
  console.log(`  gross_earned=${totals.earned}  paid_out=${totals.paid}  net_received=${totals.received}`);
  console.log(`  fee=${totals.fee}  (${(Number(totals.fee) / Number(totals.earned) * 100).toFixed(6)}% of gross)`);
  console.log(`  nfts=${totals.nfts} protocol=${protoNft} (balanceOf contract=${protoBal})`);
})();
