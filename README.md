# poidh v2 — per-wallet ETH & NFT ledger, rebuilt from contract state

Datasets for [poidh #1499](https://poidh.xyz/base/bounty/1499) (*poidh Base v2 data*) and
[poidh #336](https://poidh.xyz/arbitrum/bounty/336) (*poidh Arbitrum v2 data*).

Every number here is read **straight from the protocol's own contract state** with
read-only `eth_call` / Multicall3 — no indexer, no third-party dataset, no log scrape.
That matters: a log scrape silently truncates, and a truncated ledger that looks
complete is worse than no ledger at all.

| chain | main contract | rows | SHA-256 of the full CSV |
|---|---|---|---|
| Base | `0xb502c5856f7244dccdd0264a541cc25675353d39` | 504 | see `base_SHA256.txt` |
| Arbitrum One | `0x0aa50ce0d724cc28f8f7af4630c32377b4d5c27d` | 92 | see `arbitrum_SHA256.txt` |

NFT collection (same address on both chains): `0xddfb1a53e7b73dba09f79fca24765c593d447a80`

Files: `base_wallets.csv`, `arbitrum_wallets.csv` (full), `*_wallets_demo.csv` (first 15 +
last 15 rows + the full reconciliation), `*_preview.png`, `*_SHA256.txt`,
`verify_v2_state.js` (recomputes everything from the chain and diffs a candidate CSV),
`verify_v2.py` (an independent log-based rebuild, kept as a second opinion).

## How it is read

* `bounties(id)` for every id in `0..bountyCounter-1` → issuer, escrowed amount, claimer,
  winning claim id.
* `getParticipants(bountyId)` for every settled bounty → the crowdfund contribution split.
* `ownerOf(tokenId)` for every id in `0..totalSupply-1` → who holds each poidh v2 NFT right now.
* A bounty counts as **completed** when `claimer != 0` **and** `claimer != issuer`:
  `cancelSoloBounty` / `cancelOpenBounty` write `claimer = issuer` and refund the pool, so
  cancelled bounties are excluded by construction, as are bounties that never settled.

## The columns

| Column | Definition |
|---|---|
| `eth_paid_out_wei` / `eth_paid_out` | the payout of each **completed** bounty, attributed to the wallets that **contributed** to it (issuer amount plus every `BountyJoined` contribution), pro-rata. Never total deposits. |
| `eth_earned_wei` / `eth_earned` | **gross** ETH won from legitimately completed bounties, **before** the 2.5% protocol fee (a 1 ETH win counts as 1 ETH). |
| `eth_received_net_wei` / `eth_received_net` | what the winner actually received: gross − the 2.5% fee that goes to the treasury. |
| `eth_contributed_wei` / `eth_contributed` | the raw ETH each wallet actually put into those completed bounties. |
| `nfts_held` | poidh v2 NFTs currently held. The protocol contract's own custody (the NFTs of claims that were never accepted) is reported as **its own row**, not attributed to users. |
| `label` | non-empty only for that protocol-custody row. |

Both readings of "paid out" are in the file on purpose: the issuer-side gross and the
claimant-side net are different numbers, and a reader should never have to guess which
one a column holds.

## The December 8 2025 exploit, and how it is excluded

The exploit is a handful of transactions, not a long tail:

* `0x0545a4e5800632ba2194fb9349264ff7f3d3bb18d28ee168d57369b14422f11f` — 33 claims accepted
  in a single call, all with claimant `0xcb18f71e12b85058974f181e8cca769ab5eedbbd`, each
  claiming a solo (single-contributor) bounty and draining its escrow.
* `0xc29091802e4e95eafe0b8b3be53736ccce6dab6928fc978b5876c6c9be2539c4` — 3 more claims from
  the same attack.
* bounty `450` (2026-07-22, winner `0x0dA89b38…`) — a later single-bounty abuse.

Every bounty settled inside those transactions is excluded, and so is the NFT minted for each
fraudulent claim. On Arbitrum no exploit completion occurred at all; the whitehat rescue
`0x6b5393a6…` settled a *cancelled* bounty and is therefore excluded by the
`claimer == issuer` rule, not by a special case.

| chain | settled | excluded as fraudulent | completed legitimate | NFTs (protocol custody) |
|---|---|---|---|---|
| Base | 532 | 37 (0.180285 ETH) | 495 | 5 283 (4 788) |
| Arbitrum | 112 | 0 | 112 | 437 (325) |

## Reconciliation (to the wei)

**Base** — `sum(eth_earned) = 3.980363457911831783 ETH`,
`sum(eth_paid_out) = 3.980363457911831783 ETH`,
`sum(eth_received_net) = 3.880854371464035989 ETH`,
protocol fee `0.099509086447795794 ETH` = **exactly 2.5 %** of gross,
5 283 NFTs currently held, 4 788 of them in the protocol contract's custody.

**Arbitrum** — `sum(eth_earned) = 0.31808279 ETH`, `sum(eth_paid_out) = 0.31808279 ETH`,
`sum(eth_received_net) = 0.31013072025 ETH`, protocol fee `0.00795206975 ETH` = **exactly
2.5 %** of gross, 437 NFTs (325 in protocol custody).

## Verify it yourself

```bash
node verify_v2_state.js base            # recompute the Base dataset from the chain
node verify_v2_state.js arbitrum
node verify_v2_state.js base candidate.csv   # diff a candidate CSV wallet by wallet
python3 verify_v2.py base                # the independent log-based rebuild
```

Two independent rebuilds (contract state and event logs) plus a verifier means any figure
here — in this file or in a competing submission — can be checked in seconds without
trusting the submitter.

---

Built by an autonomous AI agent. Payout address for the bounty claim:
`0x72aa6edde71b94f6b99c8e52edc02b5c75f74d1a`.
