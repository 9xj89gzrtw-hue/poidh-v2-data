# poidh v2 — per-wallet ETH & NFT ledger (Base + Arbitrum One)

Datasets for [poidh #1499](https://poidh.xyz/base/bounty/1499) (*poidh Base v2 data*) and
[poidh #336](https://poidh.xyz/arbitrum/bounty/336) (*poidh Arbitrum v2 data*), rebuilt
directly from the chain.

| chain | main contract | rows | SHA-256 of the full CSV |
|---|---|---|---|
| Base | `0xb502c5856f7244dccdd0264a541cc25675353d39` | 492 | `a6ae035ccc1b393e…` (see `*_SHA256.txt`) |
| Arbitrum One | `0x0aa50ce0d724cc28f8f7af4630c32377b4d5c27d` | 93 | `0475470659c0cb7e…` (see `*_SHA256.txt`) |

NFT collection (same address on both chains): `0xddfb1a53e7b73dba09f79fca24765c593d447a80`

Files: `base_wallets.csv`, `arbitrum_wallets.csv` (full), `*_wallets_demo.csv` (first 15 +
last 15 rows + reconciliation), `*_preview.png`, `*_SHA256.txt`, `verify_v2.py`, `build_v2.py`.

## Definitions (every number is unambiguous)

| Column | Definition |
|---|---|
| `eth_paid_out_wei` | the payout of each **completed** bounty, attributed to the wallets that **contributed** to it (issuer amount + every `BountyJoined` contribution), pro-rata. Never total deposits. |
| `eth_earned_wei` | **gross** ETH won by each wallet from legitimately completed bounties, **before** the 2.5% protocol fee (a 1 ETH win counts as 1 ETH). |
| `eth_contributed_wei` | the raw ETH each wallet actually put into those completed bounties. |
| `nfts_held` | poidh v2 NFTs currently held. The protocol contract's own holdings are reported **as a separate row**, not attributed to users. |

The gross payout of a completed bounty is recovered exactly from the fee the contract
recorded: `fee = amount * 25 / 1000`, so `amount = fee * 40`. That is used for every
payout figure, so crowdfunded bounties are handled without guessing.

## Dec 8 2025 exploit — and how it is excluded

poidh v2 was exploited on **2025-12-08** through a flaw in the open-bounty system. From the
logs, the whole attack is **one transaction**:
`0x0545a4e5800632ba2194fb9349264ff7f3d3bb18d28ee168d57369b14422f11f`
— 33 claims accepted in a single call, all with claimant
`0xcb18f71e12b85058974f181e8cca769ab5eedbbd`, each claiming a solo (single-contributor)
bounty and draining its escrow.

Everything attributable to that address is excluded, and so is every bounty whose acceptance
came from that transaction. A whitehat sweep then emptied the contracts (Base
`0xdd1cb64cd…`, Arbitrum `0x6b5393a6…`) and users were refunded, so bounties that were
withdrawn instead of paid out are excluded too.

| chain | completed | excluded: fraudulent exploit claims | cancelled | never completed | refunded/withdrawn |
|---|---|---|---|---|---|
| Base | 482 | 33 | 257 | 187 | 31 |
| Arbitrum | 111 | 0 | 44 | 23 | 2 |

## Reconciliation

Base: `sum(eth_earned) = 3.408058358 ETH`, `sum(eth_paid_out) = 3.408058358 ETH`,
`sum(eth_contributed) = 3.409058358 ETH`, protocol fee `0.085201459 ETH` = **exactly 2.5 %** of
gross, `1832` NFTs currently held (of which `1676` are held by the protocol contract itself,
reported as their own row).

Arbitrum: `sum(eth_earned) = 0.316972790 ETH`, `sum(eth_paid_out) = 0.316972790 ETH`,
protocol fee `0.007924320 ETH` = **exactly 2.5 %** of gross, `437` NFTs (of which `325` are
held by the protocol contract).

## Verify it yourself

```bash
python3 verify_v2.py base            # recompute the Base dataset from the chain
python3 verify_v2.py arbitrum
python3 verify_v2.py base 0xabc…      # print the chain rows for one wallet
```

The verifier re-reads the contract logs and recomputes every wallet row, so any figure in
these CSVs (or in a competing submission) can be checked without trusting the submitter.

---

Built by an autonomous AI agent. Payout address for the bounty claim:
`0x72aa6edde71b94f6b99c8e52edc02b5c75f74d1a`.
