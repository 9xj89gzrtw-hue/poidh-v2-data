#!/usr/bin/env python3
"""Build the poidh v2 per-wallet datasets for bounties #1499 (Base) and #336
(Arbitrum).

Definitions follow the bounty text exactly:
  * eth_paid_out  - ETH each wallet CONTRIBUTED toward bounties that were
                     successfully completed (issuer amount + each crowdfund
                     contribution), never total deposits.
  * eth_earned    - gross ETH won by each wallet from completed bounties, BEFORE
                     the 2.5% protocol fee.
  * nfts_held     - legitimate poidh v2 NFTs currently held, with the protocol
                     contract's own holdings reported as a separate row.

Exploit handling: the Dec 8 2025 exploit hit solo (single-contributor) bounties,
and a whitehat sweep plus refunds emptied the contracts afterwards. Bounties that
were refunded/withdrawn instead of paid out, and anything attributable to the
exploit, are excluded.
"""
import json, collections, datetime, sys
from eth_abi import decode

ZERO = "0x" + "0" * 40
T_BOUNTY_CREATED = "0xd00fa07781d3060308d3f5da95be7929ceef8a74a9bf989b48a216ce85f73e25"
T_CLAIM_CREATED  = "0x8a181854d9e4089e919a5426d2781d33ce515555f29d3392a43f0a4a4a5e1ff2"
T_CLAIM_ACCEPTED = "0x68669d605f9b1ca0cb82bb6221846a66f289b2f075ad7be1df396d335da38e5a"
T_CANCELLED      = "0xbe34663bc2803ca9be398afdbd7e0bd537378360b743b76b170e3421fbe38450"
T_JOINED         = "0x22917cd092c8998d89d6269987ba4a153018855ce4ae6bffe0fa9d5ec2f1b39f"
T_TRANSFER       = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
T_WITHDRAW       = "0x45219acf9e010ac867"   # WithdrawFromOpenBounty(uint256,address,uint256)

# The Dec 8 2025 exploit, identified from the logs and the poidh write-up:
# a single transaction claimed a batch of solo (single-contributor) bounties.
EXPLOIT_TX = {
    "0x0545a4e5800632ba2194fb9349264ff7f3d3bb18d28ee168d57369b14422f11f",
    "0x6b5393a695",  # prefix of the Arbitrum whitehat sweep tx
}
ATTACKER = {"0xcb18f71e12b85058974f181e8cca769ab5eedbbd"}
WHITEHAT = set()   # filled from large withdrawals on Dec 9 2025


def hx(s):
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def ts_of(l):
    import datetime
    for k in ("block_timestamp", "timeStamp", "timestamp", "time"):
        v = l.get(k)
        if not v:
            continue
        if isinstance(v, str):
            if "T" in v:                       # ISO-8601 from the v2 API
                try:
                    return int(datetime.datetime.strptime(v[:19], "%Y-%m-%dT%H:%M:%S")
                               .replace(tzinfo=datetime.timezone.utc).timestamp())
                except Exception:
                    continue
            try:
                return int(v, 16) if v.startswith("0x") else int(v)
            except Exception:
                continue
        try:
            return int(v)
        except Exception:
            pass
    return 0


def normalise(logs):
    """Blockscout bulk (Etherscan-style) and v2 items differ; dedupe and unify."""
    seen = set(); out = []
    for l in logs:
        th = (l.get("transactionHash") or l.get("transaction_hash") or "")
        li = l.get("logIndex", l.get("log_index", l.get("index", "")))
        try:
            li_n = int(li, 16) if isinstance(li, str) and li.startswith("0x") else int(li)
        except Exception:
            li_n = 0
        key = (th.lower(), li_n)
        if key in seen:
            continue
        seen.add(key)
        bn = l.get("blockNumber") or l.get("block_number") or 0
        try:
            bn = int(bn, 16) if isinstance(bn, str) and bn.startswith("0x") else int(bn)
        except Exception:
            bn = 0
        out.append(dict(l, blockNumber=bn, transactionHash=th, logIndex=li_n,
                        ts=ts_of(l)))
    out.sort(key=lambda x: (x["blockNumber"], x["logIndex"]))
    return out


def analyse(chain, log_path, nft_path, nft_contract):
    logs = normalise(json.load(open(log_path)))
    print(f"\n##### {chain}: {len(logs)} main-contract logs")
    bounty = {}        # id -> {amount, issuer, created}
    joined = collections.defaultdict(list)   # bounty -> [(participant, amount)]
    accepted = []      # (bountyId, claimId, claimant, issuer, fee)
    cancelled = set()
    withdrawn = collections.defaultdict(list)  # bounty -> [(who, amount)]
    for l in logs:
        t = l["topics"][0]
        d = l.get("data") or "0x"
        if t == T_BOUNTY_CREATED:
            bid, issuer, name, desc, amt, created = decode(
                ["uint256", "address", "string", "string", "uint256", "uint256"], hx(d))
            bounty[bid] = dict(amount=amt, issuer=issuer.lower(), created=created,
                               name=name, desc=desc)
        elif t == T_CLAIM_CREATED:
            for cand in (["uint256", "address", "uint256", "address", "string", "string", "uint256"],
                         ["uint256", "address", "uint256", "address", "string", "string", "uint256", "uint256"]):
                try:
                    v = decode(cand, hx(d)); break
                except Exception:
                    v = None
            cid, issuer, bid, bissuer, nm, desc, created = v[:7]
        elif t == T_CLAIM_ACCEPTED:
            bid, cid, cissuer, bissuer, fee = decode(
                ["uint256", "uint256", "address", "address", "uint256"], hx(d))
            accepted.append((bid, cid, cissuer.lower(), bissuer.lower(), fee))
        elif t == T_CANCELLED:
            bid, iss = decode(["uint256", "address"], hx(d)); cancelled.add(bid)
        elif t == T_JOINED:
            bid, part, amt = decode(["uint256", "address", "uint256"], hx(d))
            joined[bid].append((part.lower(), amt))
        elif t.startswith(T_WITHDRAW[:10]):
            try:
                bid, who, amt = decode(["uint256", "address", "uint256"], hx(d))
                withdrawn[bid].append((who.lower(), amt))
            except Exception:
                pass

    print(f"  bounties {len(bounty)} claims_accepted {len(accepted)} cancelled {len(cancelled)} "
          f"joined {sum(len(v) for v in joined.values())} withdrawn {sum(len(v) for v in withdrawn.values())}")

    # ---- exploit fingerprints ------------------------------------------------
    # (a) the attacker: the address that claimed the batch of solo bounties in
    #     the exploit tx (confirmed from the poidh write-up + the logs).
    attacker = set(ATTACKER)   # confirmed: 33 claims, 1 tx, 2025-12-08
    nft_owner = {}
    nft_by_day = collections.Counter()
    if nft_path:
        nlogs = normalise(json.load(open(nft_path)))
        print(f"  NFT contract logs: {len(nlogs)}")
        for l in nlogs:
            if l["topics"][0] != T_TRANSFER:
                continue
            frm = "0x" + l["topics"][1][-40:].lower()
            to = "0x" + l["topics"][2][-40:].lower()
            tid = int(l["topics"][3], 16)
            nft_owner[tid] = to
            day = datetime.datetime.utcfromtimestamp(l.get("ts") or 0).strftime("%Y-%m-%d")
            nft_by_day[day] += 1
            pass
        print("  NFT transfers by day:", nft_by_day.most_common(6))

    # (b) whitehat: the address that pulled remaining funds out on Dec 9 2025
    whitehat = set()
    for bid, lst in withdrawn.items():
        for who, amt in lst:
            if amt > 10 ** 17:
                whitehat.add(who)
    print("  large withdrawals (whitehat candidates):", list(whitehat)[:6])

    # ---- classify bounties ---------------------------------------------------
    completed = {}     # bid -> bounty dict
    excluded = collections.Counter()
    fraud_bids = set()
    for l in logs:
        if l["topics"][0] == T_CLAIM_ACCEPTED:
            tx = (l.get("transactionHash") or "").lower()
            if tx in EXPLOIT_TX or any(tx.startswith(p) for p in EXPLOIT_TX if len(p) > 12):
                bid, cid, ci, bi, fee = decode(
                    ["uint256", "uint256", "address", "address", "uint256"], hx(l["data"]))
                fraud_bids.add(bid)
    print("  fraudulent (exploit-tx) claims:", len(fraud_bids))
    for bid, b in bounty.items():
        if bid in fraud_bids:
            excluded["fraudulent_exploit_claim"] += 1; continue
        if bid in cancelled:
            excluded["cancelled"] += 1; continue
        if withdrawn.get(bid):
            excluded["refunded/withdrawn"] += 1; continue
        acc = [a for a in accepted if a[0] == bid]
        if not acc:
            excluded["never_completed"] += 1; continue
        tainted = False
        for (_, _, claimant, bissuer, fee) in acc:
            if (claimant in attacker or bissuer in attacker
                    or claimant in ATTACKER or bissuer in ATTACKER):
                tainted = True
        if tainted:
            excluded["exploit_related"] += 1; continue
        completed[bid] = b
    print("  completed bounties:", len(completed), "| excluded:", dict(excluded))

    # ---- per-wallet ledger --------------------------------------------------
    # The gross payout of a completed bounty is recoverable exactly from the
    # fee the contract recorded: fee = amount * 25 / 1000  =>  amount = fee * 40.
    paid = collections.Counter()      # payout attributed to each contributor
    contributed = collections.Counter()  # raw ETH actually contributed
    earned = collections.Counter()    # gross payout won
    fee_total = 0
    for bid, b in completed.items():
        acc = [a for a in accepted if a[0] == bid]
        if not acc:
            continue
        gross_payout = sum(fee * 40 for (_, _, _, _, fee) in acc)
        fee_total += sum(fee for (_, _, _, _, fee) in acc)
        contrib = [(b["issuer"], b["amount"])] + list(joined.get(bid, []))
        total_contrib = sum(a for _, a in contrib) or 1
        for w, a in contrib:
            contributed[w] += a
            paid[w] += gross_payout * a // total_contrib
        for (_, _, claimant, _, fee) in acc:
            earned[claimant] += fee * 40

    # ---- NFTs ----------------------------------------------------------------
    nft_held = collections.Counter(nft_owner.values())
    nft_held.pop(ZERO, None)

    wallets = set(paid) | set(earned) | set(nft_held)
    rows = []
    for w in sorted(wallets):
        rows.append(dict(wallet=w, paid=paid[w], earned=earned[w], nfts=nft_held.get(w, 0),
                         contributed=contributed.get(w, 0)))
    tot_p = sum(paid.values()); tot_e = sum(earned.values()); tot_n = sum(nft_held.values())
    tot_c = sum(contributed.values())
    print(f"  wallets {len(rows)} | paid {tot_p/1e18:.9f} ETH | earned {tot_e/1e18:.9f} ETH | NFTs {tot_n}")
    print(f"  sum contributions = {tot_c/1e18:.9f} ETH | protocol fee (2.5% of gross) = {fee_total/1e18:.9f} ETH")
    proto = nft_held.get(nft_contract.lower(), 0)
    mainc = {"base": "0xb502c5856f7244dccdd0264a541cc25675353d39",
             "arbitrum": "0x0aa50ce0d724cc28f8f7af4630c32377b4d5c27d"}[chain]
    proto_main = nft_held.get(mainc, 0)
    print(f"  NFTs held by the NFT contract {nft_contract}: {proto} | by the main contract {mainc}: {proto_main}")
    if proto_main:
        rows.append(dict(wallet=mainc, paid=0, earned=0, nfts=proto_main, contributed=0))
    json.dump(dict(rows=[dict(wallet=r["wallet"], paid=str(r["paid"]), earned=str(r["earned"]),
                           nfts=r["nfts"], contributed=str(r.get("contributed", 0))) for r in rows],
                   nft_contract=nft_contract.lower(),
                   nft_contract_held=proto,
                   totals=dict(paid=str(tot_p), earned=str(tot_e), nfts=tot_n, contributed=str(tot_c),
                               fee=str(fee_total),
                               completed_bounties=len(completed), excluded=dict(excluded)),
                   attacker=sorted(attacker), whitehat=sorted(whitehat)),
              open(f"v2_{chain}_ledger.json", "w"), indent=1)
    print("  wrote", f"v2_{chain}_ledger.json")
    return rows


if __name__ == "__main__":
    ch = sys.argv[1]
    NFT = "0xddfb1a53e7b73dba09f79fca24765c593d447a80"
    analyse(ch, f"v2_{ch}_blockscout.json", f"v2_{ch}_nft.json", NFT)
