#!/usr/bin/env python3
"""Recompute the poidh v2 per-wallet ledger straight from the chain and (optionally)
diff it against a candidate CSV.

    python3 verify_v2.py base
    python3 verify_v2.py base 0xabc...          # show one wallet's chain rows
    python3 verify_v2.py base candidate.csv     # diff a CSV against the chain

Data source: Blockscout's API v2 (paginated), which serves the full contract history
without an API key:
    <chain>.blockscout.com/api/v2/addresses/<contract>/logs
"""
import json, subprocess, sys, collections, datetime, os
from eth_abi import decode

CONTRACTS = {
    "base": dict(host="https://base.blockscout.com", main="0xb502c5856f7244dccdd0264a541cc25675353d39"),
    "arbitrum": dict(host="https://arbitrum.blockscout.com", main="0x0aa50ce0d724cc28f8f7af4630c32377b4d5c27d"),
}
NFT = "0xddfb1a53e7b73dba09f79fca24765c593d447a80"
T_BC = "0xd00fa07781d3060308d3f5da95be7929ceef8a74a9bf989b48a216ce85f73e25"
T_CC = "0x8a181854d9e4089e919a5426d2781d33ce515555f29d3392a43f0a4a4a5e1ff2"
T_CA = "0x68669d605f9b1ca0cb82bb6221846a66f289b2f075ad7be1df396d335da38e5a"
T_CX = "0xbe34663bc2803ca9be398afdbd7e0bd537378360b743b76b170e3421fbe38450"
T_JN = "0x22917cd092c8998d89d6269987ba4a153018855ce4ae6bffe0fa9d5ec2f1b39f"
T_TR = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
T_WD = "0x45219acf9e010ac867"      # WithdrawFromOpenBounty
EXPLOIT_TX = {"0x0545a4e5800632ba2194fb9349264ff7f3d3bb18d28ee168d57369b14422f11f"}
ATTACKER = {"0xcb18f71e12b85058974f181e8cca769ab5eedbbd"}
ZERO = "0x" + "0" * 40


def hx(s):
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def fetch_all(host, addr):
    """Pull the full log history via Blockscout v2 pagination."""
    url = f"{host}/api/v2/addresses/{addr}/logs"
    out, params = [], None
    while True:
        q = url + (("?" + "&".join(f"{k}={v}" for k, v in params.items())) if params else "")
        raw = subprocess.run(["curl", "-s", "--max-time", "60", q], capture_output=True, text=True).stdout
        try:
            j = json.loads(raw)
        except Exception:
            break
        out.extend(j.get("items", []))
        if not j.get("next_page_params"):
            break
        params = j["next_page_params"]
    return out


def norm(logs):
    seen, out = set(), []
    for l in logs:
        th = (l.get("transactionHash") or l.get("transaction_hash") or "").lower()
        li = l.get("logIndex", l.get("log_index", l.get("index", 0)))
        try:
            li = int(li, 16) if isinstance(li, str) and li.startswith("0x") else int(li)
        except Exception:
            li = 0
        if (th, li) in seen:
            continue
        seen.add((th, li))
        ts = l.get("block_timestamp") or l.get("timeStamp")
        try:
            if isinstance(ts, str) and "T" in ts:
                ts = int(datetime.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
                         .replace(tzinfo=datetime.timezone.utc).timestamp())
            else:
                ts = int(ts, 16) if isinstance(ts, str) and ts.startswith("0x") else int(ts or 0)
        except Exception:
            ts = 0
        out.append(dict(l, tx=th, li=li, ts=ts))
    return out


def ledger(chain):
    cfg = CONTRACTS[chain]
    main = norm(fetch_all(cfg["host"], cfg["main"]))
    nft = norm(fetch_all(cfg["host"], NFT))
    bounty, joined, accepted, cancelled, withdrawn = {}, collections.defaultdict(list), [], set(), collections.defaultdict(list)
    fraud = set()
    for l in main:
        t, d = l["topics"][0], l["data"]
        try:
            if t == T_BC:
                bid, iss, nm, ds, amt, cr = decode(["uint256", "address", "string", "string", "uint256", "uint256"], hx(d))
                bounty[bid] = dict(amount=amt, issuer=iss.lower())
            elif t == T_CA:
                bid, cid, ci, bi, fee = decode(["uint256", "uint256", "address", "address", "uint256"], hx(d))
                accepted.append((bid, ci.lower(), fee))
                if l["tx"] in EXPLOIT_TX: fraud.add(bid)
            elif t == T_CX:
                bid, iss = decode(["uint256", "address"], hx(d)); cancelled.add(bid)
            elif t == T_JN:
                bid, part, amt = decode(["uint256", "address", "uint256"], hx(d)); joined[bid].append((part.lower(), amt))
            elif t.startswith(T_WD[:10]):
                bid, who, amt = decode(["uint256", "address", "uint256"], hx(d)); withdrawn[bid].append(who.lower())
        except Exception:
            pass
    paid, contributed, earned = collections.Counter(), collections.Counter(), collections.Counter()
    fee_total = 0
    for bid, b in bounty.items():
        if bid in cancelled or bid in fraud or withdrawn.get(bid): continue
        acc = [a for a in accepted if a[0] == bid]
        if not acc: continue
        if any(ci in ATTACKER for _, ci, _ in acc): continue
        gross = sum(fee * 40 for _, _, fee in acc)
        fee_total += sum(fee for _, _, fee in acc)
        contrib = [(b["issuer"], b["amount"])] + list(joined.get(bid, []))
        tot = sum(a for _, a in contrib) or 1
        for w, a in contrib:
            contributed[w] += a
            paid[w] += gross * a // tot
        for _, ci, _ in acc:
            earned[ci] += gross
    owner = {}
    for l in nft:
        if l["topics"][0] == T_TR and len(l["topics"]) >= 4:
            owner[int(l["topics"][3], 16)] = "0x" + l["topics"][2][-40:].lower()
    held = collections.Counter(owner.values()); held.pop(ZERO, None)
    proto = held.get(cfg["main"], 0)
    if proto:
        held_row = dict(wallet=cfg["main"], paid=0, earned=0, nfts=proto, contributed=0)
    else:
        held_row = None
    rows = [dict(wallet=w, paid=paid[w], earned=earned[w], nfts=held.get(w, 0), contributed=contributed[w])
            for w in sorted(set(paid) | set(earned) | set(held))]
    if held_row: rows.append(held_row)
    return rows, dict(paid=str(sum(paid.values())), earned=str(sum(earned.values())),
                      contributed=str(sum(contributed.values())), fee=str(fee_total),
                      nfts=sum(held.values()), completed=len([b for b in bounty if b not in cancelled and b not in fraud and not withdrawn.get(b)]),
                      fraud=len(fraud), cancelled=len(cancelled), withdrawn=len(withdrawn))


def eths(w):
    return f"{w/1e18:.12f}".rstrip("0").rstrip(".") if w else "0"


if __name__ == "__main__":
    chain = sys.argv[1]
    rows, t = ledger(chain)
    print(f"=== {chain}: {len(rows)} rows ===")
    print(f"  sum(eth_earned)     = {eths(int(t['earned']))} ETH")
    print(f"  sum(eth_paid_out)   = {eths(int(t['paid']))} ETH")
    print(f"  sum(eth_contributed)= {eths(int(t['contributed']))} ETH")
    print(f"  protocol fee        = {eths(int(t['fee']))} ETH ({int(t['fee'])/int(t['earned'])*100:.6f}% of gross)")
    print(f"  NFTs held           = {t['nfts']}")
    print(f"  completed bounties  = {t['completed']} (fraudulent excluded {t['fraud']}, cancelled {t['cancelled']}, withdrawn {t['withdrawn']})")
    if len(sys.argv) > 2 and sys.argv[2].startswith("0x"):
        w = sys.argv[2].lower()
        for r in rows:
            if r["wallet"].lower() == w:
                print(f"  {w}: paid_out {eths(r['paid'])} ETH | earned {eths(r['earned'])} ETH | nfts {r['nfts']}")
    if len(sys.argv) > 2 and not sys.argv[2].startswith("0x"):
        import csv
        cand = list(csv.DictReader(open(sys.argv[2])))
        byp = {r["wallet"].lower(): r for r in rows}
        bad = 0
        for c in cand:
            w = c["wallet"].lower()
            r = byp.get(w)
            if r is None:
                print(f"  {w}: not in recomputed ledger"); bad += 1; continue
            for col, key in (("eth_paid_out_wei", "paid"), ("eth_earned_wei", "earned"), ("nfts_held", "nfts")):
                if col in c and str(c[col]) != str(r[key]):
                    print(f"  {w}: {col} candidate={c[col]} chain={r[key]}"); bad += 1
        print(f"  mismatches: {bad} across {len(cand)} candidate rows")
