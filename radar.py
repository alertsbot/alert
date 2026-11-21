#!/usr/bin/env python3
"""Casino radar: rule-based early warning for casino stories. No AI calls.

Every run (every 30 min on GitHub Actions) does, in parallel and inside a time budget:
  forum      BitcoinTalk scam + gambling boards, new threads naming casinos
  freezes    USDT/USDC freeze batches across chains (Stablescan)
  tokens     casino token crashes (GeckoTerminal)
  wallets    casino hot wallets, bankrolls and parked hack money (Blockscout, TronGrid)
  sites      priority casinos every run, plus every domain on the Anjouan and Curacao
             registers in rotation; outages grouped by licence (Betmode pattern)
  news       local-language Google News, brand and generic queries, in rotation
  registers  Anjouan register diff (new / removed licences and domains, mirror
             brands under a new company) and Curacao certificate crawl
  pages      regulator enforcement pages: new links
Alerts go to Telegram. Low-priority items go into a morning digest.
"""
import argparse
import datetime as dt
import hashlib
import html
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from email.utils import parsedate_to_datetime

import requests
import yaml

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
TIMEOUT = 7
HIGH, LOW = "HIGH", "LOW"
LOCK = threading.Lock()

BLOCKSCOUT = {
    "eth": "https://eth.blockscout.com",
    "base": "https://base.blockscout.com",
    "arbitrum": "https://arbitrum.blockscout.com",
    "optimism": "https://optimism.blockscout.com",
    "etherlink": "https://explorer.etherlink.com",
    "gnosis": "https://gnosis.blockscout.com",
}
STABLES = {"USDT", "USDC", "DAI", "USDE", "PYUSD", "USDS", "USDSM", "FDUSD", "USD1", "USDT0", "TUSD"}
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
WTRX = "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR"


# ---------------------------------------------------------------- basics
def now():
    return dt.datetime.now(dt.timezone.utc)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def due(st, key, t, minutes):
    """True if a periodic job is due; records the run time."""
    last = st.get(key)
    if last and t - parse_iso(last) < dt.timedelta(minutes=minutes):
        return False
    st[key] = iso(t)
    return True


def norm_domain(d):
    d = d.strip().lower()
    d = re.sub(r"^https?://", "", d).split("/")[0]
    return d[4:] if d.startswith("www.") else d


def rotate(items, st, key, n):
    """Return the next n items from a list, wrapping around, and move the cursor."""
    if not items:
        return []
    i = st.get(key, 0) % len(items)
    out = (items[i:] + items[:i])[:n]
    st[key] = (i + len(out)) % len(items)
    return out


class Budget:
    def __init__(self, seconds):
        self.end = time.time() + seconds

    def left(self):
        return self.end - time.time()

    def ok(self, need=0):
        return self.left() > need


class Http:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        a = requests.adapters.HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=0)
        self.s.mount("https://", a)
        self.s.mount("http://", a)

    def get(self, url, **kw):
        kw.setdefault("timeout", TIMEOUT)
        return self.s.get(url, **kw)

    def json(self, url, **kw):
        r = self.get(url, **kw)
        r.raise_for_status()
        return r.json()

    def post(self, url, **kw):
        kw.setdefault("timeout", TIMEOUT)
        return self.s.post(url, **kw)

    def snippet(self, url, limit=60000):
        """GET a page but read at most `limit` bytes (cheap site checks)."""
        r = self.s.get(url, timeout=TIMEOUT, stream=True, allow_redirects=True)
        chunks, size = [], 0
        try:
            for c in r.iter_content(8192):
                chunks.append(c)
                size += len(c)
                if size >= limit:
                    break
        finally:
            r.close()
        enc = r.encoding or "utf-8"
        r._snip = b"".join(chunks).decode(enc, "replace")
        return r


class Alert:
    def __init__(self, level, check, key, text):
        self.level, self.check, self.key, self.text = level, check, key, text

    def __repr__(self):
        return f"[{self.level}] {self.check}: {self.text}"


QUIET = os.environ.get("RADAR_QUIET") == "1"
ERRORS = {}


def log(*a):
    """In quiet mode (public repo) only error counts are printed, never names,
    addresses or alert text."""
    msg = " ".join(str(x) for x in a)
    if QUIET:
        k = msg.split(":")[0].split(" ")[0]
        with LOCK:
            ERRORS[k] = ERRORS.get(k, 0) + 1
    else:
        print(msg, file=sys.stderr)


# ---------------------------------------------------------------- tokens
def check_tokens(cfg, state, http, t, budget=None):
    alerts = []
    rules = cfg.get("token_rules", {})
    drop6, drop24 = rules.get("drop_6h_pct", 20), rules.get("drop_24h_pct", 25)
    st = state.setdefault("tokens", {})
    by_net = {}
    for tok in cfg.get("tokens", []):
        by_net.setdefault(tok["network"], []).append(tok)
    for net, toks in by_net.items():
        for i in range(0, len(toks), 30):
            part = toks[i:i + 30]
            try:
                data = http.json(f"https://api.geckoterminal.com/api/v2/networks/{net}/pools/multi/"
                                 + ",".join(x["pool"] for x in part))["data"]
            except Exception as e:
                log(f"tokens {net}: {e}")
                continue
            found = {d["attributes"]["address"].lower(): d["attributes"] for d in data}
            for tok in part:
                a = found.get(tok["pool"].lower())
                if not a:
                    continue
                ch = a.get("price_change_percentage") or {}
                h6, h24 = float(ch.get("h6") or 0), float(ch.get("h24") or 0)
                price = a.get("base_token_price_usd")
                last = st.get(tok["name"], {})
                rec = {"price": price, "h24": h24, "at": iso(t)}
                if last.get("alerted"):
                    rec["alerted"] = last["alerted"]
                st[tok["name"]] = rec
                if h6 <= -drop6 or h24 <= -drop24:
                    if last.get("alerted") and t - parse_iso(last["alerted"]) < dt.timedelta(hours=12):
                        continue
                    rec["alerted"] = iso(t)
                    alerts.append(Alert(HIGH, "token", f"tok:{tok['name']}:{t:%Y%m%d%H}",
                        f"TOKEN CRASH: {tok['name']} down {h6:.0f}% in 6h, {h24:.0f}% in 24h "
                        f"(price ${float(price):.3g}). https://www.geckoterminal.com/{net}/pools/{tok['pool']}"))
    return alerts


# ---------------------------------------------------------------- wallets
# Main stablecoin contracts, counted even when the explorer leaves out holder counts
KNOWN_STABLES = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "0x6b175474e89094c44da98b954eedeac495271d0f", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    "0xaf88d065e77c8cc2239327c5edb3a432268e5831", "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
    "0x0b2c639c533813f4aa9d7837caf62653d097ff85", "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58",
}


def wallet_usd_blockscout(http, chain, address):
    base = BLOCKSCOUT[chain]
    info = http.json(f"{base}/api/v2/addresses/{address}")
    rate = float(info.get("exchange_rate") or 0)
    if not rate and float(info.get("coin_balance") or 0) > 1e17:
        raise ValueError("explorer gave no native price")  # a bad read, not a drop
    native = float(info.get("coin_balance") or 0) / 1e18 * rate
    total, parts = native, ({"native": native} if native > 1 else {})
    for b in http.json(f"{base}/api/v2/addresses/{address}/token-balances"):
        tok = b.get("token") or {}
        sym = (tok.get("symbol") or "").upper()
        dec = int(tok.get("decimals") or 18)
        amt = float(b.get("value") or 0) / 10 ** dec
        holders = int(tok.get("holders_count") or tok.get("holders") or 0)
        if (tok.get("address_hash") or tok.get("address") or "").lower() in KNOWN_STABLES:
            usd = amt
        elif sym in STABLES and holders > 1000:
            usd = amt
        elif tok.get("exchange_rate") and holders > 1000:
            usd = amt * float(tok["exchange_rate"])
        else:
            continue  # unpriced, spam or fake token
        if usd > 1:
            parts[sym] = parts.get(sym, 0) + usd
            total += usd
    return total, parts


def outflow_usd_blockscout(http, chain, address, since, pages=6):
    """USD that really left the wallet since `since`, from its outgoing transfers.
    Used to confirm a balance drop before calling it a drain."""
    base, total = BLOCKSCOUT[chain], 0.0
    url = f"{base}/api/v2/addresses/{address}/token-transfers?filter=from"
    for _ in range(pages):
        d = http.json(url)
        old = False
        for i in d.get("items") or []:
            if parse_iso(i["timestamp"]) < since:
                old = True
                break
            tok = i.get("token") or {}
            tot = i.get("total") or {}
            amt = float(tot.get("value") or 0) / 10 ** int(tot.get("decimals") or tok.get("decimals") or 18)
            if (tok.get("address_hash") or tok.get("address") or "").lower() in KNOWN_STABLES:
                total += amt
            elif tok.get("exchange_rate") and int(tok.get("holders_count") or tok.get("holders") or 0) > 1000:
                total += amt * float(tok["exchange_rate"])
        nxt = d.get("next_page_params")
        if old or not nxt:
            break
        url = f"{base}/api/v2/addresses/{address}/token-transfers?filter=from&" + "&".join(f"{k}={v}" for k, v in nxt.items())
    info = http.json(f"{base}/api/v2/addresses/{address}")
    rate = float(info.get("exchange_rate") or 0)
    d = http.json(f"{base}/api/v2/addresses/{address}/transactions?filter=from")
    for i in d.get("items") or []:
        if i.get("timestamp") and parse_iso(i["timestamp"]) >= since:
            total += float(i.get("value") or 0) / 1e18 * rate
    return total


def wallet_usd_tron(http, address, trx_usd):
    d = (http.json(f"https://api.trongrid.io/v1/accounts/{address}").get("data") or [{}])
    d = d[0] if d else {}
    trx = float(d.get("balance") or 0) / 1e6
    usdt = 0.0
    for x in d.get("trc20") or []:
        if TRON_USDT in x:
            usdt = float(x[TRON_USDT]) / 1e6
    parts = {"TRX": trx * trx_usd, "USDT": usdt}
    return parts["TRX"] + usdt, {k: v for k, v in parts.items() if v > 1}


def trx_price(http):
    try:
        d = http.json(f"https://api.geckoterminal.com/api/v2/simple/networks/tron/token_price/{WTRX}")
        return float(list(d["data"]["attributes"]["token_prices"].values())[0])
    except Exception:
        return 0.0


def merge_private(cfg):
    """Private watchlists come from GitHub secrets so a public repo never shows them.
    RADAR_PRIVATE_YAML: YAML whose lists are added to the config's lists.
    RADAR_WALLETS_CSV: extra lines in wallets.csv format."""
    raw = os.environ.get("RADAR_PRIVATE_YAML")
    if raw:
        try:
            extra = yaml.safe_load(raw) or {}
        except Exception:
            log("private: unreadable RADAR_PRIVATE_YAML")
            extra = {}

        def merge(a, b):
            for k, v in b.items():
                if isinstance(v, list) and isinstance(a.get(k), list):
                    a[k] = a[k] + v
                elif isinstance(v, dict) and isinstance(a.get(k), dict):
                    merge(a[k], v)
                else:
                    a[k] = v
        merge(cfg, extra)
    cfg["_wallets_csv_extra"] = os.environ.get("RADAR_WALLETS_CSV", "")
    return cfg


def load_wallets(cfg, state, base_dir="."):
    """Config wallets + wallets.csv (name,chain,address,kind,min_usd) + auto-discovered."""
    ws = list(cfg.get("wallets", []))
    path = os.path.join(base_dir, cfg.get("wallets_csv", "wallets.csv"))
    lines = open(path, encoding="utf-8").read().splitlines() if os.path.exists(path) else []
    lines += (cfg.get("_wallets_csv_extra") or "").splitlines()
    if lines:
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.lower().startswith("name,"):
                continue
            p = [x.strip() for x in line.split(",")]
            if len(p) >= 3:
                w = {"name": p[0], "chain": p[1].lower(), "address": p[2], "kind": (p[3] if len(p) > 3 and p[3] else "hot")}
                if len(p) > 4 and p[4]:
                    w["min_usd"] = float(p[4])
                ws.append(w)
    pinned = {(w["chain"], w["address"].lower()) for w in ws}
    disc = [dict(v, address=k.split(":", 1)[1], chain=k.split(":", 1)[0], kind="hot", discovered=True)
            for k, v in sorted(state.get("discovered_wallets", {}).items())
            if (k.split(":", 1)[0], k.split(":", 1)[1]) not in pinned]
    return ws, disc


def check_wallets(cfg, state, http, t, budget=None, base_dir="."):
    alerts = []
    st = state.setdefault("wallets", {})
    pinned, disc = load_wallets(cfg, state, base_dir)
    # leads (stolen money, frozen funds) every run; the long list of casino wallets in rotation
    always = [w for w in pinned if w.get("kind") == "parked"]
    rest = [w for w in pinned if w.get("kind") != "parked" and w["chain"] in BLOCKSCOUT] + [w for w in disc if w["chain"] in BLOCKSCOUT]
    batch = always + rotate(rest, state.setdefault("cursors", {}), "wallets", cfg.get("wallets_per_run", 60))
    trx_usd = trx_price(http) if any(w["chain"] == "tron" for w in batch) else 0

    def one(w):
        if budget and not budget.ok(3):
            return w, None, "budget"
        try:
            if w["chain"] == "tron":
                return w, wallet_usd_tron(http, w["address"], trx_usd), None
            if w["chain"] not in BLOCKSCOUT:
                return w, None, "budget"  # polygon/bsc wallets are covered by the chain watcher
            return w, wallet_usd_blockscout(http, w["chain"], w["address"]), None
        except Exception as e:
            return w, None, e

    with ThreadPoolExecutor(10) as ex:
        results = list(ex.map(one, batch))
    for w, res, err in results:
        key = f"{w['chain']}:{w['address'].lower()}"
        if err or res is None:
            if err != "budget":
                log(f"wallet {w['name']}: {err}")
            continue
        usd, parts = res
        rec = st.get(key, {"hist": []})
        hist = [h for h in rec.get("hist", []) if t - parse_iso(h[0]) < dt.timedelta(hours=24)]
        prev = hist[-1][1] if hist else None
        peak = max([h[1] for h in hist] + [usd])
        hist.append([iso(t), round(usd, 2)])
        rec["hist"] = hist[-60:]
        st[key] = rec
        if prev is None:
            continue
        label = f"{w['name']} ({w['chain']} {w['address'][:8]}…{w['address'][-4:]})"
        parts_txt = ", ".join(f"{k} ${v:,.0f}" for k, v in sorted(parts.items(), key=lambda x: -x[1])[:4])
        link = (f"https://tronscan.org/#/address/{w['address']}" if w["chain"] == "tron"
                else f"{BLOCKSCOUT.get(w['chain'], '')}/address/{w['address']}")
        if w.get("kind") == "parked":
            moved = prev - usd
            if moved >= max(float(w.get("min_usd", 25000)), 0.05 * prev):
                alerts.append(Alert(HIGH, "wallet", f"w:{key}:{t:%Y%m%d%H}",
                    f"PARKED MONEY MOVED: {label} dropped ${moved:,.0f} (now ${usd:,.0f}). {parts_txt} {link}"))
        else:
            fall = peak - usd
            if peak > 0 and fall >= float(w.get("min_usd", 250000)) and fall / peak * 100 >= w.get("drop_pct", 60):
                if rec.get("alerted") and t - parse_iso(rec["alerted"]) < dt.timedelta(hours=6):
                    continue
                if w["chain"] in BLOCKSCOUT:
                    # A drop in the reading alone is not a drain: explorers sometimes return a
                    # half-empty balance. Read again and check the money actually went out.
                    try:
                        usd2, parts2 = wallet_usd_blockscout(http, w["chain"], w["address"])
                        sent = outflow_usd_blockscout(http, w["chain"], w["address"], t - dt.timedelta(hours=24))
                    except Exception as e:
                        log(f"wallet {w['name']}: drain check failed: {e}")
                        rec["hist"] = rec["hist"][:-1]  # drop the doubtful reading
                        continue
                    if (peak - usd2) / peak * 100 < w.get("drop_pct", 60) or sent < 0.5 * (peak - usd2):
                        log(f"wallet {w['name']}: drop not confirmed (reread ${usd2:,.0f}, sent ${sent:,.0f}); ignored")
                        rec["hist"] = [[iso(t), round(usd2, 2)]]  # restart the 24h window from a good read
                        continue
                    usd, fall, parts_txt = usd2, peak - usd2, ", ".join(
                        f"{k} ${v:,.0f}" for k, v in sorted(parts2.items(), key=lambda x: -x[1])[:4])
                    parts_txt += f". ${sent:,.0f} sent out in 24h"
                rec["alerted"] = iso(t)
                alerts.append(Alert(HIGH, "wallet", f"w:{key}:{t:%Y%m%d%H}",
                    f"WALLET DRAIN: {label} fell {fall / peak * 100:.0f}% in 24h, ${peak:,.0f} -> ${usd:,.0f}. "
                    f"{parts_txt} {link}"))
    return alerts


def discover_wallets(cfg, state, http, t, budget=None):
    """Always on: rotates through every (chain, casino name) pair and keeps the wallets that
    block explorers label with that name. Deposit addresses are skipped; hot wallets and named
    wallets are kept. A full pass over ~200 names x 5 chains takes about a day."""
    found = state.setdefault("discovered_wallets", {})
    before = len(found)
    skip = re.compile(r"deposit address|staking|token|deployer|competition|nft|airdrop|\.eth$", re.I)
    pairs = [(c, b) for b in cfg.get("wallet_brands", []) for c in cfg.get("discover_chains", ["eth"]) if c in BLOCKSCOUT]
    for chain, brand in rotate(pairs, state.setdefault("cursors", {}), "discover", cfg.get("discover_per_run", 40)):
        if budget and not budget.ok(5):
            break
        base = BLOCKSCOUT[chain]
        key = re.sub(r"\.(com|us|gg|io|bet|game|games|casino)$", "", brand.lower())
        key = re.sub(r"[^a-z0-9]", "", key)
        url = f"{base}/api/v2/search?q={urllib.parse.quote(brand)}"
        for _ in range(4):
            try:
                r = http.json(url)
            except Exception as e:
                log(f"discover {brand}: {e}")
                break
            for x in r.get("items") or []:
                name = ((x.get("metadata") or {}).get("name") or "")
                a = x.get("address_hash")
                if x.get("type") != "metadata_tag" or not a or skip.search(name):
                    continue
                if key not in re.sub(r"[^a-z0-9]", "", name.lower()):
                    continue
                found.setdefault(f"{chain}:{a.lower()}", {"name": name, "min_usd": 250000})
            npp = r.get("next_page_params")
            if not npp:
                break
            url = f"{base}/api/v2/search?q={urllib.parse.quote(brand)}&{urllib.parse.urlencode(npp)}"
    added = len(found) - before
    return [Alert(LOW, "wallets", f"disc:{t:%Y%m%d%H%M}", f"Wallet discovery: {added} new labelled casino wallets, {len(found)} watched in total")] if added else []


# ---------------------------------------------------------------- freezes
def check_freezes(cfg, state, http, t, budget=None):
    rules = cfg.get("freeze_rules", {})
    win = dt.timedelta(minutes=rules.get("batch_minutes", 15))
    min_batch = rules.get("min_batch", 3)
    big = rules.get("big_single_usd", 1_000_000)
    st = state.setdefault("freezes", {"seen": []})
    seen = set(st.get("seen", []))
    try:
        items = http.json("https://stablescan.achivx.com/v1/freezes/acts?limit=200")["items"]
    except Exception as e:
        log(f"freezes: {e}")
        return []
    first_run = not st.get("seen")
    new = [x for x in items if x["action"] in ("freeze", "seize") and f"{x['tx_hash']}:{x['subject']}" not in seen]
    for x in items:
        seen.add(f"{x['tx_hash']}:{x['subject']}")
    st["seen"] = list(seen)[-3000:]
    if first_run or not new:
        return []

    pinned, disc = load_wallets(cfg, state)
    casino = {w["address"].lower(): w["name"] for w in pinned + disc}

    def amount(x):
        usd = None
        try:
            r = http.json(f"https://stablescan.achivx.com/v1/addresses/{x['subject']}?chain={x['chain_slug']}")
            for f in r.get("freeze") or []:
                if f.get("token") == x["token"] and f.get("frozen_usd6") is not None:
                    usd = f["frozen_usd6"] / 1e6
        except Exception:
            pass
        try:  # does the frozen wallet trade with a casino wallet we watch?
            g = http.json(f"https://stablescan.achivx.com/v1/addresses/{x['subject']}/graph?chain={x['chain_slug']}")
            x["linked"] = sorted({casino[n["address"].lower()] for n in g.get("nodes") or []
                                  if n.get("hop") == 1 and (n.get("address") or "").lower() in casino})
        except Exception:
            x["linked"] = []
        return usd

    with ThreadPoolExecutor(6) as ex:
        amts = list(ex.map(amount, new[:40]))
    for x, a in zip(new, amts + [None] * len(new)):
        x["usd"] = a
    new.sort(key=lambda x: (x["chain_slug"], x["block_time"]))
    groups, cur = [], []
    for x in new:
        if cur and (x["chain_slug"] != cur[-1]["chain_slug"] or
                    parse_iso(x["block_time"]) - parse_iso(cur[0]["block_time"]) > win):
            groups.append(cur)
            cur = []
        cur.append(x)
    if cur:
        groups.append(cur)
    alerts = []
    for x in new:
        if x.get("linked"):
            alerts.append(Alert(HIGH, "freeze", f"fzl:{x['tx_hash']}:{x['subject']}",
                f"FROZEN WALLET LINKED TO A CASINO: {x['token']} freeze on {x['chain_slug']}, ${x.get('usd') or 0:,.0f} locked. "
                f"It has traded directly with {', '.join(x['linked'][:4])}. {x['subject']}"))
    for g in groups:
        total = sum(x.get("usd") or 0 for x in g)
        biggest = max((x.get("usd") or 0) for x in g)
        if len(g) >= min_batch or biggest >= big:
            lines = "; ".join(f"{x['subject']} ${x['usd'] or 0:,.0f}" for x in sorted(g, key=lambda x: -(x.get('usd') or 0))[:6])
            alerts.append(Alert(HIGH, "freeze", f"fz:{g[0]['tx_hash']}",
                f"FREEZE BATCH: {len(g)} {g[0]['token']} freezes on {g[0]['chain_slug']} at {g[0]['block_time'][:16]}Z, "
                f"about ${total:,.0f} locked. {lines} https://stablescan.achivx.com"))
        else:
            for x in g:
                alerts.append(Alert(LOW, "freeze", f"fz:{x['tx_hash']}:{x['subject']}",
                    f"Freeze {x['token']} {x['chain_slug']} {x['subject']} ${x.get('usd') or 0:,.0f}"))
    return alerts


# ---------------------------------------------------------------- sites
MAINT_RE = re.compile(r"(under maintenance|maintenance mode|scheduled maintenance|we.ll be back|"
                      r"temporarily unavailable|technical work|site is down|currently unavailable|"
                      r"en mantenimiento|wartungsarbeiten|manuten[cç][aã]o|bakımda|в разработке|техническ)", re.I)
CHALLENGE_RE = re.compile(r"(just a moment|cf-chl|attention required|checking your browser|ddos-guard|captcha|"
                          r"access denied|not available in your (country|region)|restricted (country|region)|"
                          r"geo.?block)", re.I)
SEIZED_RE = re.compile(r"(this (domain|website|site) (name )?has been seized|seized by (the )?(fbi|police|homeland|europol|law enforcement)|"
                       r"domain seized|website seized|beschlagnahmt|zabaven[aoý]|saisi par|sequestrad[oa] por|in beslag genomen)", re.I)
NOTICE_RE = re.compile(r"(withdrawals? (are |is )?(temporarily )?(paused|suspended|disabled|delayed|unavailable)|"
                       r"(we are|we're) (closing|shutting down|ceasing)|ceas(e|ing) (all )?operations|"
                       r"no longer (accept|available)|final withdrawal|account(s)? will be closed|"
                       r"security incident|unauthori[sz]ed access|we (have been|were) (hacked|attacked))", re.I)
PARKED_RE = re.compile(r"(domain (is )?for sale|buy this domain|parked free|sedo|dan\.com|afternic|"
                       r"this domain (name )?(has expired|is parked)|godaddy\.com/forsale)", re.I)


def classify_site(http, domain):
    try:
        r = http.snippet(f"https://{domain}")
    except requests.exceptions.SSLError:
        return "down", "TLS error"
    except requests.exceptions.ConnectionError as e:
        s = str(e)
        return "down", "DNS failure" if ("Name or service" in s or "NameResolution" in s or "getaddrinfo" in s) else "no connection"
    except requests.exceptions.Timeout:
        return "down", "timeout"
    except Exception as e:
        return "blocked", f"error {type(e).__name__}"
    body = getattr(r, "_snip", "")
    title = (re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S) or [None, ""])[1].strip()[:80]
    if "maintenance" in r.url.lower():
        return "maintenance", f"redirects to {r.url[:80]}"
    if SEIZED_RE.search(body[:30000]):
        return "seized", "page shows a seizure banner"
    if PARKED_RE.search(body[:20000]):
        return "parked", "domain parked or for sale"
    if CHALLENGE_RE.search(body[:20000]) and r.status_code in (403, 429, 451, 503):
        return "blocked", f"bot or geo check {r.status_code}"
    if r.status_code >= 500:
        return "down", f"HTTP {r.status_code}"
    visible = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", body, flags=re.S | re.I)
    m = MAINT_RE.search(title) or (MAINT_RE.search(visible) if len(visible.split()) < 400 else None)
    if m:
        return "maintenance", f"page says: {title or m.group(0)}"
    n = NOTICE_RE.search(visible[:30000])
    if n:
        return "notice", f"page says: \"{n.group(0)}\""
    host = norm_domain(r.url)
    if host and host != norm_domain(domain) and not host.endswith("." + norm_domain(domain)) \
            and not norm_domain(domain).endswith("." + host):
        return "moved", f"now redirects to {host}"
    if r.status_code in (401, 403, 404, 410, 429, 451):
        return "blocked", f"HTTP {r.status_code}"
    return "up", f"HTTP {r.status_code}"


def licence_index(state):
    """domain -> (regulator, licence number, company), from the stored registers."""
    idx = {}
    for num, rec in (state.get("registers", {}).get("anjouan") or {}).items():
        for d in rec.get("domains", []):
            idx.setdefault(d, ("Anjouan", num, rec.get("company", "")))
    for num, rec in (state.get("registers", {}).get("curacao") or {}).items():
        for d in rec.get("domains", []):
            idx.setdefault(d, ("Curaçao", num, rec.get("company", "")))
    return idx


def check_sites(cfg, state, http, t, budget=None):
    """Priority sites every run; all register domains in rotation. A domain that
    looks bad is rechecked next run together with every domain on its licence."""
    rules = cfg.get("site_rules", {})
    st = state.setdefault("sites", {})
    idx = licence_index(state)
    priority = [norm_domain(s if isinstance(s, str) else s["domain"]) for s in cfg.get("sites", [])]
    recheck = state.get("site_recheck", [])
    pool = sorted(set(idx) - set(priority))
    batch = list(dict.fromkeys(priority + recheck +
                               rotate(pool, state.setdefault("cursors", {}), "sites", rules.get("rotation_per_run", 500))))

    def one(d):
        if budget and not budget.ok(TIMEOUT + 2):
            return d, None
        return d, classify_site(http, d)

    with ThreadPoolExecutor(rules.get("threads", 64)) as ex:
        res = dict(ex.map(one, batch))
    went_bad, came_back, suspects = [], [], set()
    for d, r in res.items():
        if r is None:
            continue
        status, why = r
        if status == "blocked":
            continue
        rec = st.get(d)
        if rec is None:  # first sighting: baseline, no alert
            st[d] = {"s": status, "n": 2, "r": "up" if status == "up" else status, "w": why, "at": iso(t)}
            continue
        rec["n"] = rec["n"] + 1 if status == rec["s"] else 1
        rec["s"], rec["w"], rec["at"] = status, why, iso(t)
        bad = status in ("maintenance", "down", "parked", "notice", "moved", "seized")
        if bad and rec["n"] == 1 and rec["r"] == "up":
            suspects.add(d)  # recheck next run before alerting
        if bad and rec["n"] >= 2 and rec["r"] == "up":
            rec["r"] = status
            went_bad.append((d, status, why))
        elif status == "up" and rec["r"] != "up" and rec["n"] >= 2:
            rec["r"] = "up"
            came_back.append(d)
    # recheck suspects and their licence siblings next run
    nxt = set(suspects)
    for d in suspects:
        if d in idx:
            lic = idx[d][1]
            nxt |= {x for x, v in idx.items() if v[1] == lic}
    state["site_recheck"] = sorted(nxt)[:400]
    alerts = []
    by_lic = {}
    for d, s, why in went_bad:
        lic = idx.get(d)
        by_lic.setdefault(lic[:2] if lic else ("none", d), []).append((d, s, why, lic))
    cluster = rules.get("cluster_min", 3)
    used = set()
    for k, items in by_lic.items():
        if k[0] != "none" and len(items) >= cluster:
            _, num, company = items[0][3]
            used |= {i[0] for i in items}
            alerts.append(Alert(HIGH, "sites", f"lic:{num}:{t:%Y%m%d}",
                f"LICENCE CLUSTER DOWN: {len(items)} sites under {k[0]} licence {num} ({company}) went down: "
                + ", ".join(f"{d} ({s})" for d, s, _, _ in items[:15]) + ". Same licence holder: check bankroll/platform."))
    rest = [x for x in went_bad if x[0] not in used]
    prio = set(priority)
    if len(rest) >= rules.get("run_cluster_min", 8):
        alerts.append(Alert(HIGH, "sites", f"cluster:{t:%Y%m%d%H}",
            f"MANY SITES DOWN AT ONCE: {len(rest)} casino sites: " + ", ".join(f"{d} ({s})" for d, s, _ in rest[:25])))
    else:
        for d, s, why in rest:
            lic = idx.get(d)
            lic_txt = f" [{lic[0]} {lic[1]}, {lic[2]}]" if lic else ""
            level = HIGH if d in prio or s in ("seized", "notice") else LOW
            alerts.append(Alert(level, "sites", f"site:{d}:{t:%Y%m%d}", f"{d} is {s}: {why}{lic_txt}"))
    for d in came_back:
        alerts.append(Alert(HIGH if d in prio else LOW, "sites", f"back:{d}:{t:%Y%m%d}", f"{d} is back up"))
    state["sites_meta"] = {"checked": sum(1 for v in res.values() if v), "known": len(st), "at": iso(t)}
    return alerts


# ---------------------------------------------------------------- registers
def fetch_anjouan(http):
    h = http.get("https://anjouangaming.com/public-register/license-register/", timeout=25).text
    m = re.search(r'<script[^>]*id="ag-licence-data"[^>]*>(.*?)</script>', h, re.S)
    if not m:
        raise ValueError("Anjouan register data block not found")
    rows = json.loads(m.group(1))
    out = {}
    for r in rows:
        num = (r.get("number") or "").strip()
        if not num:
            continue
        doms = sorted({norm_domain(x) for x in str(r.get("domains") or "").split(",") if x.strip()})
        out[num] = {"company": (r.get("company") or "").strip(), "status": (r.get("status") or "").lower(),
                    "type": r.get("type"), "issued": r.get("issued"), "expiry": r.get("expiry"), "domains": doms}
    return out


def stem(d):
    s = d.split(".")[0]
    s = re.sub(r"(casino|bet|win|play|\d+)$", "", s) or s
    return re.sub(r"^(the|my|play)", "", s)


def diff_register(name, old, new, brands, t):
    """Compare two register snapshots: licences and domains added or removed,
    status changes, and mirror brands that reappear under another company."""
    alerts = []
    brand_re = re.compile("|".join(re.escape(b.lower()) for b in brands)) if brands else None

    def known(ds):
        return [d for d in ds if brand_re and brand_re.search(d)]

    for num in sorted(set(old) - set(new)):
        o = old[num]
        lvl = HIGH if known(o["domains"]) or len(o["domains"]) >= 5 else LOW
        alerts.append(Alert(lvl, "register", f"reg:{name}:gone:{num}",
            f"{name.upper()} LICENCE GONE from register: {num} {o['company']} ({len(o['domains'])} domains: "
            f"{', '.join(o['domains'][:8])})"))
    # stems of domains held by each company, to spot mirrors under a new company
    stems_by_company = {}
    for num, o in old.items():
        for d in o["domains"]:
            stems_by_company.setdefault(stem(d), set()).add(o["company"])
    for num in sorted(set(new) - set(old)):
        n = new[num]
        mirrors = sorted({d for d in n["domains"] if any(c != n["company"] for c in stems_by_company.get(stem(d), set()))})
        if len(mirrors) >= 2:
            owners = sorted({c for d in mirrors for c in stems_by_company.get(stem(d), set()) if c != n["company"]})
            alerts.append(Alert(HIGH, "register", f"reg:{name}:mirror:{num}",
                f"{name.upper()} NEW LICENCE WITH COPIED BRANDS: {num} {n['company']} has {len(mirrors)} domains matching "
                f"brands of {', '.join(owners[:4])}: {', '.join(mirrors[:10])}"))
        else:
            lvl = HIGH if known(n["domains"]) else LOW
            alerts.append(Alert(lvl, "register", f"reg:{name}:new:{num}",
                f"{name.capitalize()} new licence {num} {n['company']} ({n.get('type') or ''}): {', '.join(n['domains'][:10])}"))
    for num in sorted(set(old) & set(new)):
        o, n = old[num], new[num]
        if o.get("status") != n.get("status"):
            alerts.append(Alert(HIGH, "register", f"reg:{name}:status:{num}:{n.get('status')}",
                f"{name.upper()} STATUS CHANGE: {num} {n['company']} {o.get('status')} -> {n.get('status')} "
                f"({', '.join(n['domains'][:8])})"))
        gone = sorted(set(o["domains"]) - set(n["domains"]))
        added = sorted(set(n["domains"]) - set(o["domains"]))
        if gone:
            lvl = HIGH if known(gone) or len(gone) >= 5 else LOW
            alerts.append(Alert(lvl, "register", f"reg:{name}:dgone:{num}:{','.join(gone)[:60]}",
                f"{name.capitalize()} licence {num} ({n['company']}) dropped {len(gone)} domains: {', '.join(gone[:10])}"))
        if added:
            alerts.append(Alert(LOW, "register", f"reg:{name}:dadd:{num}:{','.join(added)[:60]}",
                f"{name.capitalize()} licence {num} ({n['company']}) added {len(added)} domains: {', '.join(added[:10])}"))
    return alerts


CGA_RE = {
    "lic": re.compile(r"license number\s+([A-Z]+/\d{4}/\d+/\d+)"),
    "company": re.compile(r"certify that\s+(.+?),\s+a company"),
    "status": re.compile(r"License status:\s*([A-Za-z ]+?)\."),
    "app": re.compile(r"Application status:\s*([A-Za-z ]+?)\."),
}


def parse_cga(text):
    plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "\n", text))
    lic = CGA_RE["lic"].search(plain)
    if not lic:
        return None
    block = re.sub(r"<[^>]+>", "\n", text)
    m = re.search(r"following domains under its license:(.*?)(Copyright|$)", block, re.S)
    doms = []
    if m:
        doms = sorted({norm_domain(x) for x in m.group(1).split("\n") if re.match(r"^\s*[a-z0-9.-]+\.[a-z]{2,}\s*$", x, re.I)})
    g = lambda k: (CGA_RE[k].search(plain).group(1).strip() if CGA_RE[k].search(plain) else "")
    return {"number": lic.group(1), "company": html.unescape(g("company")), "status": g("status").lower(),
            "app": g("app").lower(), "domains": doms}


def check_registers(cfg, state, http, t, budget=None):
    rcfg = cfg.get("registers", {})
    regs = state.setdefault("registers", {})
    jobs = state.setdefault("jobs", {})
    brands = cfg.get("forum", {}).get("brands", [])
    alerts = []
    # Anjouan: one page holds the whole register
    if due(jobs, "anjouan", t, rcfg.get("anjouan_every_minutes", 360)):
        try:
            new = fetch_anjouan(http)
            old = regs.get("anjouan")
            if old and len(new) > 0.5 * len(old):
                alerts += diff_register("anjouan", old, new, brands, t)
            regs["anjouan"] = new
        except Exception as e:
            jobs.pop("anjouan", None)
            log(f"anjouan: {e}")
    # Curacao: certificate pages, slowly (the server rate-limits)
    cur = regs.setdefault("curacao", {})
    cst = state.setdefault("curacao_crawl", {"next": rcfg.get("curacao_first_id", 1), "miss": 0})
    max_id = rcfg.get("curacao_max_id", 3000)
    per_run = rcfg.get("curacao_per_run", 12)
    known_ids = sorted(int(k.split("/")[-1]) for k in cur)
    # half the slots go to new ids, half to re-checking known licences
    ids = []
    for _ in range(per_run // 2):
        ids.append(cst["next"])
        cst["next"] = cst["next"] + 1 if cst["next"] < max_id else 1
    ids += rotate(known_ids, state.setdefault("cursors", {}), "curacao_known", per_run - len(ids))
    for i in ids:
        if budget and not budget.ok(6):
            break
        try:
            r = http.get(f"https://cert.cga.cw/token?id={i}", timeout=10)
        except Exception as e:
            log(f"curacao {i}: {e}")
            continue
        if r.status_code == 429:
            log("curacao: rate limited, stopping for this run")
            break
        rec = parse_cga(r.text) if r.status_code == 200 else None
        time.sleep(rcfg.get("curacao_delay_s", 2.5))
        if not rec:
            continue
        num = rec.pop("number")
        old = cur.get(num)
        cur[num] = rec
        if old:
            alerts += diff_register("curacao", {num: old}, {num: rec}, brands, t)
        elif cst.get("seeded"):
            # a licence id we had never seen, after the first full pass: a new licence
            alerts += diff_register("curacao", {}, {num: rec}, brands, t)
    if cst["next"] == 1 and known_ids:
        cst["seeded"] = True
    return alerts


# ---------------------------------------------------------------- news
def gnews(http, query, lang, country, ceid=None):
    q = urllib.parse.quote(query + " when:2d")
    ceid = ceid or f"{country}:{lang.split('-')[0]}"
    r = http.get(f"https://news.google.com/rss/search?q={q}&hl={lang}&gl={country}&ceid={ceid}")
    if r.status_code in (429, 503):
        raise RuntimeError("rate limited")
    r.raise_for_status()
    out = []
    for m in re.finditer(r"<item>(.*?)</item>", r.text, re.S):
        it = m.group(1)

        def g(tag):
            mm = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", it, re.S)
            return html.unescape(mm.group(1)).strip() if mm else ""
        su = re.search(r'<source[^>]+url=["\']([^"\']+)', it)
        out.append({"title": g("title"), "link": g("link"), "date": g("pubDate"), "source": g("source"),
                    "source_url": su.group(1) if su else ""})
    return out


def news_jobs(ncfg, extra_brands=()):
    brands = list(ncfg.get("brands", []))
    have = {b.lower() for b in brands}
    more = [b for b in extra_brands if b.lower() not in have and b.lower() not in AMBIGUOUS_BRANDS and len(b) >= 4]
    harvest = ncfg.get("harvest_words", [])
    size = ncfg.get("brands_per_query", 10)
    chunks = [brands[i:i + size] for i in range(0, len(brands), size)]
    jobs = []
    for e, ed in enumerate(ncfg.get("editions", [])):
        words = ed.get("words", [])
        for q in ed.get("queries", []):
            jobs.append((e, q, "generic"))
        for w in ed.get("words", [])[:harvest and 4 or 0]:
            jobs.append((e, w, "harvest"))  # broad local searches: mostly to learn new outlets
        for c, ch in enumerate(chunks):
            q = "(" + " OR ".join(f'"{b}"' for b in ch) + ")"
            if words:
                q += " (" + " OR ".join(f'"{w}"' if " " in w else w for w in words) + ")"
            jobs.append((e, q, "brand"))
        if ed.get("lang", "").startswith("en") and more:
            # every other casino we track, searched in the English editions with that edition's trouble words
            for i in range(0, len(more), size):
                q = "(" + " OR ".join(f'"{b}"' for b in more[i:i + size]) + ")"
                if words:
                    q += " (" + " OR ".join(f'"{w}"' if " " in w else w for w in words) + ")"
                jobs.append((e, q, "brand"))
    return jobs


def check_news(cfg, state, http, t, budget=None):
    ncfg = cfg.get("news", {})
    st = state.setdefault("news", {"seen": []})
    seen = set(st.get("seen", []))
    first_run = not seen
    jobs = news_jobs(ncfg, cfg.get("wallet_brands", []))
    batch = rotate(jobs, state.setdefault("cursors", {}), "news", ncfg.get("queries_per_run", 40))
    eds = ncfg.get("editions", [])
    exclude = [x.lower() for x in ncfg.get("exclude_sources", [])]
    hot = re.compile("|".join(re.escape(b.lower()) for b in ncfg.get("brands", []) + ncfg.get("hot_words", [])), re.I)
    topic_re_news = outlet_terms(cfg)[2]
    stop = threading.Event()

    def run(job):
        e, q, kind = job
        if stop.is_set() or (budget and not budget.ok(TIMEOUT + 2)):
            return job, []
        ed = eds[e]
        try:
            return job, gnews(http, q, ed["lang"], ed["country"], ed.get("ceid"))
        except Exception as ex:
            if "rate limited" in str(ex):
                stop.set()
            log(f"news {ed['lang']}: {ex}")
            return job, []

    with ThreadPoolExecutor(ncfg.get("threads", 4)) as ex:
        results = list(ex.map(run, batch))
    alerts = []
    learned = state.setdefault("learned_outlets", {})
    for (e, q, kind), items in results:
        ed = eds[e]
        for it in items:
            dom = norm_domain(it.get("source_url") or "")
            if dom and "." in dom and dom not in learned and len(learned) < ncfg.get("learn_max", 8000):
                learned[dom] = ed["country"]
            k = hashlib.sha1(re.sub(r"\W+", "", it["title"].lower()).encode()).hexdigest()[:16]
            if k in seen:
                continue
            seen.add(k)
            if first_run:
                continue
            if any(x in (it["source"] or "").lower() for x in exclude):
                continue
            try:
                if t - parsedate_to_datetime(it["date"]) > dt.timedelta(hours=ncfg.get("max_age_hours", 36)):
                    continue
            except Exception:
                pass
            if kind == "harvest" and not hot.search(it["title"]) and not topic_re_news.search(it["title"]):
                continue
            level = HIGH if kind == "brand" or hot.search(it["title"]) else LOW
            alerts.append(Alert(level, "news", f"n:{k}", f"[{ed['lang']}] {it['title']} ({it['date'][5:16]}) {it['link']}"))
    st["seen"] = list(seen)[-8000:]
    return alerts


# ---------------------------------------------------------------- forum
TOPIC_RE = re.compile(r'<span id="msg_\d+"><a href="[^"]*topic=(\d+)\.0">([^<]+)</a>')


TROUBLE_RE = re.compile(r"scam|not pay|won.?t pay|withdraw|locked|frozen|confiscat|kyc|stuck|delay|exit|hack|"
                        r"rigged|closed|shut|disappear|stole|stolen|refus|ban+ed|blocked|missing|lost", re.I)


def check_forum(cfg, state, http, t, budget=None):
    fcfg = cfg.get("forum", {})
    st = state.setdefault("forum", {"seen": [], "hits": {}})
    seen = set(st.get("seen", []))
    first_run = not seen
    brands = [b.lower() for b in fcfg.get("brands", [])]
    brand_res = [(b, re.compile(r"(?<![a-z0-9])" + re.escape(b) + r"(?![a-z0-9])")) for b in brands]
    words = re.compile("|".join(fcfg.get("words", ["withdraw", "scam", "hack", "frozen", "rigged"])), re.I)
    alerts = []
    for board in fcfg.get("boards", [83]):
        bid, pages = (board, 1) if isinstance(board, int) else (board["id"], board.get("pages", 1))
        for p in range(pages):
            try:
                h = http.get(f"https://bitcointalk.org/index.php?board={bid}.{p * 40}", timeout=12).text
            except Exception as e:
                log(f"forum {bid}: {e}")
                continue
            time.sleep(1)
            for tid, title in TOPIC_RE.findall(h):
                title = html.unescape(title).strip()
                if tid in seen:
                    continue
                seen.add(tid)
                if first_run:
                    continue
                tl = title.lower()
                brand = next((b for b, rx in brand_res if rx.search(tl)), None)
                scam_board = bid in fcfg.get("scam_boards", [83])
                trouble = TROUBLE_RE.search(title)
                gambling = re.search(r"casino|gambl|bet|dice|slots?|poker|sportsbook|crash|plinko|bankroll", tl)
                if not brand and not (scam_board and (words.search(title) or gambling)) and not (gambling and trouble):
                    continue
                if not brand:
                    alerts.append(Alert(HIGH if scam_board and trouble and gambling else LOW, "forum", f"bt:{tid}",
                                        f"BitcoinTalk: {title} https://bitcointalk.org/index.php?topic={tid}.0"))
                    continue
                url = f"https://bitcointalk.org/index.php?topic={tid}.0"
                if brand:
                    hits = [x for x in st["hits"].get(brand, []) if t - parse_iso(x) < dt.timedelta(days=7)]
                    if scam_board:
                        hits.append(iso(t))
                    st["hits"][brand] = hits
                    many = len(hits) >= fcfg.get("repeat_threshold", 2)
                    level = HIGH if (scam_board and many) or (scam_board and words.search(title) and fcfg.get("brand_scam_is_high", True)) else LOW
                    extra = f" ({len(hits)} scam threads on {brand} this week)" if many else ""
                    alerts.append(Alert(level, "forum", f"bt:{tid}", f"BitcoinTalk: {title}{extra} {url}"))
                else:
                    alerts.append(Alert(LOW, "forum", f"bt:{tid}", f"BitcoinTalk: {title} {url}"))
    st["seen"] = list(seen)[-6000:]
    return alerts


# ---------------------------------------------------------------- pages
def check_pages(cfg, state, http, t, budget=None):
    """Regulator and enforcement pages: alert on new links."""
    pcfg = cfg.get("pages", {})
    if not due(state.setdefault("jobs", {}), "pages", t, pcfg.get("every_minutes", 180)):
        return []
    st = state.setdefault("pages", {})
    alerts = []

    def one(p):
        try:
            return p, http.get(p["url"], timeout=15).text
        except Exception as e:
            log(f"page {p['name']}: {e}")
            return p, None

    with ThreadPoolExecutor(6) as ex:
        results = list(ex.map(one, pcfg.get("list", [])))
    for p, h in results:
        if not h:
            continue
        rx = re.compile(p.get("link_pattern", "."), re.I)
        links = []
        for href, text in re.findall(r'<a[^>]+href="([^"#]+)"[^>]*>(.*?)</a>', h, re.S | re.I):
            text = re.sub(r"<[^>]+>|\s+", " ", html.unescape(text)).strip()
            full = urllib.parse.urljoin(p["url"], href)
            if rx.search(full) or rx.search(text):
                links.append((full, text[:140]))
        old = set(st.get(p["name"], []))
        cur = {l for l, _ in links}
        if old:
            for l, txt in links:
                if l not in old:
                    alerts.append(Alert(HIGH if p.get("high") else LOW, "pages", f"pg:{l}",
                        f"{p['name']}: new item: {txt or l} {l}"))
                    old.add(l)
        st[p["name"]] = sorted(old | cur)[-1500:]
    return alerts


# ---------------------------------------------------------------- chain watcher
RPC = {
    "eth": "https://ethereum-rpc.publicnode.com",
    "polygon": "https://polygon-bor-rpc.publicnode.com",
    "bsc": "https://bsc-rpc.publicnode.com",
    "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
    "base": "https://base-rpc.publicnode.com",
    "optimism": "https://optimism-rpc.publicnode.com",
    "etherlink": "https://node.mainnet.etherlink.com",
}
TOPIC = {
    "Transfer": "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    "OwnershipTransferred": "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
    "RoleGranted": "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d",
    "RoleRevoked": "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b",
    "Upgraded": "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
    "AdminChanged": "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f",
    "Paused": "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258",
    "Unpaused": "0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa",
    "BeaconUpgraded": "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e",
}
ADMIN_TOPICS = {v: k for k, v in TOPIC.items() if k != "Transfer"}
# major tokens per chain: address -> (symbol, decimals, usd per unit or None = use native price)
MAJOR = {
    "eth": {"0xdac17f958d2ee523a2206206994597c13d831ec7": ("USDT", 6, 1), "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", 6, 1),
            "0x6b175474e89094c44da98b954eedeac495271d0f": ("DAI", 18, 1), "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ("WETH", 18, None)},
    "polygon": {"0xc2132d05d31c914a87c6611c10748aeb04b58e8f": ("USDT", 6, 1), "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": ("USDC", 6, 1),
                "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": ("USDC.e", 6, 1), "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063": ("DAI", 18, 1),
                "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619": ("WETH", 18, None)},
    "bsc": {"0x55d398326f99059ff775485246999027b3197955": ("USDT", 18, 1), "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": ("USDC", 18, 1)},
    "arbitrum": {"0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": ("USDT", 6, 1), "0xaf88d065e77c8cc2239327c5edb3a432268e5831": ("USDC", 6, 1),
                 "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": ("WETH", 18, None)},
    "base": {"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": ("USDC", 6, 1), "0x4200000000000000000000000000000000000006": ("WETH", 18, None)},
    "optimism": {"0x0b2c639c533813f4aa9d7837caf62653d097ff85": ("USDC", 6, 1), "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58": ("USDT", 6, 1),
                 "0x4200000000000000000000000000000000000006": ("WETH", 18, None)},
    "etherlink": {"0x796ea11fa2dd751ed01b53c372ffdb4aaa8f00f9": ("USDC", 6, 1), "0x2c03058c8afc06713be23e58d2febc8337dbfe6a": ("USDT", 6, 1),
                  "0x6bde51212203ae5d592cc5180da2abbd41c922de": ("USDSM", 18, 1)},
}
EXPLORER = {"eth": "https://etherscan.io", "polygon": "https://polygonscan.com", "bsc": "https://bscscan.com",
            "arbitrum": "https://arbiscan.io", "base": "https://basescan.org", "optimism": "https://optimistic.etherscan.io",
            "etherlink": "https://explorer.etherlink.com"}


def rpc(http, chain, method, params):
    r = http.post(RPC[chain], json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=12)
    j = r.json()
    if "error" in j:
        raise RuntimeError(f"{chain} {method}: {j['error'].get('message', j['error'])}")
    return j["result"]


def pad(a):
    return "0x" + a.lower().replace("0x", "").rjust(64, "0")


def unpad(t):
    return "0x" + t[-40:]


def eth_price(http):
    try:
        d = http.json("https://api.geckoterminal.com/api/v2/simple/networks/eth/token_price/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
        return float(list(d["data"]["attributes"]["token_prices"].values())[0])
    except Exception:
        return 0.0


def watched_evm(cfg, state, base_dir="."):
    """chain -> {address: name} for every EVM wallet we watch (pinned, csv, discovered)."""
    pinned, disc = load_wallets(cfg, state, base_dir)
    out = {}
    for w in pinned + disc:
        if w["chain"] in RPC:
            out.setdefault(w["chain"], {})[w["address"].lower()] = (w["name"], w.get("kind", "hot"), float(w.get("min_usd") or 0))
    now = dt.datetime.now(dt.timezone.utc)
    sus = state.setdefault("suspects", {})
    for key in [k for k, v in sus.items() if parse_iso(v["until"]) < now]:
        del sus[key]
    for key, v in sus.items():
        chain, addr = key.split(":", 1)
        if chain in RPC and addr not in out.get(chain, {}):
            out.setdefault(chain, {})[addr] = (v["name"], "suspect", 10000.0)
    return out


def fan_in(state, moves, t, cfg):
    """A new wallet receiving big money from two or more different watched wallets is the
    clearest hack shape (Betmode, Nov 17: two bankrolls, then 20 operator wallets, one receiver)."""
    rec = state.setdefault("receivers", {})
    for k in [k for k, v in rec.items() if t - parse_iso(v["last"]) > dt.timedelta(hours=12)]:
        del rec[k]
    out = []
    min_total = cfg.get("chains", {}).get("fan_in_min_usd", 50_000)
    for chain, src, dst, usd, fresh, name in moves:
        if not fresh:
            continue
        r = rec.setdefault(f"{chain}:{dst}", {"sources": {}, "total": 0, "first": iso(t), "last": iso(t), "sent": False})
        r["sources"][src] = name
        r["total"] += usd
        r["last"] = iso(t)
    for key, r in rec.items():
        if not r["sent"] and len(r["sources"]) >= 2 and r["total"] >= min_total:
            r["sent"] = True
            chain, dst = key.split(":", 1)
            names = ", ".join(sorted(set(r["sources"].values()))[:6])
            out.append(Alert(HIGH, "chain", f"fan:{key}",
                f"POSSIBLE HACK: a brand-new wallet got ${r['total']:,.0f} from {len(r['sources'])} watched casino wallets "
                f"within hours ({names}) on {chain}. {EXPLORER.get(chain, '')}/address/{dst}"))
    return out


def scan_logs(http, chain, frm, to, address, topics, step=2000):
    logs = []
    b = frm
    while b <= to:
        e = min(to, b + step - 1)
        logs += rpc(http, chain, "eth_getLogs", [{"fromBlock": hex(b), "toBlock": hex(e), "address": address, "topics": topics}])
        b = e + 1
    return logs


def deposit_drops(cfg, state, watched, t):
    """Once a day: a hot wallet whose deposits yesterday fell below drop_share of its 7-day average."""
    ccfg = cfg.get("chains", {})
    share, min_avg = ccfg.get("deposit_drop_share", 0.25), ccfg.get("deposit_min_avg_usd", 50000)
    flows = state.setdefault("flows", {})
    out = []
    y = (t - dt.timedelta(days=1)).strftime("%Y-%m-%d")
    prior = [(t - dt.timedelta(days=d)).strftime("%Y-%m-%d") for d in range(2, 9)]
    since = state.setdefault("flow_since", {})
    checked = state.setdefault("flow_checked", {})
    for key, rec in flows.items():
        since.setdefault(key, min(rec, default=f"{t:%Y-%m-%d}"))
        for d in [d for d in rec if d < prior[-1]]:
            del rec[d]  # keep 8 days
        if checked.get(key) == y or since[key] > prior[-1]:
            continue  # already checked today, or less than 8 days of history
        state["flow_checked"][key] = y
        avg = sum(rec.get(d, 0) for d in prior) / 7
        got = rec.get(y, 0)
        if avg >= min_avg and got < avg * share:
            chain, addr = key.split(":", 1)
            name = watched.get(chain, {}).get(addr, ("?",))[0]
            out.append(Alert(HIGH, "chain", f"flow:{key}:{y}",
                f"DEPOSITS COLLAPSED: {name} received ${got:,.0f} on {y}, down {1 - got / avg:.0%} from its 7-day average "
                f"of ${avg:,.0f} a day ({chain}). {EXPLORER.get(chain, '')}/address/{addr}"))
    return out


def check_chains(cfg, state, http, t, budget=None, base_dir="."):
    """Per chain, new blocks since last run:
    - big stablecoin/WETH outflows from any watched wallet; HIGH when the receiver
      is a fresh address or a known mixer/bridge (classic hot wallet hack shape)
    - admin events on watched contracts (owner/role change, upgrade, pause)
    - a watched contract sending out most of a token balance (Betfin LP drain shape)"""
    ccfg = cfg.get("chains", {})
    st = state.setdefault("chainwatch", {})
    alerts = []
    watched = watched_evm(cfg, state, base_dir)
    contracts = {}
    for c in cfg.get("contracts", []):
        contracts.setdefault(c["chain"], []).append(c)
    mixers = {k.lower(): v for k, v in (ccfg.get("mixers") or {}).items()}
    min_usd = ccfg.get("outflow_min_usd", 250000)
    fresh_max = ccfg.get("fresh_max_txs", 3)
    ethp = None
    moves = []
    hist_all = state.setdefault("outhist", {})
    chains = [c for c in RPC if c in watched or c in contracts]

    def one(chain):
        nonlocal ethp
        out = []
        try:
            head = int(rpc(http, chain, "eth_blockNumber", []), 16)
        except Exception as e:
            log(f"chain {chain}: {e}")
            return out
        cur = st.get(chain)
        if cur is None:
            st[chain] = head
            return out
        frm, to = cur + 1, min(head, cur + ccfg.get("max_blocks_per_run", 20000))
        if frm > to:
            return out
        try:
            # 1. outflows from watched wallets, major tokens, wallets OR-ed in chunks
            addrs = list(watched.get(chain, {}))
            toks = list(MAJOR.get(chain, {}))
            for i in range(0, len(addrs), 100):
                if budget and not budget.ok(4):
                    break
                part = addrs[i:i + 100]
                for l in scan_logs(http, chain, frm, to, toks, [TOPIC["Transfer"], [pad(a) for a in part]]):
                    sym, dec, px = MAJOR[chain][l["address"].lower()]
                    if px is None:
                        if ethp is None:
                            ethp = eth_price(http)
                        px = ethp
                    usd = int(l["data"], 16) / 10 ** dec * px
                    src, dst = unpad(l["topics"][1]), unpad(l["topics"][2])
                    name, kind, wmin = watched[chain].get(src, ("?", "hot", 0))
                    floor = wmin if kind in ("parked", "suspect") and wmin else min_usd
                    if usd < min(floor, ccfg.get("look_min_usd", 25000)):
                        continue  # too small to matter for anyone
                    tag, level, fresh, extra = "", LOW, False, ""
                    if dst in mixers:
                        tag, level = f" to {mixers[dst]}", HIGH
                    else:
                        try:
                            n = int(rpc(http, chain, "eth_getTransactionCount", [dst, "latest"]), 16)
                            code = rpc(http, chain, "eth_getCode", [dst, "latest"])
                            if n <= fresh_max and code in ("0x", "0x0"):
                                tag, level, fresh = f" to a FRESH address ({n} txs)", HIGH, True
                        except Exception:
                            pass
                    # how much of the wallet's balance left in one go (hacks empty wallets; withdrawals don't)
                    try:
                        bal = int(rpc(http, chain, "eth_call", [{"to": l["address"], "data": "0x70a08231" + pad(src)[2:]}, "latest"]), 16) / 10 ** dec * px
                        share = usd / (usd + bal) if usd + bal else 0
                        if share >= ccfg.get("share_urgent", 0.4):
                            extra += f" [{share:.0%} OF ITS BALANCE]"
                    except Exception:
                        pass
                    # compared with this wallet's own payments over the last 30 days
                    hk = f"{chain}:{src}"
                    hist = [h for h in hist_all.get(hk, []) if t - parse_iso(h[0]) < dt.timedelta(days=30)]
                    biggest = max((h[1] for h in hist), default=0)
                    if biggest and usd >= 3 * biggest:
                        extra += f" [{usd / biggest:.0f}X ITS BIGGEST IN 30 DAYS]"
                    hist.append((iso(t), usd))
                    hist_all[hk] = sorted(hist, key=lambda h: -h[1])[:20]
                    if usd < floor and "OF ITS BALANCE" not in extra and not ("ITS BIGGEST" in extra and fresh) \
                            and dst not in mixers:
                        continue  # below the size bar and nothing unusual about it
                    if kind == "parked":
                        level = HIGH
                    elif kind == "suspect":
                        level, extra = HIGH, extra + " [SUSPECT WALLET MOVED]"
                    elif not tag and usd >= ccfg.get("big_payout_usd", 2_000_000):
                        tag, level = " (possible big win payout or treasury move)", HIGH
                    moves.append((chain, src, dst, usd, fresh, name))
                    if fresh and usd >= ccfg.get("suspect_min_usd", 100_000):
                        state.setdefault("suspects", {}).setdefault(f"{chain}:{dst}", {
                            "name": f"New wallet that got ${usd:,.0f} from {name}", "until": iso(t + dt.timedelta(hours=72))})
                    out.append(Alert(level, "chain", f"out:{l['transactionHash']}:{l['logIndex']}",
                        f"OUTFLOW: {name} sent ${usd:,.0f} {sym}{tag}{extra} on {chain}. "
                        f"{EXPLORER[chain]}/tx/{l['transactionHash']}"))
            # 1b. deposits into hot wallets: daily USD tally, used to spot a collapse in deposits (Betfin shape)
            hot = [a for a in addrs if watched[chain][a][1] not in ("parked", "suspect")]
            flows = state.setdefault("flows", {})
            day = f"{t:%Y-%m-%d}"
            for i in range(0, len(hot), 100):
                if budget and not budget.ok(4):
                    break
                part = hot[i:i + 100]
                for l in scan_logs(http, chain, frm, to, toks, [TOPIC["Transfer"], None, [pad(a) for a in part]]):
                    if len(l.get("topics", [])) < 3:
                        continue
                    dst = unpad(l["topics"][2])
                    if dst not in watched[chain]:
                        continue
                    sym, dec, px = MAJOR[chain][l["address"].lower()]
                    if px is None:
                        if ethp is None:
                            ethp = eth_price(http)
                        px = ethp
                    rec = flows.setdefault(f"{chain}:{dst}", {})
                    rec[day] = rec.get(day, 0) + int(l["data"], 16) / 10 ** dec * px
            # 2 + 3. watched contracts
            for c in contracts.get(chain, []):
                if budget and not budget.ok(4):
                    break
                a = c["address"].lower()
                for l in scan_logs(http, chain, frm, to, a, [list(ADMIN_TOPICS)]):
                    ev = ADMIN_TOPICS.get(l["topics"][0], "admin event")
                    out.append(Alert(HIGH, "chain", f"adm:{l['transactionHash']}:{l['logIndex']}",
                        f"CONTRACT {ev.upper()}: {c['name']} ({chain} {a[:10]}…) {EXPLORER[chain]}/tx/{l['transactionHash']}"))
                toks = list({x.lower() for x in c.get("tokens", [])} | set(MAJOR.get(chain, {})))
                for l in scan_logs(http, chain, frm, to, toks, [TOPIC["Transfer"], pad(a)]):
                    amt = int(l["data"], 16)
                    try:
                        bal = int(rpc(http, chain, "eth_call", [{"to": l["address"], "data": "0x70a08231" + pad(a)[2:]}, "latest"]), 16)
                    except Exception:
                        continue
                    share = amt / (amt + bal) if amt + bal else 0
                    if share >= c.get("drain_share", 0.5) and amt > 0:
                        sym = MAJOR.get(chain, {}).get(l["address"].lower(), (l["address"][:10],))[0]
                        out.append(Alert(HIGH, "chain", f"drain:{l['transactionHash']}:{l['logIndex']}",
                            f"CONTRACT DRAINED: {c['name']} sent {share:.0%} of its {sym} balance to {unpad(l['topics'][2])} "
                            f"on {chain}. {EXPLORER[chain]}/tx/{l['transactionHash']}"))
            st[chain] = to
        except Exception as e:
            log(f"chain {chain}: {e}")  # cursor not moved: retried next run
        return out

    with ThreadPoolExecutor(len(chains) or 1) as ex:
        for got in ex.map(one, chains):
            alerts += got
    alerts += fan_in(state, moves, t, cfg)
    alerts += deposit_drops(cfg, state, watched, t)
    return alerts


# ---------------------------------------------------------------- on-chain messages
def decode_message(raw):
    """Readable text in a transaction's input (how hack negotiations happen on chain)."""
    if not raw or len(raw) < 26:
        return None
    try:
        b = bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
    except ValueError:
        return None
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in s)
    if printable / max(len(s), 1) < 0.95 or " " not in s or len(s.strip()) < 12:
        return None
    return re.sub(r"\s+", " ", s).strip()


MSG_RE = re.compile(r"hack|exploit|return|refund|bounty|reward|white ?hat|negotiat|contact|funds|stolen|drain|%|email|telegram|"
                    r"law enforcement|police|fbi|lawsuit|deal|keep|ransom|seize", re.I)


def check_messages(cfg, state, http, t, budget=None, base_dir="."):
    """Readable messages sent to or from watched wallets (pinned + rotation)."""
    st = state.setdefault("messages", {"seen": []})
    seen = set(st["seen"])
    pinned, disc = load_wallets(cfg, state, base_dir)
    batch = [w for w in pinned if w["chain"] in BLOCKSCOUT] + \
        rotate([w for w in disc if w["chain"] in BLOCKSCOUT], state.setdefault("cursors", {}), "messages", cfg.get("messages_per_run", 40))
    first = not seen
    alerts = []
    spam_seen = set()

    def one(w):
        if budget and not budget.ok(3):
            return w, []
        try:
            return w, http.json(f"{BLOCKSCOUT[w['chain']]}/api/v2/addresses/{w['address']}/transactions").get("items") or []
        except Exception as e:
            log(f"messages {w['name']}: {e}")
            return w, []

    with ThreadPoolExecutor(8) as ex:
        for w, items in ex.map(one, batch):
            for x in items[:50]:
                h = x.get("hash")
                if not h or h in seen:
                    continue
                seen.add(h)
                msg = decode_message(x.get("raw_input") or "")
                if not msg or first:
                    continue
                frm = ((x.get("from") or {}).get("hash") or "")
                direction = "from" if frm.lower() == w["address"].lower() else "to"
                letters = sum(ch.isalpha() for ch in msg)
                if letters < 12 or letters < len(msg) * 0.5:
                    continue  # symbol spam ("-----", address poisoning)
                if w.get("kind") not in ("parked", "suspect") and direction == "to" and not MSG_RE.search(msg):
                    continue  # strangers writing to a big casino wallet: only hack-related words count
                if msg in spam_seen:
                    continue
                spam_seen.add(msg)
                alerts.append(Alert(HIGH if w.get("kind") == "parked" else LOW, "message", f"msg:{h}",
                    f"ON-CHAIN MESSAGE {direction} {w['name']} ({w['chain']}): \"{msg[:300]}\" "
                    f"{BLOCKSCOUT[w['chain']]}/tx/{h}"))
    st["seen"] = list(seen)[-20000:]
    return alerts


# ---------------------------------------------------------------- hacks database + freeze proposals
def check_hacks(cfg, state, http, t, budget=None):
    """New entries in DefiLlama's hack database. Gambling targets are HIGH."""
    hcfg = cfg.get("hacks", {})
    if not due(state.setdefault("jobs", {}), "hacks", t, hcfg.get("every_minutes", 60)):
        return []
    st = state.setdefault("hacks", {"seen": []})
    try:
        rows = http.json("https://api.llama.fi/hacks", timeout=20)
    except Exception as e:
        log(f"hacks: {e}")
        return []
    seen = set(st["seen"])
    first = not seen
    hot = re.compile(hcfg.get("high_pattern", r"casino|gambl|bet|dice|lotter|bankroll|sportsbook|poker|stake|game"), re.I)
    alerts = []
    for r in rows:
        k = f"{r.get('name')}:{r.get('date')}"
        if k in seen:
            continue
        seen.add(k)
        if first:
            continue
        text = " ".join(str(r.get(x) or "") for x in ("name", "targetType", "description", "classification"))
        level = HIGH if hot.search(text) or (r.get("amount") or 0) >= hcfg.get("high_usd", 20_000_000) else LOW
        day = dt.datetime.fromtimestamp(int(r.get("date") or 0), dt.timezone.utc).strftime("%Y-%m-%d")
        alerts.append(Alert(level, "hacks", f"hk:{k}",
            f"HACK LOGGED: {r.get('name')} ({r.get('targetType')}) ${float(r.get('amount') or 0):,.0f} on "
            f"{', '.join(r.get('chain') or [])}, {day}. {r.get('technique') or r.get('classification') or ''} {r.get('source') or ''}".strip()))
    st["seen"] = list(seen)
    return alerts


def check_freeze_proposals(cfg, state, http, t, budget=None):
    """Tether's multisig proposes a freeze or seizure before it executes."""
    st = state.setdefault("proposals", {"seen": []})
    seen = set(st["seen"])
    first = not seen
    alerts = []
    for chain in cfg.get("freeze_rules", {}).get("proposal_chains", ["tron", "ethereum"]):
        try:
            items = http.json(f"https://stablescan.achivx.com/v1/freezes/proposals?chain={chain}&status=pending&limit=50").get("items") or []
        except Exception as e:
            log(f"proposals {chain}: {e}")
            continue
        for p in items:
            k = f"{chain}:{p.get('submitted_at')}:{p.get('action')}:{p.get('selector')}"
            if k in seen:
                continue
            seen.add(k)
            if first:
                continue
            act = p.get("action") or p.get("selector")
            level = HIGH if act == "seize" else LOW
            alerts.append(Alert(level, "freeze", f"prop:{k}",
                f"PENDING {p.get('token')} {str(act).upper()} on {chain}: multisig proposal submitted {p.get('submitted_at')}, "
                f"{p.get('confirmations')}/{p.get('required')} signatures (address hidden until it executes)."))
    st["seen"] = list(seen)[-3000:]
    return alerts


# ---------------------------------------------------------------- outlets (RSS)
FEED_LINK_RE = re.compile(r'<link[^>]+type=["\']application/(?:rss|atom)\+xml["\'][^>]*>', re.I)


def load_outlets(cfg, base_dir=".", state=None):
    ocfg = cfg.get("outlets", {})
    files = ocfg.get("files") or [ocfg.get("file", "outlets.txt")]
    out, seen = [], set()
    for fn in files:
        path = os.path.join(base_dir, fn)
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8"):
            line = line.split("#", 1)[0].strip() if not line.lstrip().startswith("http") else line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if parts[0] not in seen:
                seen.add(parts[0])
                out.append({"src": parts[0], "tags": parts[1:]})
    known = {norm_domain(o["src"]) for o in out}
    for dom, cc in sorted((state or {}).get("learned_outlets", {}).items()):
        if dom not in known:
            out.append({"src": dom, "tags": [f"cc:{cc}", "learned"]})
    return out


def discover_feed(http, src):
    if src.startswith("http") and re.search(r"(rss|feed|atom|\.xml)", src, re.I):
        return src
    home = src if src.startswith("http") else f"https://{src}"
    try:
        r = http.snippet(home, limit=200000)
        for tag in FEED_LINK_RE.findall(getattr(r, "_snip", "")):
            m = re.search(r'href=["\']([^"\']+)["\']', tag)
            if m:
                return urllib.parse.urljoin(r.url, html.unescape(m.group(1)))
    except Exception:
        pass
    for p in ("/feed", "/rss", "/feed/", "/rss.xml", "/feed.xml", "/index.xml", "/atom.xml"):
        try:
            r = http.snippet(home.rstrip("/") + p, limit=3000)
            s = getattr(r, "_snip", "")
            if r.status_code == 200 and ("<rss" in s or "<feed" in s or "<rdf" in s):
                return r.url
        except Exception:
            continue
    return None


def parse_feed(text):
    items = []
    for m in re.finditer(r"<(item|entry)\b.*?</\1>", text, re.S | re.I):
        it = m.group(0)

        def g(tag):
            mm = re.search(rf"<{tag}\b[^>]*>(.*?)</{tag}>", it, re.S | re.I)
            v = mm.group(1) if mm else ""
            v = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", v, flags=re.S)
            return html.unescape(re.sub(r"<[^>]+>", " ", v)).strip()
        link = g("link")
        if not link:
            mm = re.search(r'<link[^>]+href=["\']([^"\']+)', it)
            link = mm.group(1) if mm else ""
        items.append({"title": re.sub(r"\s+", " ", g("title")), "link": link.strip(),
                      "date": g("pubDate") or g("updated") or g("published") or g("dc:date"),
                      "summary": re.sub(r"\s+", " ", g("description") or g("summary"))[:400]})
    return items


AMBIGUOUS_BRANDS = {"stake", "shuffle", "duel", "thrill", "lucky", "moon", "shock", "degen", "flush", "yeet", "gamba", "toshi",
                    "limitless", "myriad", "ignition", "spartans", "easygo", "dicey", "bluff", "chancer", "winz", "yolo", "dope",
                    "lottery", "casino", "gambling", "sportsbook", "kick", "oshi", "weiss", "goated", "vave", "rugs", "acebet"}


TIPS_RE = re.compile(r"\b(odds|picks?|prediction|predictions|best bets?|betting tips?|tips|preview|parlay|props?|"
                     r"promo code|bonus code|free bets?|sign[- ]?up offer|how to watch|live stream|vs\.?|v\.)\b", re.I)


def outlet_terms(cfg):
    brands = {b.lower() for b in cfg.get("news", {}).get("brands", []) + cfg.get("forum", {}).get("brands", [])
              + cfg.get("wallet_brands", []) if len(b) >= 4}
    words = set(cfg.get("outlets", {}).get("trigger_words", []))
    for ed in cfg.get("news", {}).get("editions", []):
        words |= {w.lower() for w in ed.get("words", [])}
    brand_re = re.compile(r"(?<![\w.])(" + "|".join(sorted((re.escape(b) for b in brands), key=len, reverse=True)) + r")(?![\w])", re.I) if brands else re.compile(r"(?!x)x")
    word_re = re.compile("|".join(sorted((re.escape(w) for w in words if w), key=len, reverse=True)), re.I) if any(words) else re.compile(r"(?!x)x")
    topic_re = re.compile(cfg.get("outlets", {}).get("topic_pattern",
        r"casino|gambl|betting|sportsbook|bookmaker|bankroll|igaming|prediction market|sweepstakes|kasino|kasyno|casin[oò]|apuesta|aposta|bahis|cassino|kaszin|hazard|พนัน|カジノ|카지노|赌|賭|казино|ставк"), re.I)
    return brand_re, word_re, topic_re


def check_outlets(cfg, state, http, t, budget=None, base_dir="."):
    """Hundreds of outlets' own RSS feeds, read in rotation. Alerts when a casino
    brand appears with a trigger word; security/crypto outlets also alert on any
    gambling story with a trigger word."""
    ocfg = cfg.get("outlets", {})
    outlets = load_outlets(cfg, base_dir, state)
    if not outlets:
        return []
    st = state.setdefault("outlets", {"feeds": {}, "seen": []})
    feeds = st["feeds"]
    seen = set(st["seen"])
    first = not seen
    brand_re, word_re, topic_re = outlet_terms(cfg)
    cur = state.setdefault("cursors", {})
    # discover feeds for outlets not yet resolved (or retry failures weekly)
    todo = [o for o in outlets if o["src"] not in feeds or
            (feeds[o["src"]] is None and t - parse_iso(st.get("disc_at", {}).get(o["src"], "2000-01-01T00:00:00Z")) > dt.timedelta(days=7))]
    disc_batch = todo[:ocfg.get("discover_per_run", 30)]

    def disc(o):
        if budget and not budget.ok(TIMEOUT + 2):
            return o, "skip"
        return o, discover_feed(http, o["src"])

    with ThreadPoolExecutor(16) as ex:
        for o, f in ex.map(disc, disc_batch):
            if f == "skip":
                continue
            feeds[o["src"]] = f
            st.setdefault("disc_at", {})[o["src"]] = iso(t)
    live = [o for o in outlets if feeds.get(o["src"])]
    batch = rotate(live, cur, "outlets", ocfg.get("feeds_per_run", 150))

    def fetch(o):
        if budget and not budget.ok(TIMEOUT + 2):
            return o, []
        try:
            r = http.snippet(feeds[o["src"]], limit=400000)
            return o, parse_feed(getattr(r, "_snip", ""))
        except Exception as e:
            return o, []

    alerts = []
    with ThreadPoolExecutor(ocfg.get("threads", 32)) as ex:
        for o, items in ex.map(fetch, batch):
            special = any(x in o["tags"] for x in ("security", "crypto", "igaming"))
            for it in items[:40]:
                key = hashlib.sha1((it["link"] or it["title"]).encode()).hexdigest()[:16]
                if key in seen:
                    continue
                seen.add(key)
                if first:
                    continue
                try:
                    if it["date"] and t - parsedate_to_datetime(it["date"]) > dt.timedelta(hours=ocfg.get("max_age_hours", 48)):
                        continue
                except Exception:
                    pass
                text = f"{it['title']} {it['summary']}"
                b = brand_re.search(text)
                weak = b is not None and b.group(0).lower() in AMBIGUOUS_BRANDS and not topic_re.search(text)
                w = word_re.search(text)
                if b and w and not weak:
                    level = HIGH
                elif special and topic_re.search(text) and w:
                    level = HIGH if "security" in o["tags"] else LOW
                elif b:
                    level = HIGH if any(x in o["tags"] for x in ("court", "regulator")) else LOW
                elif topic_re.search(it["title"]) and not TIPS_RE.search(it["title"]):
                    level = LOW  # any gambling story, even about a casino we don't know yet
                else:
                    continue
                src = o.get("src") or ""
                src = norm_domain(src) if src.startswith("http") or "/" in src else src
                src = src or norm_domain(it["link"] or "") or "news"
                alerts.append(Alert(level, "outlets", f"o:{key}", f"[{src}] {it['title'][:200]} {it['link']}"))
    st["seen"] = list(seen)[-30000:]
    state["outlets_meta"] = {"outlets": len(outlets), "feeds": len(live)}
    return alerts


# ---------------------------------------------------------------- telegram channels
HACK_RE = re.compile(r"hack|exploit|drain|stolen|attack|compromis|breach|suspicious|rug|frozen|laundr|tornado", re.I)
TG_MSG_RE = re.compile(r'data-post="([^"]+)".*?<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', re.S)


def check_telegram(cfg, state, http, t, budget=None):
    """Public Telegram channels (t.me/s/<name> web preview): casino announcement
    channels and hack/security channels."""
    tcfg = cfg.get("telegram_channels", {})
    chans = tcfg.get("list", [])
    if not chans:
        return []
    st = state.setdefault("tg", {"seen": []})
    seen = set(st["seen"])
    first = not seen
    brand_re, word_re, topic_re = outlet_terms(cfg)
    batch = rotate(chans, state.setdefault("cursors", {}), "tg", tcfg.get("per_run", 40))

    def one(c):
        name = c if isinstance(c, str) else c["name"]
        if budget and not budget.ok(TIMEOUT + 2):
            return c, ""
        try:
            return c, http.get(f"https://t.me/s/{name}").text
        except Exception as e:
            log(f"telegram: {e}")
            return c, ""

    alerts = []
    with ThreadPoolExecutor(8) as ex:
        for c, h in ex.map(one, batch):
            kind = "" if isinstance(c, str) else c.get("kind", "")
            for post, body in TG_MSG_RE.findall(h):
                if post in seen:
                    continue
                seen.add(post)
                if first:
                    continue
                text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", body))).strip()
                b, w = brand_re.search(text), word_re.search(text)
                if kind == "casino" and (w or MAINT_RE.search(text) or NOTICE_RE.search(text)):
                    level = HIGH
                elif b and w:
                    level = HIGH
                elif kind == "security" and topic_re.search(text):
                    level = HIGH
                elif b:
                    level = LOW
                elif kind == "security" and HACK_RE.search(text):
                    level = LOW  # every hack a tracker posts; a casino may not be named yet
                else:
                    continue
                marker = "casino channel " if kind == "casino" and level == HIGH else ""
                alerts.append(Alert(level, "telegram", f"tg:{post}", f"[{marker}t.me/{post}] {text[:280]}"))
    st["seen"] = list(seen)[-20000:]
    return alerts


# ---------------------------------------------------------------- health
def record_health(state, name, ok, t):
    h = state.setdefault("health", {})
    rec = h.setdefault(name, {})
    if ok:
        rec["ok"] = iso(t)
    else:
        rec["fail"] = iso(t)


def health_lines(state, t):
    out = []
    for name, rec in sorted(state.get("health", {}).items()):
        ok = rec.get("ok")
        if not ok or t - parse_iso(ok) > dt.timedelta(hours=6):
            out.append(f"{name}: no successful run since {ok or 'start'}")
    return out


# ---------------------------------------------------------------- delivery
ORDER = ["chain", "message", "wallet", "sites", "freeze", "hacks", "token", "telegram", "register", "outlets", "news", "forum", "pages", "wallets"]
URGENT = "URGENT"
STRONG_EN = (r"hack|exploit|drain|stolen|steal|breach|attacker|arrest|raid|charged|charges?|indicted|detain|seiz|frozen|freez|"
             r"insolven|bankrupt|exit scam|rug ?pull|shut(s|ting)? down|withdrawals? (paused|suspended|halted|frozen)")



REL_RE = re.compile(r"casino|gambl|betting|bookmaker|sportsbook|igaming|i-gaming|slot machine|online slots|poker|lotter|"
                    r"prediction market|sweepstakes|wager|bet365|betway|draftkings|fanduel|betmgm|kalshi|polymarket|"
                    r"crypto casino|gaming licen|gaming commission|gaming authority|curacao|curaçao|anjouan|ukgc|"
                    r"responsible gaming|match.fixing|spot.fixing|illegal betting|online gaming", re.I)
CRYPTO_RE = re.compile(r"crypto|bitcoin|ethereum|solana|tron|usdt|usdc|stablecoin|token|defi|wallet|exchange|bridge|protocol|"
                       r"blockchain|web3|on-chain|onchain", re.I)
SPORT_RE = re.compile(r"\b(vs\.?|match|league|season|coach|striker|goal|fans|player|derby|clásico|classico|semifinal|final|"
                      r"tournament|playoff|kick-?off|lineup|transfer window|preview|highlights)\b", re.I)


NON_LATIN = re.compile(r"[\u0400-\u04FF\u0590-\u06FF\u0900-\u097F\u0E00-\u0E7F\u3040-\u30FF\u3400-\u9FFF\uAC00-\uD7AF]")
SPORT_EXTRA = re.compile(r"\b(libertadores|home runs?|innings|touchdown|quarterback|standings|reclassification|relegation|"
                         r"premier league|la liga|serie a|bundesliga|champions league|copa|world cup|grand prix|nba|nfl|mlb|nhl|"
                         r"ufc|duel|matchday|scored|halftime|overtime|hat-?trick|squad|olympic)\b", re.I)
BUSINESS_RE = re.compile(r"casino|gambl|igaming|licen|regulat|illegal|crypto|hack|police|arrest|raid|\bfined?\b|\bbans?\b|banned|"
                         r"court|lawsuit|sued|\btax|sponsor|acqui|merger|\bceo\b|layoff|fixing|integrity|suspicious bet|prediction market", re.I)
GAMBLING_HACK_RE = re.compile(r"casino|gambl|\bbet|dice|lotter|bankroll|sportsbook|poker|\bstake\b|prediction|kalshi|polymarket|"
                              r"igaming|slots?\b|wager", re.I)


PROMO_RE = re.compile(r"\b(best|top \d+|top-rated|recommend\w*|review|reviews|bonus(es)?|free spins|no deposit|promo|"
                      r"guide|how to|ranked|ranking|list of|sign.?up|welcome offer|vip program)\b", re.I)


def classify(cfg, it):
    """After translation: is it clearly about our beat (update), or only maybe (report only)?"""
    if it["check"] == "wallets":
        return "minor"  # housekeeping: shown in the report
    if it["check"] == "hacks":
        # the hack feeds list every DeFi hack; only gambling ones belong in the update
        return "major" if (GAMBLING_HACK_RE.search(it["text"]) or outlet_terms(cfg)[0].search(it["text"])) else "minor"
    if it["check"] not in ("news", "outlets", "telegram", "forum"):
        return "major"
    if it.get("foreign"):
        return "minor"
    head = news_parts(it["text"])[0] if it["check"] in ("news", "outlets") else URL_RE.sub("", it["text"])
    if NON_LATIN.search(head):
        return "minor"  # translation failed: never shown untranslated
    if (SPORT_RE.search(head) or SPORT_EXTRA.search(head)) and not BUSINESS_RE.search(head):
        return "minor"  # match reports, standings and tips, even when a betting brand sponsors the league
    brand_re = outlet_terms(cfg)[0]
    b = brand_re.search(head)
    strong_brand = b is not None and b.group(0).lower() not in AMBIGUOUS_BRANDS
    if it["check"] == "forum" or (it["check"] == "telegram" and "[casino channel" in it["text"]):
        return "major" if (strong_brand or REL_RE.search(head) or TROUBLE_RE.search(head)) else "minor"
    if strong_brand or REL_RE.search(head):
        if SPORT_RE.search(head) and not (strong_brand or re.search(r"casino|gambl|igaming|licen|regulat|illegal|crypto", head, re.I)):
            return "minor"  # match reports and tips that mention betting in passing
        if TIPS_RE.search(head) and not strong_brand:
            return "minor"
        if PROMO_RE.search(head) and not HACK_RE.search(head) and not re.search(r"police|raid|arrest|charged|court|sued|fined|regulat|ban", head, re.I):
            return "minor"  # paid listicles and casino promos
        return "major"
    if HACK_RE.search(head) and CRYPTO_RE.search(head):
        return "major"  # crypto hacks: a casino is often named only later
    return "minor"


PREDICTION_BRANDS = {"kalshi", "polymarket", "limitless", "myriad", "novig", "underdog", "prizepicks", "sleeper", "fliff"}
HACK_STRONG = re.compile(r"hack|exploit|drain|stolen|breach|insolven|bankrupt|exit scam|withdrawals? (paused|suspended|halted|frozen)", re.I)


def is_urgent(cfg, a):
    """The one place that decides what gets a 🚨. Rules are listed in the README."""
    k, txt = a.key, a.text
    if a.level == URGENT:
        return True
    if k.startswith(("drain:", "adm:", "lic:", "cluster:", "fzl:", "tok:", "flow:", "fan:")):
        return True
    if k.startswith("w:"):
        return True  # parked money moved, or hot wallet / bankroll drained
    if k.startswith("out:"):
        if "possible big win" in txt:
            return False  # casino paying a winner is news, not an emergency
        mixers = [m for m in (cfg.get("chains", {}).get("mixers") or {}).values() if m]
        if "PARKED" in txt or "SUSPECT WALLET MOVED" in txt or any(m in txt for m in mixers):
            return True
        usd = re.search(r"sent \$([\d,]+)", txt)
        usd = float(usd.group(1).replace(",", "")) if usd else 0
        if "OF ITS BALANCE]" in txt and ("FRESH" in txt or usd >= cfg.get("chains", {}).get("share_urgent_min_usd", 250_000)):
            return True  # emptied a big part of the wallet in one payment (small hot wallets sweep all the time)
        if "FRESH" in txt and "ITS BIGGEST IN 30 DAYS]" in txt:
            return True  # far bigger than this wallet's normal payments, to a new wallet
        return "FRESH" in txt and usd >= cfg.get("chains", {}).get("fresh_urgent_usd", 1_000_000)
    if k.startswith("msg:"):
        return a.level == HIGH  # message to or from a parked/attacker wallet
    if k.startswith("site:"):
        return " is seized:" in txt or (a.level == HIGH and re.search(r" is (down|maintenance|notice|parked):", txt) is not None)
    if k.startswith("hk:"):
        return a.level == HIGH and re.search(cfg.get("hacks", {}).get("high_pattern",
            r"casino|gambl|bet|dice|lotter|bankroll|sportsbook|poker|stake"), txt, re.I) is not None
    if k.startswith("reg:") and (":gone:" in k or ":status:" in k):
        return a.level == HIGH
    if k.startswith("bt:"):
        return "scam threads on" in txt
    if k.startswith("tg:"):
        return "[casino channel " in txt
    if k.startswith(("n:", "o:")):
        brand_re, _, _ = outlet_terms(cfg)
        title = news_parts(txt)[0]
        b = brand_re.search(title)
        if not b or b.group(0).lower() in AMBIGUOUS_BRANDS:
            return False
        if b.group(0).lower() in PREDICTION_BRANDS:
            return bool(HACK_STRONG.search(title))  # Kalshi/Polymarket court news is news, not an emergency
        return bool(re.search(STRONG_EN, title, re.I))
    return False


CATS = {  # check -> (icon, label, hashtag, topic)
    "chain": ("⛓", "On-chain", "onchain", "onchain"), "message": ("✉️", "On-chain message", "message", "onchain"),
    "wallet": ("👛", "Wallet", "wallet", "onchain"), "wallets": ("👛", "Wallets", "wallet", "onchain"),
    "freeze": ("🧊", "Freeze", "freeze", "onchain"), "hacks": ("💥", "Hack", "hack", "onchain"),
    "token": ("📉", "Token", "token", "onchain"), "sites": ("🌐", "Sites", "site", "sites"),
    "register": ("📜", "Licences", "licence", "sites"), "pages": ("🏛", "Regulators", "regulator", "sites"),
    "outlets": ("📰", "News", "news", "news"), "news": ("📰", "News", "news", "news"),
    "forum": ("💬", "Forums", "forum", "forums"), "telegram": ("💬", "Telegram", "telegram", "forums"),
}
GROUP = {"outlets": "news", "news": "news", "telegram": "forum", "wallets": "wallet"}
URL_RE = re.compile(r"https?://[^\s\]\)>\"']+")
STOP = set("the and for with from that this into over after says said will have been their about more than news".split())


def esc(s):
    return html.escape(s, quote=False)


def brand_tags(cfg, text):
    tl = text.lower()
    out = []
    for b in cfg.get("forum", {}).get("brands", []):
        if len(b) >= 4 and re.search(r"(?<![a-z0-9])" + re.escape(b.lower()) + r"(?![a-z0-9])", tl):
            tag = re.sub(r"[^a-z0-9]", "", b.lower())
            if tag and tag not in out:
                out.append(tag)
    return out[:3]


CHAIN_NAMES = {"solana": "Solana", "eth": "Ethereum", "polygon": "Polygon", "bsc": "BNB Chain", "arbitrum": "Arbitrum", "base": "Base",
               "optimism": "Optimism", "etherlink": "Etherlink", "gnosis": "Gnosis", "tron": "Tron"}


def money(m):
    v = float(m.group(1).replace(",", ""))
    return "$" + (f"{v / 1e6:.1f}M" if v >= 1e6 else f"{v / 1e3:.0f}K" if v >= 1e4 else f"{v:,.0f}")


def plain(text):
    """Turn the radar's internal wording into a sentence a person reads at a glance."""
    t = text
    t = re.sub(r"^OUTFLOW:\s*", "", t)
    t = re.sub(r"^CONTRACT DRAINED:\s*", "Contract drained: ", t)
    t = re.sub(r"to a FRESH address \(\d+ txs?\)", "to a brand-new wallet", t)
    t = re.sub(r"\s*\(possible big win payout or treasury move\)", " (big win or treasury move?)", t)
    t = re.sub(r" \[(\d+)% OF ITS BALANCE\]", r", \1% of what the wallet held", t)
    t = re.sub(r" \[(\d+)X ITS BIGGEST IN 30 DAYS\]", r", \1x its biggest payment this month", t)
    t = t.replace(" [SUSPECT WALLET MOVED]", ", money on the move again")
    t = re.sub(r"^POSSIBLE HACK:\s*", "Possible hack: ", t)
    t = re.sub(r"^(\S+\.\w+) is maintenance: ", r"\1 is in maintenance: ", t)
    t = re.sub(r"^(\S+\.\w+) is (down|in maintenance|seized|parked|blocked): (?:page says: )?(.+)$", r"\1 is \2 (\3)", t)
    t = re.sub(r"\$([\d,]{5,})", money, t)
    t = re.sub(r" on (eth|polygon|bsc|arbitrum|base|optimism|etherlink|gnosis|tron|solana)\b", lambda m: " (" + CHAIN_NAMES[m.group(1)] + ")", t)
    t = re.sub(r"^\[\s*([A-Z]{2})\]\s*", r"\1: ", t)
    t = re.sub(r"^Wallet discovery: (\d+) new labelled casino wallets, (\d+) watched in total",
               r"Now watching \2 casino wallets found on block explorers (\1 new)", t)
    return t


def split_text(text):
    links = URL_RE.findall(text)
    body = plain(URL_RE.sub("", text).strip()).rstrip(".").strip()
    m = re.match(r"^([A-Z0-9 /&'().-]{6,60}):\s*(.*)$", body, re.S)
    if m:
        return m.group(1).strip().capitalize(), m.group(2).strip(), links
    return body, "", links


def short_line(a, limit=150):
    head, rest, links = split_text(a["text"])
    line = head if not rest else f"{head}: {rest}"
    if a.get("line"):
        line = a["line"]
    line = re.sub(r"\s+", " ", line)
    if len(line) > limit:
        line = line[:limit - 1].rsplit(" ", 1)[0] + "…"
    return line, (links[0] if links else "")


def story_sig(a):
    """Signature used to merge the same story across sources and runs."""
    check = GROUP.get(a["check"], a["check"])
    if check == "news":
        title = re.sub(r"^\[[^\]]*\]\s*", "", URL_RE.sub("", a["text"]).lower())
        title = re.sub(r"\s[-|–]\s[^-|–]{2,40}$", "", title)  # drop " - Outlet name"
        words = {w for w in re.findall(r"[^\W\d_]{4,}", title) if w not in STOP}
        return check, words
    return check, {a["key"]}


def same_story(s1, s2):
    if s1[0] != s2[0]:
        return False
    a, b = s1[1], s2[1]
    if not a or not b:
        return False
    return len(a & b) / len(a | b) >= 0.45 if s1[0] == "news" else a == b


def add_to_stories(state, items, t, keep_hours=48):
    """Returns the items that start a new story; others are counted as extra sources."""
    stories = [x for x in state.get("stories", []) if t - parse_iso(x["last"]) < dt.timedelta(hours=keep_hours)]
    new = []
    for it in items:
        sig = story_sig(it)
        match = next((s for s in stories if same_story((s["check"], set(s["sig"])), sig)), None)
        if match:
            match["sources"] += 1
            match["last"] = iso(t)
            if match["first"] != iso(t):
                match["bumped"] = iso(t)  # an older story got news this run
            match["urgent"] = match["urgent"] or it["urgent"]
            src = news_parts(it["text"])[1].split(" · ")[0] if sig[0] == "news" else ""
            if src and src not in match.setdefault("also", []):
                match["also"].append(src)
            continue
        st = {"check": sig[0], "sig": sorted(sig[1]), "text": it["text"], "key": it["key"], "urgent": it["urgent"], "minor": it.get("minor", False),
              "level": it["level"], "first": iso(t), "last": iso(t), "sources": 1}
        for f in ("line", "ai_keep", "ai_score", "why", "also"):
            if it.get(f) is not None:
                st[f] = it[f]
        stories.append(st)
        new.append(st)
    state["stories"] = stories[-6000:]
    return new


def format_urgent(cfg, s, t):
    """One urgent story, on its own, with sound."""
    icon, label = CATS.get(s["check"], ("•", s["check"]))[:2]
    head, meta, link = disp(s, 200)
    lt = t.astimezone(local_tz(cfg))
    lines = [f"🚨 <b>URGENT</b> · {icon} {esc(label)}", "", f"<b>{esc(head)}</b>"]
    if not s.get("line") and GROUP.get(s["check"], s["check"]) not in ("news", "forum"):
        rest = split_text(s["text"])[1]
        if rest:
            lines.append(esc(rest[:400]))
    if s.get("why"):
        lines.append(f"Why it matters: {esc(s['why'])}")
    lines.append(f"<i>{lt:%H:%M}" + (f" · {esc(meta)}" if meta else "") + "</i>")
    if link:
        lines.append(f'🔗 <a href="{esc(link)}">{esc(re.sub(r"^https?://(www[.])?", "", link)[:50])}</a>')
    return "\n".join(lines)


def merge_same_wallet(stories):
    """Several outflows from one wallet in one message become one line with a total."""
    out, by = [], {}
    for s in stories:
        m = re.match(r"^OUTFLOW: (.+?) sent \$([\d,]+) (\S+)", s["text"]) if s["check"] == "chain" else None
        if not m:
            out.append(s)
            continue
        by.setdefault(m.group(1), []).append((s, float(m.group(2).replace(",", ""))))
    for name, items in by.items():
        if len(items) == 1:
            out.append(items[0][0])
            continue
        total = sum(v for _, v in items)
        first = items[0][0]
        chain = re.search(r" on (\w+)\.", first["text"])
        link = URL_RE.findall(first["text"])
        merged = dict(first)
        merged["text"] = (f"OUTFLOW: {name} sent ${total:,.0f} in {len(items)} transfers"
                          + (f" on {chain.group(1)}." if chain else ".") + (" " + link[0] if link else ""))
        merged["urgent"] = any(x["urgent"] for x, _ in items)
        out.append(merged)
    return out


LANG_NAMES = {"es": "Spanish", "pt": "Portuguese", "it": "Italian", "de": "German", "fr": "French", "nl": "Dutch",
              "cs": "Czech", "sk": "Slovak", "pl": "Polish", "tr": "Turkish", "ru": "Russian", "uk": "Ukrainian",
              "th": "Thai", "ja": "Japanese", "ko": "Korean", "zh-CN": "Chinese", "zh-TW": "Chinese", "zh": "Chinese",
              "vi": "Vietnamese", "id": "Indonesian", "ms": "Malay", "tl": "Filipino", "hi": "Hindi", "ar": "Arabic",
              "he": "Hebrew", "sv": "Swedish", "no": "Norwegian", "da": "Danish", "fi": "Finnish", "el": "Greek",
              "ro": "Romanian", "hu": "Hungarian", "bg": "Bulgarian", "hr": "Croatian", "sr": "Serbian", "lt": "Lithuanian",
              "lv": "Latvian", "et": "Estonian", "sl": "Slovenian", "fa": "Persian", "ka": "Georgian"}
EN_HINT = re.compile(r"\b(the|of|and|to|in|for|on|with|is|after|over|says|from)\b", re.I)


def translate_en(http, text, cache):
    """Free Google Translate endpoints (two, with a retry); returns (english, language name),
    (text, None) when it is already English, or (text, "?") when translation failed."""
    if text in cache:
        return tuple(cache[text])
    q = urllib.parse.quote(text[:400])
    urls = [f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=en&dt=t&q={q}",
            f"https://clients5.google.com/translate_a/t?client=dict-chrome-ex&sl=auto&tl=en&q={q}"]
    res = None
    for attempt in range(3):
        u = urls[attempt % 2]
        try:
            j = http.json(u)
            if "translate_a/single" in u:
                en = "".join(seg[0] for seg in j[0] if seg and seg[0]).strip()
                lang = j[2] if len(j) > 2 and isinstance(j[2], str) else None
            else:  # [["translation","lang"]] or ["translation"]
                first = j[0]
                en, lang = (first[0], first[1]) if isinstance(first, list) else (first, None)
            if en:
                res = (en, LANG_NAMES.get(lang, lang)) if lang and not str(lang).startswith("en") else (text, None)
                break
        except Exception:
            time.sleep(1 + attempt)
    if res is None:
        res = (text, "?")
    else:
        cache[text] = list(res)
        if len(cache) > 3000:
            for k in list(cache)[:1000]:
                del cache[k]
    return res


def news_parts(text):
    """'[es-419] Title - Source (20 Nov 2026) link' or '[source] Title link' -> headline, meta, link."""
    links = URL_RE.findall(re.sub(r"^\[[^\]]*\]\s*", "", text)) or URL_RE.findall(text)  # not the feed URL in the tag
    body = URL_RE.sub("", text).strip()
    tag = re.match(r"^\[([^\]]*)\]\s*", body)
    tag = tag.group(1).strip() if tag else ""
    body = re.sub(r"^\[[^\]]*\]\s*", "", body)
    date = re.search(r"\s*\((\d{1,2} \w{3} \d{4})[^)]*\)\s*$", body)
    if date:
        body = body[:date.start()].strip()
    lang = re.search(r"\s*\{(\w[\w ]*)\}", body)
    if lang:
        body = (body[:lang.start()] + body[lang.end():]).strip()
    src = re.search(r"\s+[-|–]\s+([^-|–]{2,60})$", body)
    source = src.group(1).strip() if src else ("" if re.match(r"^[a-z]{2}(-\w+)?$", tag or "x") else tag)
    if src:
        body = body[:src.start()].strip()
    meta = " · ".join(x for x in [source, lang.group(1) if lang else "", date.group(1)[:6] if date else ""] if x)
    return body, meta, (links[0] if links else "")


def translate_items(http, state, items, limit=80):
    """Headlines in other languages become English, with the language noted."""
    cache = state.setdefault("translations", {})
    done = 0
    for it in items:
        if it["check"] not in ("news", "outlets", "telegram", "forum"):
            continue
        if done >= limit:
            it["foreign"] = not news_parts(it["text"])[0].isascii()
            continue
        head, meta, link = news_parts(it["text"])
        tagged = re.match(r"^\[(es|pt|it|de|fr|nl|cs|sk|pl|tr|ru|uk|th|ja|ko|zh|vi|id|ms|tl|hi|ar|he|sv|no|da|fi|el|ro|hu|bg|hr|sr|lt|lv|et|sl|fa|ka)", it["text"])
        if not tagged and head.isascii() and len(EN_HINT.findall(head)) >= 2:
            continue  # already English
        en, lang = translate_en(http, head, cache)
        done += 1
        if lang == "?":
            it["foreign"] = True  # could not translate: report only, never urgent
        elif lang:
            it["text"] = it["text"].replace(head, f"{en} {{{lang}}}", 1)



def format_group_list(cfg, stories, per_type, with_sources=True):
    groups = {}
    for s in merge_same_wallet(stories):
        groups.setdefault(s["check"], []).append(s)
    blocks = []
    for check in sorted(groups, key=lambda c: ORDER.index(c) if c in ORDER else 99):
        icon, label, tag, _ = CATS.get(check, ("•", check, check, "news"))
        items = sorted(groups[check], key=lambda s: (not s["urgent"], s["level"] != HIGH, -s["sources"]))
        lines = []
        newsy = check in ("news", "forum")
        for s in items[:per_type]:
            mark = "🚨 " if s["urgent"] else ""
            src = f" (+{s['sources'] - 1} source{'s' if s['sources'] > 2 else ''})" if with_sources and s["sources"] > 1 else ""
            if newsy:
                head, meta, link = disp(s, 160)
                sub = " · ".join(x for x in [meta, src.strip(" ()")] if x)
                lines.append(f"• {mark}{esc(head)}" + (f'\n   <i>{esc(sub)}</i>' if sub else "")
                             + (f' <a href="{esc(link)}">↗</a>' if link else ""))
            else:
                line, link = short_line(s)
                lines.append(f"• {mark}{esc(line)}{src}" + (f' <a href="{esc(link)}">↗</a>' if link else ""))
        more = f"\n<i>+{len(items) - len(lines)} more</i>" if len(items) > len(lines) else ""
        blocks.append(f"{icon} <b>{esc(label)}</b> ({len(items)})\n\n" + ("\n\n" if newsy else "\n").join(lines) + more)
    return "\n\n".join(blocks)


def local_tz(cfg):
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(cfg.get("telegram", {}).get("timezone", "Europe/Madrid"))
    except Exception:
        return dt.timezone.utc


def importance(cfg, s):
    """Score used to sort the update: money at stake, hack and police words, known brands, how many sources."""
    txt = s["text"]
    head = news_parts(txt)[0] if s["check"] in ("news", "outlets") else URL_RE.sub("", txt)
    sc = 100 if s.get("urgent") else 0
    sc += {"chain": 40, "freeze": 35, "hacks": 35, "sites": 30, "register": 30, "message": 30, "token": 25,
           "telegram": 20, "pages": 20, "outlets": 15, "news": 15, "forum": 15, "wallets": 0}.get(s["check"], 10)
    m = re.search(r"\$([\d,]+)", txt)
    if m:
        usd = float(m.group(1).replace(",", ""))
        sc += 10 if usd >= 1e5 else 0
        sc += 10 if usd >= 1e6 else 0
        sc += 10 if usd >= 1e7 else 0
    if HACK_RE.search(head):
        sc += 25
    if re.search(r"police|raid|arrest|charged|seiz|court|sued|lawsuit|fined|licen[cs]e (revoked|suspended)|regulat|banned|block", head, re.I):
        sc += 15
    if re.search(r"withdraw|frozen|freez|maintenance|down|offline|paused|insolven|exit", head, re.I):
        sc += 15
    if "OF ITS BALANCE" in txt or "ITS BIGGEST" in txt or "FRESH" in txt:
        sc += 15
    b = outlet_terms(cfg)[0].search(head)
    if b and b.group(0).lower() not in AMBIGUOUS_BRANDS:
        sc += 10
    sc += min(4, s.get("sources", 1) - 1) * 5
    if s.get("level") == HIGH:
        sc += 5
    return sc


def cut(text, limit):
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[:limit - 1].rsplit(" ", 1)[0].rstrip(",;:") + "…"


def disp(s, limit=130):
    """(headline, small grey line, link) for any story, in plain English."""
    if GROUP.get(s["check"], s["check"]) in ("news", "forum") or s["check"] == "news":
        head, meta, link = news_parts(s["text"])
        if s.get("line"):
            head = s["line"]
            meta = re.sub(r"\s*·\s*(" + "|".join(set(LANG_NAMES.values())) + r")\b", "", meta)
        meta = " · ".join(p for p in meta.split(" · ") if p and not NON_LATIN.search(p))  # no unreadable source names
        also = [a for a in s.get("also", []) if not NON_LATIN.search(a)]
        if also:
            meta = (meta + " · " if meta else "") + "also " + ", ".join(also[:3])
        return cut(head, limit), meta, link
    line, link = short_line(s, 400)
    return cut(line, limit), "", link


def still_urgent(cfg, s):
    """Re-check a stored story with today's rules, so old mistakes don't stay in the log."""
    if s.get("ai_keep"):
        return s["ai_keep"] == "urgent" or (s["check"] in HARD_CHECKS and s.get("urgent"))
    it = {"check": s["check"], "text": s["text"], "key": s["key"], "level": s["level"]}
    if classify(cfg, it) == "minor":
        return False
    return is_urgent(cfg, Alert(s["level"], s["check"], s["key"], s["text"]))


def urgent_today_block(cfg, state, t, limit=5):
    """'Urgent today' at the top of every update: today's urgent stories, newest first."""
    tz = local_tz(cfg)
    today = t.astimezone(tz).date()
    items = [s for s in state.get("stories", []) if s.get("urgent") and parse_iso(s["first"]).astimezone(tz).date() == today
             and still_urgent(cfg, s)]
    if not items:
        return "🚨 <b>Urgent today:</b> none"
    items.sort(key=lambda s: s["first"], reverse=True)
    lines = []
    for s in items[:limit]:
        when = parse_iso(s["first"]).astimezone(tz).strftime("%H:%M")
        head, _, link = disp(s, 90)
        lines.append(f"<code>{when}</code> {esc(head)}" + (f' <a href="{esc(link)}">↗</a>' if link else ""))
    more = f"\n<i>+{len(items) - limit} earlier today</i>" if len(items) > limit else ""
    return "🚨 <b>Urgent today</b>\n" + "\n".join(lines) + more


SECTIONS = [("⛓", "On-chain", {"chain", "message", "wallet", "freeze", "token"}),
            ("💥", "Hacks", {"hacks"}),
            ("🌐", "Sites and licences", {"sites", "register", "pages"}),
            ("📰", "News", {"news", "outlets"}),
            ("💬", "Forums and Telegram", {"forum", "telegram"})]


def score(cfg, s):
    return s["ai_score"] + (100 if s.get("urgent") else 0) if s.get("ai_score") is not None else importance(cfg, s)


def main_brand(cfg, s):
    b = outlet_terms(cfg)[0].search(disp(s, 400)[0])
    return b.group(0).lower() if b and b.group(0).lower() not in AMBIGUOUS_BRANDS else None


def format_sections(cfg, stories, limit):
    """Update body: stories grouped by kind, the most important kind first, best story first in each.
    News about the same brand in one update is folded into one line."""
    items = sorted(merge_same_wallet(stories), key=lambda s: -score(cfg, s))
    kept, by_brand = [], {}
    for s in items:
        if s["check"] in ("news", "outlets"):
            b = main_brand(cfg, s)
            if b and b in by_brand:
                by_brand[b]["_more"].append(s)
                continue
            s = dict(s, _more=[])
            if b:
                by_brand[b] = s
        kept.append(s)
    shown, blocks = kept[:limit], []
    for icon, title, checks in sorted(SECTIONS, key=lambda sec: -max([score(cfg, s) for s in shown if s["check"] in sec[2]] or [-1])):
        group = [s for s in shown if s["check"] in checks]
        if not group:
            continue
        lines = []
        for s in group:
            head, meta, link = disp(s)
            arrow = f' <a href="{esc(link)}">↗</a>' if link else ""
            more = s.get("_more") or []
            if more:
                srcs = [news_parts(m["text"])[1].split(" · ")[0] for m in more]
                meta = (meta + " · " if meta else "") + f"+{len(more)} more on this: " + ", ".join(x for x in srcs if x)[:80]
            if title == "News":
                lines.append(f"• <b>{esc(head)}</b>" + (f"\n   <i>{esc(meta)}</i>{arrow}" if meta else arrow))
            else:
                lines.append(f"• {esc(head)}{arrow}" + (f"\n   <i>{esc(meta)}</i>" if meta else ""))
        blocks.append(f"{icon} <b>{title}</b>\n" + "\n".join(lines))
    rest = len(kept) - len(shown)
    return "\n\n".join(blocks) + (f"\n\n<i>+{rest} smaller items in the next report</i>" if rest > 0 else "")


def story_lines(cfg, s, tz=None, bold=True, extra=""):
    """One story: icon + headline (+ time) on the first line, source line under it in grey."""
    icon = CATS.get(s["check"], ("•",))[0]
    head, meta, link = disp(s, 120)
    when = f"<code>{parse_iso(s['first']).astimezone(tz):%H:%M}</code> " if tz else ""
    arrow = f' <a href="{esc(link)}">↗</a>' if link else ""
    title = f"<b>{esc(head)}</b>" if bold else esc(head)
    sub = " · ".join(x for x in [meta, extra] if x)
    if sub:
        return f"{when}{icon} {title}\n      <i>{esc(sub)}</i>{arrow}"
    return f"{when}{icon} {title}{arrow}"


def fold_brands(cfg, items):
    """Same brand in several news items -> one line with '+N more on this'."""
    kept, by_brand = [], {}
    for s in items:
        if s["check"] in ("news", "outlets"):
            b = main_brand(cfg, s)
            if b and b in by_brand:
                by_brand[b]["_more"].append(s)
                continue
            s = dict(s, _more=[])
            if b:
                by_brand[b] = s
        kept.append(s)
    return kept


def more_note(s):
    more = s.get("_more") or []
    if not more:
        return ""
    srcs = [news_parts(m["text"])[1].split(" · ")[0] for m in more]
    return f"+{len(more)} more on this" + (": " + ", ".join(x for x in srcs if x)[:60] if any(srcs) else "")


def format_update(cfg, state, new, t, summary="", updated=(), filtered=()):
    """Every update has the same order, so the eye knows where to look:
    URGENT (today) -> NEW (since the last update) -> UPDATED (older stories with fresh news) -> EARLIER TODAY."""
    tcfg = cfg.get("telegram", {})
    tz = local_tz(cfg)
    lt = t.astimezone(tz)
    today = lt.date()
    blocks = [f"🛰 <b>UPDATE · {lt:%H:%M}</b>" + (f"\n<i>{esc(summary)}</i>" if summary else "")
              + (f"\n⚠️ AI check not working ({esc(state['ai_error'])}), plain filters used" if state.get("ai_error") else "")]

    todays = [s for s in state.get("stories", []) if parse_iso(s["first"]).astimezone(tz).date() == today]
    urg = sorted([s for s in todays if s.get("urgent") and still_urgent(cfg, s)], key=lambda s: s["first"], reverse=True)
    if urg:
        lim = tcfg.get("urgent_items") or 10**6
        blocks.append(f"🚨 <b>URGENT TODAY</b> ({len(urg)})\n\n" + "\n\n".join(
            story_lines(cfg, s, tz, extra="NEW" if s["first"] == iso(t) else "") for s in urg[:lim])
            + (f"\n\n<i>+{len(urg) - lim} earlier, see the report</i>" if len(urg) > lim else ""))
    else:
        blocks.append("🚨 <b>URGENT TODAY</b>: none")

    if new:
        items = fold_brands(cfg, sorted(merge_same_wallet(new), key=lambda s: -score(cfg, s)))
        lim = tcfg.get("update_items") or 10**6
        blocks.append(f"🆕 <b>NEW</b> ({len(items)})\n\n" + "\n\n".join(story_lines(cfg, s, extra=more_note(s)) for s in items[:lim])
                      + (f"\n\n<i>+{len(items) - lim} smaller items in the next report</i>" if len(items) > lim else ""))

    if updated:
        items = sorted(updated, key=lambda s: -score(cfg, s))[:tcfg.get("updated_items") or 10**6]
        blocks.append(f"🔁 <b>UPDATED</b> ({len(items)})\n\n" + "\n\n".join(
            story_lines(cfg, s, tz, bold=False, extra="" if s.get("also") else f"now {s['sources']} sources") for s in items))

    shown = {id(s) for s in urg} | {s.get("key") for s in new} | {s.get("key") for s in updated}
    earlier = [s for s in todays if not s.get("minor") and id(s) not in {id(u) for u in urg}
               and s.get("key") not in shown and not s.get("urgent")]
    if earlier:
        earlier = fold_brands(cfg, sorted(earlier, key=lambda s: -score(cfg, s)))
        lim = tcfg.get("earlier_items") or 10**6
        blocks.append(f"📋 <b>EARLIER TODAY</b> " + (f"(top {lim} of {len(earlier)})" if len(earlier) > lim else f"({len(earlier)})") + "\n\n" + "\n".join(
            story_lines(cfg, s, tz, bold=False).split("\n")[0] for s in earlier[:lim]))
    if filtered:
        lines = []
        for s in sorted(filtered, key=lambda s: -score(cfg, s)):
            head, _, link = disp(s, 100)
            if NON_LATIN.search(head):
                head = "(headline could not be translated)"
            why = s.get("why") or ""
            lines.append(f"· {esc(head)}" + (f' <a href="{esc(link)}">↗</a>' if link else "") + (f" <i>({esc(why)})</i>" if why else ""))
        blocks.append(f"🔎 <b>FILTERED OUT</b> ({len(filtered)}) <i>held back since the last update, in case the filter got it wrong</i>\n"
                      + "\n".join(lines))
    return "\n\n".join(blocks)


# ---------- optional AI check (Claude Haiku), used only when ANTHROPIC_API_KEY is set ----------
HARD_CHECKS = {"chain", "message", "wallet", "freeze", "token", "sites", "register", "pages"}  # facts the radar measured itself
AI_SYSTEM = """You are the night editor for a news alert feed. The reader is a journalist at FairGambling, an independent watchdog that covers crypto casinos, online gambling and iGaming, sportsbooks, and prediction markets (Kalshi, Polymarket). Their edge is breaking stories first and checking what operators claim against on-chain data. They read the feed on a phone, so every line must make sense at a glance.

THE ONE RULE: missing an important story is far worse than showing an extra one. If you are unsure, choose "update", never "drop". Only drop what is clearly off the beat.

Each run you get numbered items found by automatic checks: news searches in many languages, gambling trade outlets, block explorers watching casino wallets, a hack database, casino websites going up and down, licence registers, BitcoinTalk and Telegram. Each item shows its kind and what the rule-based filter thought. The filter is crude, so judge for yourself, except that you never hide on-chain, wallet, site or licence facts (the code keeps those anyway).

For every item decide "keep":
- "urgent": could become a story within hours, so the journalist should look now.
  * a hack, drain, exploit or insider theft at a casino, sportsbook, prediction market or gambling platform, or its bankroll or hot wallet
  * player withdrawals frozen, a casino suddenly offline, seized or gone, an exit scam
  * police raids, arrests, charges or asset seizures involving a gambling operator, its owners or payment partners, anywhere in the world
  * a regulator or court banning, blocking, suspending or shutting down a gambling brand, or revoking a licence
  * big money leaving a watched attacker wallet or a casino bankroll
  * a real development in a story listed under "Ongoing stories" (an arrest, a statement, funds moving, a ruling)
- "update": on the beat but not an emergency: lawsuits and court steps, new laws and regulation, licences, tax, company deals and ownership, layoffs, big wins, smaller wallet moves, players saying a casino won't pay, streamer gambling stories with a business or legal angle, research and data about gambling.
- "report": only loosely related to gambling or crypto casinos.
- "drop": clearly off the beat: sport results, standings, previews and transfer news; odds, picks and betting tips; promo, bonus and referral codes; casino reviews and best-of lists; celebrity gossip; horse racing results; lottery winner human-interest stories; crypto hacks and market news with no gambling link.

How to judge:
- Small, local and foreign outlets matter. A local Czech news site was the only place that reported the police raid on Betfin in October, and that story was missed. A police or court story about a gambling operator is urgent whatever the language or outlet size.
- An unknown casino name next to a word like hack, drained, frozen, raid, arrested, won't pay or scam still counts. Most casinos on the beat are small.
- Watched brands (anything in this list is on the beat): {brands}
- A brand name in a sports headline (a betting firm sponsoring a league or team) does not make it gambling news.
- Kalshi and Polymarket court and regulation fights are "update". Make them "urgent" only when a ruling, ban or shutdown actually takes effect, or for a hack.
- If several items are the same story, keep the most informative one and give the others "same_as" with its id.

For every item also write:
- "line": one plain-English sentence, at most 110 characters, that a busy person understands at once. Translate anything not in English. Start with who did what, then the number, then where: "Czech police raid Betfin office over illegal gambling", "Roobet hot wallet sent $410K USDT to a brand-new wallet (Ethereum)". Use only facts in the item and never guess. Keep amounts short ($110K, $5.3M). No hashtags, emojis, quote marks or clickbait.
- "why": at most 12 words on why it matters, or why you dropped it.
- "score": 0 to 100, how much it matters to this watchdog right now.

Also write "summary": one sentence of at most 150 characters on the most important thing in this batch, or "" if nothing stands out.

Answer with JSON only:
{{"summary": "...", "items": [{{"id": 1, "keep": "update", "line": "...", "why": "...", "score": 40, "same_as": null}}]}}"""

# words that mean a story must never be dropped by the AI, whatever it thinks
NEVER_DROP_RE = re.compile(r"hack|exploit|drain|stolen|theft|raid|arrest|detain|charged|indict|seiz|frozen|freez|"
                           r"insolven|bankrupt|exit scam|won'?t pay|not paying|withdrawals? (paused|suspended|halted|blocked)|"
                           r"licen[cs]e (revoked|suspended|cancel)|shut ?down|banned|blocked", re.I)


def ai_review(cfg, http, items, state=None):
    """Claude reads the new items, sorts them, writes one clear English line each and a summary.
    Safety rails in code: measured facts are never hidden, rule-urgent items never go below the
    update, items with hack/police/freeze words are never dropped, and if the call fails the
    rule-based result is used. Returns the summary, or None when off or failed."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    acfg = cfg.get("ai", {}) or {}
    if not key or not items or acfg.get("enabled", True) is False:
        return None
    batch = items[:acfg.get("max_items", 80)]
    brands = ", ".join(dict.fromkeys(cfg.get("wallet_brands", []) + (cfg.get("forum", {}) or {}).get("brands", [])))[:3000]
    ongoing = []
    if state:
        t_now = max((parse_iso(s["last"]) for s in state.get("stories", [])), default=None)
        for s in reversed(state.get("stories", [])):
            if s.get("urgent") and t_now and t_now - parse_iso(s["first"]) < dt.timedelta(days=3):
                ongoing.append("- " + cut(disp(s)[0], 120))
            if len(ongoing) >= 12:
                break
    rows = []
    for i, it in enumerate(batch, 1):
        rule = "urgent" if it["urgent"] else ("report" if it.get("minor") else "update")
        kind = CATS.get(it["check"], ("", it["check"]))[1]
        rows.append(f"{i}. [{kind}] (filter: {rule}) {cut(plain(it['text']), 420)}")
    user = ("Ongoing stories (last 3 days):\n" + ("\n".join(ongoing) or "- none") + "\n\nNew items:\n" + "\n".join(rows))
    body = {"model": acfg.get("model", "claude-haiku-5-5"), "max_tokens": acfg.get("max_tokens", 8000),
            "system": AI_SYSTEM.format(brands=brands), "messages": [{"role": "user", "content": user}]}
    try:
        r = http.post("https://api.anthropic.com/v1/messages", json=body, timeout=90,
                      headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        r.raise_for_status()
        text = "".join(c.get("text", "") for c in r.json().get("content", []) if c.get("type") == "text")
        data = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
    except Exception as e:
        log(f"ai: skipped ({type(e).__name__})")
        if state is not None:
            code = getattr(getattr(e, "response", None), "status_code", "")
            state["ai_error"] = {401: "API key not accepted", 403: "API key not allowed",
                                 429: "rate limit or no credit left", 400: "request refused (check credit)"}.get(code, f"{type(e).__name__} {code}".strip())
        return None
    if state is not None:
        state.pop("ai_error", None)
        state["ai_ok"] = state.get("ai_ok", 0) + 1
    dups = []
    for d in data.get("items", []):
        try:
            it = batch[int(d["id"]) - 1]
        except (KeyError, ValueError, IndexError, TypeError):
            continue
        keep = d.get("keep") if d.get("keep") in ("urgent", "update", "report", "drop") else None
        if not keep:
            continue
        line = cut(str(d.get("line") or ""), 160)
        if line and not NON_LATIN.search(line):
            it["line"] = line
        why = cut(str(d.get("why") or ""), 100)
        if why:
            it["why"] = why
        try:
            it["ai_score"] = max(0, min(100, int(d.get("score") or 0)))
        except (TypeError, ValueError):
            pass
        head = news_parts(it["text"])[0] + " " + (it.get("line") or "")
        if keep in ("report", "drop") and NEVER_DROP_RE.search(head) and not SPORT_EXTRA.search(head):
            keep = "update"  # rail: hack, police or freeze words never leave the update
        it["ai_keep"] = keep
        if it["check"] in HARD_CHECKS:
            if keep == "urgent" and not it.get("minor"):
                it["urgent"] = True  # measured facts: Claude may raise them, never hide them
            continue
        try:
            same = int(d.get("same_as")) if d.get("same_as") not in (None, "", "null") else None
        except (TypeError, ValueError):
            same = None
        if same and same != int(d["id"]) and 0 < same <= len(batch) and not it["urgent"]:
            dups.append((it, batch[same - 1]))
            continue
        if keep == "urgent":
            it["urgent"], it["minor"] = True, False
        elif keep == "update" or it["urgent"]:
            it["urgent"], it["minor"] = False, False  # a rule-urgent item never goes below the update
        else:
            it["urgent"], it["minor"] = False, True
    for it, target in dups:
        it["urgent"], it["minor"], it["ai_keep"] = False, True, "dup"
        src = news_parts(it["text"])[1].split(" · ")[0]
        if src and src not in target.setdefault("also", []):
            target["also"].append(src)
    return cut(str(data.get("summary") or ""), 180)


def split_message(text, size=3900):
    """Telegram takes 4096 characters per message. Split between stories (never inside one, so
    HTML tags never break) and never drop anything: long lists simply become several messages."""
    paras = []
    for para in text.split("\n\n"):
        if len(para) <= size:
            paras.append(para)
            continue
        cur = ""
        for line in para.split("\n"):
            if len(cur) + len(line) + 1 > size and cur:
                paras.append(cur)
                cur = ""
            cur = (cur + "\n" + line) if cur else line[:size]
        if cur:
            paras.append(cur)
    chunks, cur = [], ""
    for para in paras:
        if len(cur) + len(para) + 2 > size and cur:
            chunks.append(cur)
            cur = ""
        cur = (cur + "\n\n" + para) if cur else para
    if cur:
        chunks.append(cur)
    return chunks


def send_telegram(http, text, cfg=None, topic=None, silent=False):
    tok, chat = os.environ.get("TELEGRAM_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not tok or not chat:
        print("TELEGRAM not configured" + ("" if QUIET else "; message below\n" + text + "\n"))
        return
    thread = ((cfg or {}).get("telegram", {}).get("topics") or {}).get(topic) if topic else None
    for c in split_message(text):
        data = {"chat_id": chat, "text": c, "parse_mode": "HTML",
                "disable_web_page_preview": "true", "disable_notification": "true" if silent else "false"}
        if thread:
            data["message_thread_id"] = str(thread)
        try:
            r = http.post(f"https://api.telegram.org/bot{tok}/sendMessage", data=data)
            if getattr(r, "status_code", 200) == 429:
                time.sleep(3)
                http.post(f"https://api.telegram.org/bot{tok}/sendMessage", data=data)
        except Exception as e:
            log(f"telegram: {e}")
        time.sleep(0.4)


def deliver(cfg, state, http, alerts, t, dry):
    """Every run: urgent stories one by one (with sound) + one short update with the
    other new stories. Every report_every_hours: a report of every story in that window."""
    tcfg = cfg.get("telegram", {})
    sent = set(state.get("sent", []))
    fresh = []
    for a in alerts:
        if a.key not in sent:
            sent.add(a.key)
            fresh.append({"key": a.key, "check": a.check, "level": a.level, "text": a.text,
                          "urgent": False, "t": iso(t)})
    state["sent"] = list(sent)[-40000:]
    if not dry or tcfg.get("translate_in_dry", False):
        translate_items(http, state, fresh, tcfg.get("translate_per_run", 120))
    for it in fresh:
        it["minor"] = classify(cfg, it) == "minor"
        it["urgent"] = not it["minor"] and is_urgent(cfg, Alert(it["level"], it["check"], it["key"], it["text"]))
    summary = ai_review(cfg, http, fresh, state) or ""
    state["inbox"] = (state.get("inbox", []) + fresh)[-tcfg.get("inbox_size", 5000):]
    new_stories = add_to_stories(state, fresh, t)
    out = []  # (text, topic, silent)
    urgent = [s for s in new_stories if s["urgent"]]
    for s in urgent[:tcfg.get("max_urgent_per_run", 10)]:
        out.append((format_urgent(cfg, s, t), "urgent", False))
    if len(urgent) > tcfg.get("max_urgent_per_run", 10):
        rest = urgent[tcfg.get("max_urgent_per_run", 10):]
        out.append((f"🚨 <b>URGENT</b> · {len(rest)} more\n\n" + format_group_list(cfg, rest, 20, False), "urgent", False))
    others = [s for s in new_stories if not s["urgent"] and not s.get("minor")]
    bumped = [s for s in state.get("stories", []) if s.get("bumped") == iso(t) and not s.get("minor") and s not in new_stories]
    # everything held back since the last update is listed at its bottom, so nothing is invisible
    pend = state.setdefault("filtered_pending", [])
    pend += [s["key"] for s in new_stories if s.get("minor") and not s["urgent"] and s["check"] not in ("wallets", "wallet")]
    if others or bumped or urgent:
        keys = set(pend)
        filtered = [s for s in state.get("stories", []) if s["key"] in keys and s.get("minor")]
        state["filtered_pending"] = []
        out.append((format_update(cfg, state, others, t, summary, bumped, filtered), "updates", tcfg.get("updates_silent", True)))
    else:
        state["filtered_pending"] = pend[-500:]
    # report every N hours: all stories in the window, merged, urgent first
    every = dt.timedelta(hours=tcfg.get("report_every_hours", 5))
    last = state.get("report_at")
    if not last:
        state["report_at"] = iso(t - dt.timedelta(seconds=1))
    elif t - parse_iso(last) >= every:
        window = [s for s in state.get("stories", []) if parse_iso(s["last"]) > parse_iso(last)]
        state["report_at"] = iso(t)
        n_urg = sum(1 for s in window if s["urgent"])
        window_major = [s for s in window if not s.get("minor")]
        meta = state.get("sites_meta", {})
        head = (f"📚 <b>{tcfg.get('report_every_hours', 5)}-hour report</b> · {(parse_iso(last) + dt.timedelta(seconds=1)).astimezone(local_tz(cfg)):%d %b %H:%M}–{t.astimezone(local_tz(cfg)):%H:%M}\n"
                f"{len(window_major)} stories, {n_urg} urgent\n"
                f"<i>{meta.get('known', 0)} sites · {len(state.get('wallets', {})) + len(state.get('discovered_wallets', {}))} wallets · "
                f"{state.get('outlets_meta', {}).get('feeds', 0)} outlet feeds · "
                f"{len(state.get('registers', {}).get('anjouan') or {})}+{len(state.get('registers', {}).get('curacao') or {})} licences</i>")
        health = health_lines(state, t)
        if health:
            head += "\n⚠️ <b>Not working:</b> " + esc("; ".join(health))
        urg = [s for s in window if s["urgent"] and still_urgent(cfg, s)]
        rest_w = [s for s in window if s not in urg and not s.get("minor")]
        minor_w = [s for s in window if s not in urg and s.get("minor") and s.get("ai_keep") != "drop"
                   and not NON_LATIN.search(disp(s)[0])]
        parts = []
        if urg:
            parts.append(f"🚨 <b>URGENT</b> ({len(urg)})\n" + "\n".join(
                "• " + esc(disp(s)[0]) + (f' <a href="{esc(disp(s)[2])}">↗</a>' if disp(s)[2] else "")
                for s in urg[:40]))
        if rest_w:
            parts.append(format_group_list(cfg, rest_w, tcfg.get("report_items_per_type", 30)))
        if minor_w:
            parts.append(f"🔎 <b>Also seen, probably not relevant</b> ({len(minor_w)})\n\n"
                         + "\n".join("• " + esc(disp(s, 110)[0]) for s in minor_w[:tcfg.get("report_minor_items", 15)])
                         + (f"\n<i>+{len(minor_w) - tcfg.get('report_minor_items', 15)} more</i>" if len(minor_w) > tcfg.get("report_minor_items", 15) else ""))
        dropped = [s for s in window if s.get("ai_keep") == "drop"]
        if dropped:
            parts.append(f"🗑 <b>Filtered out by the AI</b> ({len(dropped)}), check now and then that nothing good is here\n"
                         + "\n".join("• " + esc(disp(s, 90)[0]) + (f" <i>({esc(s['why'])})</i>" if s.get("why") else "")
                                      for s in dropped[:20]))
        body = "\n\n".join(parts) if parts else "Nothing new in this window."
        out.append((head + "\n\n" + body, "reports", False))
    for text, topic, silent in out:
        if dry:
            print(text + "\n")
        else:
            send_telegram(http, text, cfg, topic, silent)
    return fresh


def _fernet():
    """State is encrypted when RADAR_STATE_KEY is set, so a copy of the cache is
    unreadable without the secret."""
    key = os.environ.get("RADAR_STATE_KEY")
    if not key:
        return None
    import base64
    from cryptography.fernet import Fernet
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))


def load_state(path):
    if not os.path.exists(path):
        return {}
    try:
        raw = open(path, "rb").read()
        f = _fernet()
        if f and not raw.lstrip().startswith(b"{"):
            raw = f.decrypt(raw)
        return json.loads(raw)
    except Exception:
        log("state unreadable, starting fresh")
        return {}


def save_state(path, state):
    raw = json.dumps(state, separators=(",", ":")).encode()
    f = _fernet()
    if f:
        raw = f.encrypt(raw)
    tmp = path + ".tmp"
    open(tmp, "wb").write(raw)
    os.replace(tmp, path)



# ---------------------------------------------------------------- solana
SOL_RPC = ["https://api.mainnet-beta.solana.com", "https://solana-rpc.publicnode.com"]
SOL_MINTS = {"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": ("USDC", 1.0), "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": ("USDT", 1.0)}


def sol_rpc(http, method, params):
    last = None
    for u in SOL_RPC:
        try:
            r = http.post(u, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15)
            j = r.json()
            if "error" in j:
                raise RuntimeError(str(j["error"])[:120])
            return j["result"]
        except Exception as e:
            last = e
    raise RuntimeError(f"solana {method}: {last}")


def sol_price(http):
    try:
        d = http.json("https://api.geckoterminal.com/api/v2/simple/networks/solana/token_price/So11111111111111111111111111111111111111112")
        return float(list(d["data"]["attributes"]["token_prices"].values())[0])
    except Exception:
        return 0.0


def sol_changes(tx, owner):
    """USD-free balance changes for `owner` in one parsed transaction:
    {asset: (delta, post_balance)} and, per asset, the account that gained the most."""
    meta = tx.get("meta") or {}
    keys = [k["pubkey"] if isinstance(k, dict) else k for k in tx["transaction"]["message"]["accountKeys"]]
    out, gainers = {}, {}
    if owner in keys:
        i = keys.index(owner)
        pre, post = meta["preBalances"][i], meta["postBalances"][i]
        out["SOL"] = ((post - pre) / 1e9, post / 1e9)
        best = max(((meta["postBalances"][j] - meta["preBalances"][j], keys[j]) for j in range(len(keys)) if keys[j] != owner), default=(0, None))
        if best[0] > 0:
            gainers["SOL"] = best[1]
    bal = {}
    for side in ("preTokenBalances", "postTokenBalances"):
        for b in meta.get(side) or []:
            mint = b.get("mint")
            if mint not in SOL_MINTS:
                continue
            amt = float((b.get("uiTokenAmount") or {}).get("uiAmount") or 0)
            k = (b.get("owner"), mint)
            bal.setdefault(k, [0.0, 0.0])[0 if side.startswith("pre") else 1] = amt
    for (own, mint), (pre, post) in bal.items():
        sym = SOL_MINTS[mint][0]
        if own == owner:
            out[sym] = (post - pre, post)
        elif post - pre > 0 and (sym not in gainers or post - pre > bal.get((gainers[sym], mint), [0, 0])[1] - bal.get((gainers[sym], mint), [0, 0])[0]):
            gainers[sym] = own
    return out, gainers


def check_solana(cfg, state, http, t, budget=None, base_dir="."):
    """Solana casino wallets and leads: big outflows (SOL, USDC, USDT), with the same hack
    signals as the EVM watcher: new receiver, share of balance, fan-in, follow the receiver."""
    scfg = cfg.get("solana", {})
    pinned, disc = load_wallets(cfg, state, base_dir)
    wallets = {w["address"]: (w["name"], w.get("kind", "hot"), float(w.get("min_usd") or 0))
               for w in pinned + disc if w["chain"] == "solana"}
    sus = state.setdefault("suspects", {})
    for key, v in list(sus.items()):
        if key.startswith("solana:") and key[7:] not in wallets:
            wallets[key[7:]] = (v["name"], "suspect", 10000.0)
    if not wallets:
        return []
    st = state.setdefault("solana", {"last": {}})
    first = not st["last"]
    px = {"SOL": None, "USDC": 1.0, "USDT": 1.0}
    min_usd = scfg.get("outflow_min_usd", cfg.get("chains", {}).get("outflow_min_usd", 250000))
    hist_all = state.setdefault("outhist", {})
    alerts, moves = [], []
    for addr in rotate(sorted(wallets), state.setdefault("cursors", {}), "solana", scfg.get("wallets_per_run", 60)):
        if budget and not budget.ok(6):
            break
        name, kind, wmin = wallets[addr]
        try:
            sigs = sol_rpc(http, "getSignaturesForAddress", [addr, {"limit": 25}])
        except Exception as e:
            log(f"solana {name}: {e}")
            continue
        last = st["last"].get(addr)
        new = []
        for x in sigs:
            if x["signature"] == last:
                break
            if not x.get("err"):
                new.append(x["signature"])
        if sigs:
            st["last"][addr] = sigs[0]["signature"]
        if first or last is None:
            continue  # first sighting: remember where we are, no alerts
        for sig in reversed(new[:15]):
            try:
                tx = sol_rpc(http, "getTransaction", [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
            except Exception as e:
                log(f"solana tx: {e}")
                continue
            if not tx:
                continue
            ch, gainers = sol_changes(tx, addr)
            for sym, (delta, post) in ch.items():
                if delta >= 0:
                    continue
                if sym == "SOL" and px["SOL"] is None:
                    px["SOL"] = sol_price(http)
                usd = -delta * (px[sym] or 0)
                floor = wmin if kind in ("parked", "suspect") and wmin else min_usd
                if usd < min(floor, scfg.get("look_min_usd", 25000)):
                    continue
                dst = gainers.get(sym)
                tag, level, fresh, extra = "", LOW, False, ""
                if dst:
                    try:
                        n = len(sol_rpc(http, "getSignaturesForAddress", [dst, {"limit": 5}]))
                        if n <= scfg.get("fresh_max_txs", 3):
                            tag, level, fresh = f" to a FRESH address ({n} txs)", HIGH, True
                    except Exception:
                        pass
                share = -delta / (-delta + post) if (-delta + post) else 0
                if share >= cfg.get("chains", {}).get("share_urgent", 0.4):
                    extra += f" [{share:.0%} OF ITS BALANCE]"
                hk = f"solana:{addr}"
                hist = [h for h in hist_all.get(hk, []) if t - parse_iso(h[0]) < dt.timedelta(days=30)]
                biggest = max((h[1] for h in hist), default=0)
                if biggest and usd >= 3 * biggest:
                    extra += f" [{usd / biggest:.0f}X ITS BIGGEST IN 30 DAYS]"
                hist.append((iso(t), usd))
                hist_all[hk] = sorted(hist, key=lambda h: -h[1])[:20]
                if usd < floor and "OF ITS BALANCE" not in extra and not ("ITS BIGGEST" in extra and fresh):
                    continue
                if kind == "parked":
                    level = HIGH
                elif kind == "suspect":
                    level, extra = HIGH, extra + " [SUSPECT WALLET MOVED]"
                if dst:
                    moves.append(("solana", addr, dst, usd, fresh, name))
                    if fresh and usd >= cfg.get("chains", {}).get("suspect_min_usd", 100_000):
                        sus.setdefault(f"solana:{dst}", {"name": f"New wallet that got ${usd:,.0f} from {name}",
                                                         "until": iso(t + dt.timedelta(hours=72))})
                alerts.append(Alert(level, "chain", f"out:{sig}:{sym}",
                    f"OUTFLOW: {name} sent ${usd:,.0f} {sym}{tag}{extra} on solana. https://solscan.io/tx/{sig}"))
    alerts += fan_in(state, moves, t, cfg)
    return alerts

CHECKS = {"forum": check_forum, "freezes": check_freezes, "proposals": check_freeze_proposals, "tokens": check_tokens,
          "wallets": check_wallets, "discover": discover_wallets, "chains": check_chains, "messages": check_messages,
          "hacks": check_hacks, "sites": check_sites, "news": check_news, "outlets": check_outlets,
          "registers": check_registers, "pages": check_pages, "telegram": check_telegram,
          "solana": check_solana}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--state", default="state.json")
    ap.add_argument("--only", help="comma list of checks to run")
    ap.add_argument("--dry", action="store_true", help="print instead of sending")
    ap.add_argument("--budget", type=float, default=None, help="seconds for all checks (default from config)")
    args = ap.parse_args()
    cfg = merge_private(yaml.safe_load(open(args.config, encoding="utf-8")))
    state = load_state(args.state)
    http, t = Http(), now()
    budget = Budget(args.budget or cfg.get("run_budget_seconds", 38))
    names = args.only.split(",") if args.only else list(CHECKS)
    alerts = []

    def run(name):
        t0 = time.time()
        try:
            got = CHECKS[name](cfg, state, http, t, budget)
            record_health(state, name, True, t)
        except Exception as e:
            log(f"{name} failed: {type(e).__name__}: {e}")
            record_health(state, name, False, t)
            got = []
        print(f"{name}: {len(got)} alerts in {time.time() - t0:.1f}s")
        return got

    # On the very first run the Anjouan register is loaded before the site sweep,
    # so the sweep knows every licensed domain. After that everything runs in parallel.
    parallel = list(names)
    if "registers" in names and not state.get("registers", {}).get("anjouan"):
        alerts += run("registers")
        parallel.remove("registers")
    with ThreadPoolExecutor(max(1, len(parallel))) as ex:
        for got in ex.map(run, parallel):
            alerts += got
    deliver(cfg, state, http, alerts, t, args.dry and not QUIET)
    if ERRORS:
        print("source errors: " + ", ".join(f"{k} {v}" for k, v in sorted(ERRORS.items())))
    state["last_run"] = iso(t)
    save_state(args.state, state)


if __name__ == "__main__":
    main()
