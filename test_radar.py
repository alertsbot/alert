"""Offline tests: feed the rules recorded or reconstructed data from past stories
and check they would have fired. Run: python -m pytest -q tests"""
import datetime as dt
import pytest
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import radar  # noqa: E402

T0 = dt.datetime(2026, 11, 17, 6, 0, tzinfo=dt.timezone.utc)
M30 = dt.timedelta(minutes=30)


class Resp:
    def __init__(self, data=None, text=None, status=200, url="https://x/"):
        self._d = data
        self.text = text if text is not None else json.dumps(data)
        self._snip = self.text
        self.status_code, self.url = status, url

    def json(self):
        return self._d

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(self.status_code)


class FakeHttp:
    def __init__(self, routes):
        self.routes = routes
        self.posts = []

    def _find(self, url):
        for sub, r in self.routes:
            if sub in url:
                return r(url) if callable(r) else r
        raise Exception("no route " + url)

    def get(self, url, **kw):
        return self._find(url)

    snippet = get

    def json(self, url, **kw):
        r = self._find(url)
        r.raise_for_status()
        return r.json()

    def post(self, url, **kw):
        self.posts.append((url, kw))


# ================================================================ Betfin
BETFIN_CLOSES = [("10-12", 1.52e-4), ("10-13", 1.51e-4), ("10-14", 1.32e-4), ("10-15", 9.07e-5),
                 ("10-16", 7.48e-5), ("10-17", 6.66e-5), ("10-18", 5.67e-5), ("10-25", 4.01e-5), ("10-26", 2.02e-6)]


def test_betfin_crash_backtest():
    fired = [d1 for (d0, p0), (d1, p1) in zip(BETFIN_CLOSES, BETFIN_CLOSES[1:])
             if (d1 == "10-26" or int(d1[3:]) - int(d0[3:]) == 1) and (p1 / p0 - 1) * 100 <= -25]
    assert fired[0] == "10-15" and "10-26" in fired


def pool(h6, h24, price="0.0000907"):
    return Resp({"data": [{"attributes": {"address": "0x549bb7e94da23bc31e5fc4685548587f4f7c9b16",
                                          "price_change_percentage": {"h6": str(h6), "h24": str(h24)},
                                          "base_token_price_usd": price}}]})


def test_token_rule_and_cooldown():
    cfg = {"tokens": [{"name": "BET", "network": "polygon_pos", "pool": "0x549bb7e94da23bc31e5fc4685548587f4f7c9b16"}]}
    st = {}
    a = radar.check_tokens(cfg, st, FakeHttp([("geckoterminal", pool(-12, -31))]), T0)
    assert len(a) == 1 and "TOKEN CRASH" in a[0].text
    assert radar.check_tokens(cfg, st, FakeHttp([("geckoterminal", pool(-12, -33))]), T0 + M30) == []


# ================================================================ wallets
def blockscout(native_wei=0, rate=0.6, tokens=()):
    def route(url):
        if url.endswith("/token-balances"):
            return Resp([{"token": {"symbol": s, "decimals": 6, "holders_count": "9000"}, "value": str(int(v * 1e6))}
                         for s, v in tokens])
        return Resp({"coin_balance": str(native_wei), "exchange_rate": str(rate)})
    return route


def test_bankroll_drain_fires(tmp_path):
    cfg = {"wallets": [{"name": "DeGaming bankroll", "chain": "etherlink",
                        "address": "0x90b965Cef6ad8e1E1296b18A5733A06f26678CeE", "kind": "hot", "min_usd": 50000}]}
    st = {}
    h1 = FakeHttp([("etherlink", blockscout(tokens=[("USDSM", 5_260_000)]))])
    assert radar.check_wallets(cfg, st, h1, T0, base_dir=tmp_path) == []
    h2 = FakeHttp([("etherlink", blockscout(tokens=[("USDSM", 219_000)]))])
    a = radar.check_wallets(cfg, st, h2, T0 + M30, base_dir=tmp_path)
    assert len(a) == 1 and "WALLET DRAIN" in a[0].text and "96%" in a[0].text


def test_parked_wallet_move_and_csv(tmp_path):
    (tmp_path / "wallets.csv").write_text("name,chain,address,kind,min_usd\nGamdom attacker,eth,0x4b30,parked,25000\n")
    cfg = {"wallets": []}
    st = {}
    radar.check_wallets(cfg, st, FakeHttp([("eth.blockscout", blockscout(tokens=[("DAI", 952_441)]))]), T0, base_dir=tmp_path)
    a = radar.check_wallets(cfg, st, FakeHttp([("eth.blockscout", blockscout(tokens=[("DAI", 500_000)]))]), T0 + M30, base_dir=tmp_path)
    assert len(a) == 1 and "PARKED MONEY MOVED" in a[0].text


def test_discovered_wallets_rotate(tmp_path):
    st = {"discovered_wallets": {f"eth:0x{i:040x}": {"name": f"Casino {i}", "min_usd": 1} for i in range(150)}}
    cfg = {"wallets": [], "wallets_per_run": 60}
    http = FakeHttp([("eth.blockscout", blockscout(tokens=[("USDC", 1000)]))])
    radar.check_wallets(cfg, st, http, T0, base_dir=tmp_path)
    radar.check_wallets(cfg, st, http, T0 + M30, base_dir=tmp_path)
    radar.check_wallets(cfg, st, http, T0 + 2 * M30, base_dir=tmp_path)
    assert len(st["wallets"]) == 150  # every discovered wallet visited within 3 runs


def test_discovery_skips_deposit_addresses():
    items = [{"type": "metadata_tag", "address_hash": "0xA", "metadata": {"name": "Roobet (0x03cd)"}},
             {"type": "metadata_tag", "address_hash": "0xB", "metadata": {"name": "Roobet: Deposit Address"}},
             {"type": "metadata_tag", "address_hash": "0xC", "metadata": {"name": "Chainlink Staking"}}]
    st = {}
    cfg = {"wallet_brands": ["Roobet"], "discover_chains": ["eth"]}
    radar.discover_wallets(cfg, st, FakeHttp([("search", Resp({"items": items, "next_page_params": None}))]), T0)
    assert list(st["discovered_wallets"]) == ["eth:0xa"]


def test_fake_token_ignored():
    def route(url):
        if url.endswith("/token-balances"):
            return Resp([{"token": {"symbol": "USDC", "decimals": 6, "holders_count": "3"}, "value": str(int(5e11))}])
        return Resp({"coin_balance": "0", "exchange_rate": "3000"})
    total, _ = radar.wallet_usd_blockscout(FakeHttp([("eth.blockscout", route)]), "eth", "0x1")
    assert total == 0


# ================================================================ freezes
def act(i, minute, chain="tron", token="USDT"):
    return {"chain_slug": chain, "token": token, "subject": f"T{i}", "action": "freeze",
            "tx_hash": f"h{i}", "block_time": f"2026-11-17T16:{minute:02d}:00Z"}


def amounts(url):
    sub = url.split("/addresses/")[1].split("?")[0]
    return Resp({"freeze": [{"token": "USDT", "frozen_usd6": {"T1": 9_900_159e6, "T2": 2_400_517e6, "T3": 817_463e6}.get(sub, 1e6)}]})


def test_freeze_batch():
    st = {}
    radar.check_freezes({}, st, FakeHttp([("acts", Resp({"items": [act(0, 1)]}))]), T0)
    http = FakeHttp([("acts", Resp({"items": [act(0, 1), act(1, 16), act(2, 16), act(3, 17)]})), ("/v1/addresses/", amounts)])
    a = radar.check_freezes({}, st, http, T0 + dt.timedelta(hours=1))
    assert len(a) == 1 and "3 USDT freezes on tron" in a[0].text and "13,118,139" in a[0].text


# ================================================================ sites
ANJ = {"ALSI-202411002-FI1": {"company": "ONCHAIN Technologies Ltd", "status": "valid",
        "domains": ["betmode.io", "luckycoin.com", "feinbet.com", "gambid.gg", "hashjack.io"]},
       "ALSI-1": {"company": "Other Ltd", "status": "valid", "domains": ["other.com"]}}
OK_PAGE = "<title>Casino</title>" + "word " * 500
MAINT = "<title>Under maintenance</title>We'll be back soon"


def site_http(pages):
    return FakeHttp([("https://", lambda url: Resp(text=pages.get(url.replace("https://", ""), OK_PAGE), url=url))])


def test_licence_cluster_betmode_pattern():
    """Betmode: brands under one Anjouan licence go down together. The sweep only
    hits some of them, but rechecks the whole licence next run and groups them."""
    st = {"registers": {"anjouan": json.loads(json.dumps(ANJ))}}
    cfg = {"sites": [], "site_rules": {"rotation_per_run": 2, "cluster_min": 3}}
    pages = {}
    http = site_http(pages)
    for i in range(4):  # baseline sweep of all 6 domains
        radar.check_sites(cfg, st, http, T0 + i * M30)
    assert len(st["sites"]) == 6
    for d in ANJ["ALSI-202411002-FI1"]["domains"]:
        pages[d] = MAINT
    alerts = []
    for i in range(4, 8):
        alerts += radar.check_sites(cfg, st, http, T0 + i * M30)
    cl = [a for a in alerts if "LICENCE CLUSTER DOWN" in a.text]
    assert cl and "ALSI-202411002-FI1" in cl[0].text and "ONCHAIN" in cl[0].text


def test_priority_site_down_is_high():
    cfg = {"sites": ["stake.com"]}
    st, pages = {}, {}
    http = site_http(pages)
    radar.check_sites(cfg, st, http, T0)
    pages["stake.com"] = MAINT
    assert radar.check_sites(cfg, st, http, T0 + M30) == []  # suspect, recheck
    a = radar.check_sites(cfg, st, http, T0 + 2 * M30)
    assert len(a) == 1 and a[0].level == "HIGH" and "stake.com is maintenance" in a[0].text


def test_bot_check_and_geo_block_ignored():
    cfg = {"sites": ["roobet.com"]}
    st = {}
    http = FakeHttp([("https://", Resp(text="<title>Just a moment...</title>", status=403))])
    for i in range(3):
        assert radar.check_sites(cfg, st, http, T0 + i * M30) == []


def test_sites_down_at_start_do_not_alert():
    cfg = {"sites": ["betmode.io"]}
    st = {}
    http = FakeHttp([("https://", Resp(text=MAINT))])
    for i in range(3):
        assert radar.check_sites(cfg, st, http, T0 + i * M30) == []


# ================================================================ registers
def test_register_diff_mirror_brands():
    """Rabocse banned in Sweden; Exceptiosoft later licensed with copies of its brands."""
    old = {"ALSI-202412035-FI2": {"company": "Rabocse SRL", "status": "valid",
           "domains": ["gxmble.io", "palmcasino.io", "seven7.casino", "slottio.com", "wildzy.io", "winzter.com"]}}
    new = dict(old)
    new["ALSI-202606020-FI1"] = {"company": "Exceptiosoft LTD", "status": "valid",
        "domains": ["gxmble-casino.io", "thepalmcasino.io", "slottio.io", "wildzycasino.io", "winztercasino.io", "rivo.casino"]}
    a = radar.diff_register("anjouan", old, new, [], T0)
    m = [x for x in a if "COPIED BRANDS" in x.text]
    assert m and "Rabocse" in m[0].text and m[0].level == "HIGH"


def test_register_diff_removed_and_status():
    old = {"A1": {"company": "X", "status": "valid", "domains": ["stake.com"]},
           "A2": {"company": "Y", "status": "valid", "domains": ["y.com"]}}
    new = {"A2": {"company": "Y", "status": "revoked", "domains": ["y.com"]}}
    a = radar.diff_register("anjouan", old, new, ["stake"], T0)
    txt = " | ".join(x.text for x in a)
    assert "LICENCE GONE" in txt and "STATUS CHANGE" in txt
    assert all(x.level == "HIGH" for x in a)


def test_anjouan_parser():
    page = ('<html><script id="ag-licence-data" type="application/json">'
            '[{"company":"ONCHAIN Technologies Ltd","status":"valid","number":"ALSI-202411002-FI1","type":"b2b & b2c",'
            '"issued":"2024-11-01","expiry":"2027-10-31","domains":"betmode.io, www.LuckyCoin.com"}]</script></html>')
    out = radar.fetch_anjouan(FakeHttp([("anjouangaming", Resp(text=page))]))
    assert out["ALSI-202411002-FI1"]["domains"] == ["betmode.io", "luckycoin.com"]


def test_curacao_parser():
    page = """<div>Certificate B2C</div><p>Application status: Granted. License status: Active.</p>
    <p>This is to certify that Innovex B.V., a company incorporated under the laws of Curaçao with Company Number 165563
    is licensed by the Curaçao Gaming Control Board since 22/Nov/2024 to offer games of chance under license number
    OGL/2024/1769/1016 in accordance with the National Ordinance</p><h3>Approved domains</h3>
    <p>The licensee has been granted approval to operate the following domains under its license:</p>
    <ul><li>20bet.tech</li><li>dragonslots.com</li><li>slotrave.com</li></ul><footer>Copyright 2026</footer>"""
    r = radar.parse_cga(page)
    assert r["number"] == "OGL/2024/1769/1016" and r["company"] == "Innovex B.V." and r["status"] == "active"
    assert r["domains"] == ["20bet.tech", "dragonslots.com", "slotrave.com"]


# ================================================================ news
RSS = "<rss><channel>{}</channel></rss>"
ITEM = "<item><title>{}</title><link>https://x/{}</link><pubDate>{}</pubDate><source url='x'>{}</source></item>"


def test_czech_news_fires_after_first_run():
    cfg = {"news": {"brands": ["Betfin"], "queries_per_run": 10, "editions": [
        {"lang": "cs", "country": "CZ", "words": ["celníci", "zadrželi"]}]}}
    st = {}
    old = RSS.format(ITEM.format("Starý článek o Betfinu", 1, "Mon, 13 Oct 2026 07:00:00 GMT", "Seznam Zprávy"))
    radar.check_news(cfg, st, FakeHttp([("news.google", Resp(text=old))]), dt.datetime(2026, 10, 14, 8, tzinfo=dt.timezone.utc))
    new = RSS.format(ITEM.format("Celníci zadrželi youtubery spojené s kryptoměnovým kasinem Betfin - Seznam Zprávy", 2,
                                 "Thu, 15 Oct 2026 07:00:00 GMT", "Seznam Zprávy"))
    a = radar.check_news(cfg, st, FakeHttp([("news.google", Resp(text=new))]), dt.datetime(2026, 10, 15, 7, 37, tzinfo=dt.timezone.utc))
    assert len(a) == 1 and a[0].level == "HIGH" and "[cs]" in a[0].text


def test_generic_news_low_unless_hot_word():
    cfg = {"news": {"brands": ["Stake.com"], "hot_words": ["kripto"], "queries_per_run": 10, "editions": [
        {"lang": "tr", "country": "TR", "words": [], "queries": ["yasa dışı bahis operasyon"]}]}}
    st = {"news": {"seen": ["x"]}}
    items = RSS.format(ITEM.format("Yasa dışı bahis operasyonu: 12 gözaltı", 1, "Thu, 15 Oct 2026 07:00:00 GMT", "Hürriyet") +
                       ITEM.format("Kripto bahis çetesine operasyon", 2, "Thu, 15 Oct 2026 07:00:00 GMT", "Sabah"))
    # only the generic query runs here (brand chunk comes on the next rotation)
    a = radar.check_news(cfg, st, FakeHttp([("news.google", Resp(text=items))]), dt.datetime(2026, 10, 15, 9, tzinfo=dt.timezone.utc))
    levels = {x.text.split("] ")[1].split(" (")[0]: x.level for x in a}
    assert levels["Kripto bahis çetesine operasyon"] == "HIGH"
    assert levels["Yasa dışı bahis operasyonu: 12 gözaltı"] in ("LOW", "HIGH")


def test_news_rotation_covers_all_queries():
    ncfg = {"brands": [f"b{i}" for i in range(25)], "brands_per_query": 10,
            "editions": [{"lang": "cs", "country": "CZ", "queries": ["a", "b"]}, {"lang": "th", "country": "TH"}]}
    jobs = radar.news_jobs(ncfg)
    assert len(jobs) == 2 + 3 + 3
    st = {}
    seen = set()
    for _ in range(3):
        seen |= {j[1] for j in radar.rotate(jobs, st, "news", 3)}
    assert len(seen) == len({j[1] for j in jobs})


# ================================================================ forum
def board(*topics):
    return Resp(text="".join(f'<span id="msg_{i}"><a href="https://bitcointalk.org/index.php?topic={i}.0">{t}</a></span>'
                             for i, t in topics))


def test_forum_brand_scam_and_repeat():
    cfg = {"forum": {"boards": [83], "brands": ["betski", "stake"]}}
    st = {}
    radar.check_forum(cfg, st, FakeHttp([("bitcointalk", board((1, "old thread")))]), T0)
    a = radar.check_forum(cfg, st, FakeHttp([("bitcointalk", board((2, "Betski - withdrawal issue")))]), T0)
    assert a[0].level == "HIGH"  # brand + scam word on the scam board
    a = radar.check_forum(cfg, st, FakeHttp([("bitcointalk", board((3, "BETSKI is not processing withdrawals")))]), T0 + dt.timedelta(days=2))
    assert "2 scam threads on betski" in a[0].text
    a = radar.check_forum(cfg, st, FakeHttp([("bitcointalk", board((4, "My mistake with a withdraw")))]), T0)
    assert a[0].level == "LOW" and "threads on" not in a[0].text


# ================================================================ pages
def test_pages_new_link():
    cfg = {"pages": {"every_minutes": 0, "list": [{"name": "UKGC", "url": "https://gc/x", "link_pattern": "/detail/", "high": True}]}}
    st = {}
    p1 = '<a href="/public-statement/detail/a">A ltd fined</a>'
    radar.check_pages(cfg, st, FakeHttp([("gc", Resp(text=p1))]), T0)
    p2 = p1 + '<a href="/public-statement/detail/b">B ltd licence suspended</a>'
    a = radar.check_pages(cfg, st, FakeHttp([("gc", Resp(text=p2))]), T0 + M30)
    assert len(a) == 1 and "B ltd licence suspended" in a[0].text and a[0].level == "HIGH"


# ================================================================ delivery
MIX = {"chains": {"mixers": {"0xtornado": "Tornado router"}}, "forum": {"brands": ["betmode", "Stake"]},
       "news": {"editions": [{"lang": "cs", "words": ["policie", "obviněn", "pokuta"]}]}, "outlets": {}}


@pytest.mark.parametrize("check,key,level,text,want", [
    ("chain", "out:1", "HIGH", "OUTFLOW: Betmode bankroll sent $5,260,000 USDSM to a FRESH address (0 txs) on etherlink.", True),
    ("chain", "out:2", "HIGH", "OUTFLOW: Duelbits hot sent $900,000 USDT to Tornado router on eth.", True),
    ("chain", "out:3", "HIGH", "OUTFLOW: Gamdom 1 (PARKED) sent $300,000 ETH on eth.", True),
    ("chain", "out:4", "HIGH", "BIG PAYOUT: Stake hot sent $3,000,000 USDT to 0xabc on eth (possible big win).", False),
    ("chain", "drain:1", "HIGH", "DRAIN: Betfin pool sent 85% of its BET balance on etherlink.", True),
    ("message", "msg:1", "HIGH", "MESSAGE to attacker wallet: please return funds", True),
    ("message", "msg:2", "LOW", "MESSAGE to Stake hot: gm", False),
    ("sites", "site:a", "HIGH", "stake.com is notice: withdrawals paused", True),
    ("sites", "site:b", "LOW", "smallcasino.io is down: timeout", False),
    ("register", "reg:anj:gone:1", "HIGH", "LICENCE GONE: Betfin removed from Anjouan register", True),
    ("register", "reg:anj:new:1", "LOW", "NEW LICENCE: Foo Casino", False),
    ("news", "n:1", "LOW", "Policie obviněn provozovatel Betmode https://x/1", True),
    ("news", "n:2", "LOW", "Betmode pokuta od úřadu https://x/2", False),
    ("news", "n:3", "LOW", "Stake launches new slot https://x/3", False),
    ("forum", "bt:1", "LOW", "2 scam threads on Betmode this week", True),
    ("telegram", "tg:1", "HIGH", "[casino channel t.me/stake/1] withdrawals paused", True),
    ("telegram", "tg:2", "LOW", "[t.me/tracker/2] new casino promo", False),
    ("pages", "pg:1", "LOW", "UKGC: new fine for operator", False),
])
def test_urgency_rules(check, key, level, text, want):
    assert radar.is_urgent(MIX, radar.Alert(level, check, key, text)) is want


def test_deliver_update_urgent_and_report(capsys):
    st = {}
    cfg = dict(MIX, telegram={"report_every_hours": 5})
    t = dt.datetime(2026, 11, 21, 6, 0, tzinfo=dt.timezone.utc)
    al = [radar.Alert("HIGH", "chain", "out:1", "OUTFLOW: Betmode bankroll sent $5,260,000 USDSM to a FRESH address (0 txs) on etherlink. https://explorer.etherlink.com/tx/0x1"),
          radar.Alert("LOW", "forum", "bt:9", "BitcoinTalk: Casino X slow withdrawals https://bitcointalk.org/index.php?topic=1.0")]
    radar.deliver(cfg, st, FakeHttp([]), al, t, dry=True)
    out = capsys.readouterr().out
    first = out.split("\n\n")[0]
    assert first.startswith("🚨 <b>URGENT</b>") and "#urgent" in out and "#betmode" in out
    assert "🛰 <b>Update</b>" in out and "Casino X slow withdrawals" in out
    assert out.index("🚨") < out.index("🛰")  # urgent first
    # same alerts again: nothing sent
    radar.deliver(cfg, st, FakeHttp([]), al, t + dt.timedelta(minutes=10), dry=True)
    assert capsys.readouterr().out == ""
    radar.deliver(cfg, st, FakeHttp([]), [radar.Alert("LOW", "sites", "site:x", "x.com is down: timeout")], t + dt.timedelta(hours=2), dry=True)
    out = capsys.readouterr().out
    assert "🛰" in out and "x.com is down" in out and "🚨" not in out
    # 5 hours later: report with every story once, urgent section on top
    radar.deliver(cfg, st, FakeHttp([]), [], t + dt.timedelta(hours=5), dry=True)
    out = capsys.readouterr().out
    assert "📚 <b>5-hour report</b>" in out and "3 stories, 1 urgent" in out
    assert out.index("🚨 <b>URGENT</b>") < out.index("x.com is down")
    assert out.count("Casino X slow withdrawals") == 1 and "#report" in out


def test_same_news_from_many_outlets_is_one_story(capsys):
    st = {}
    cfg = dict(MIX, telegram={"report_every_hours": 5})
    t = dt.datetime(2026, 11, 21, 6, 0, tzinfo=dt.timezone.utc)
    titles = ["Czech police charge 15 over Betfin crypto casino - Seznam",
              "Czech police charge 15 people over Betfin crypto casino - iDnes",
              "Betfin crypto casino: Czech police charge 15 - Novinky"]
    al = [radar.Alert("LOW", "outlets", f"o:{i}", f"{x} https://site{i}.cz/a") for i, x in enumerate(titles)]
    radar.deliver(cfg, st, FakeHttp([]), al[:1], t, dry=True)
    capsys.readouterr()
    radar.deliver(cfg, st, FakeHttp([]), al[1:], t + dt.timedelta(minutes=10), dry=True)
    assert capsys.readouterr().out == ""  # later outlets only add sources
    radar.deliver(cfg, st, FakeHttp([]), [], t + dt.timedelta(hours=5), dry=True)
    out = capsys.readouterr().out
    assert "(+2 sources)" in out and "1 stories" in out


def test_telegram_send_html_silent_topic(monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "1")
    monkeypatch.setattr(radar.time, "sleep", lambda s: None)
    http = FakeHttp([])
    radar.send_telegram(http, "hello", {"telegram": {"topics": {"updates": 7}}}, "updates", silent=True)
    url, kw = http.posts[0]
    assert kw["data"]["disable_notification"] == "true" and kw["data"]["message_thread_id"] == "7" and kw["data"]["parse_mode"] == "HTML"


# ================================================================ chain watcher
class RpcHttp(FakeHttp):
    """Fake JSON-RPC node: answers eth_blockNumber, eth_getLogs, eth_call, nonce, code."""
    def __init__(self, head, logs, nonces=None, balances=None, routes=()):
        super().__init__(list(routes))
        self.head, self.logs, self.nonces, self.balances = head, logs, nonces or {}, balances or {}

    def post(self, url, json=None, **kw):
        m, p = json["method"], json["params"]
        if m == "eth_blockNumber":
            r = hex(self.head)
        elif m == "eth_getLogs":
            f = p[0]
            addrs = f["address"] if isinstance(f["address"], list) else [f["address"]]
            t1 = f["topics"][1] if len(f["topics"]) > 1 else None
            t1 = t1 if isinstance(t1, list) or t1 is None else [t1]
            r = [l for l in self.logs if l["address"].lower() in [a.lower() for a in addrs]
                 and (f["topics"][0] == l["topics"][0] or (isinstance(f["topics"][0], list) and l["topics"][0] in f["topics"][0]))
                 and (t1 is None or l["topics"][1] in t1)
                 and int(f["fromBlock"], 16) <= l["block"] <= int(f["toBlock"], 16)]
        elif m == "eth_getTransactionCount":
            r = hex(self.nonces.get(p[0].lower(), 100))
        elif m == "eth_getCode":
            r = "0x"
        elif m == "eth_call":
            r = hex(self.balances.get(p[0]["to"].lower(), 0))
        return Resp({"jsonrpc": "2.0", "id": 1, "result": r})


def tlog(token, frm, to, amount, block, tx="0xabc", topic=radar.TOPIC["Transfer"]):
    return {"address": token, "topics": [topic, radar.pad(frm), radar.pad(to)], "data": hex(amount),
            "block": block, "transactionHash": tx, "logIndex": "0x1"}


USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
HOT = "0x014435b1e39945cf4f5f0c3cbb5833195a95cc9b"


def test_hot_wallet_to_fresh_address(tmp_path):
    """Duelbits shape: hot wallet sends a big amount to a brand new address."""
    cfg = {"wallets": [{"name": "Duelbits hot wallet", "chain": "eth", "address": HOT, "kind": "hot"}], "chains": {}}
    st = {}
    radar.check_chains(cfg, st, RpcHttp(100, []), T0, base_dir=tmp_path)  # first run sets cursor
    logs = [tlog(USDT, HOT, "0x" + "ab" * 20, 900_000 * 10**6, 150, tx="0xdrain"),
            tlog(USDT, HOT, "0x" + "cd" * 20, 1_000 * 10**6, 151)]
    a = radar.check_chains(cfg, st, RpcHttp(200, logs, nonces={"0x" + "ab" * 20: 0}), T0 + M30, base_dir=tmp_path)
    assert len(a) == 1 and a[0].level == "HIGH" and "FRESH" in a[0].text and "$900,000" in a[0].text
    assert st["chainwatch"]["eth"] == 200


def test_parked_wallet_to_tornado(tmp_path):
    cfg = {"wallets": [{"name": "Gamdom attacker", "chain": "eth", "address": "0x4b304741599c125a244e498d14562487d7109ab8",
                        "kind": "parked", "min_usd": 10000}],
           "chains": {"mixers": {"0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash router"}}}
    st = {"chainwatch": {"eth": 99}}
    logs = [tlog("0x6b175474e89094c44da98b954eedeac495271d0f", "0x4b304741599c125a244e498d14562487d7109ab8",
                 "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", 100_000 * 10**18, 120)]
    a = radar.check_chains(cfg, st, RpcHttp(200, logs), T0, base_dir=tmp_path)
    assert len(a) == 1 and "Tornado Cash router" in a[0].text and a[0].level == "HIGH"


def test_betfin_liquidity_pool_drain_replay(tmp_path):
    """Oct 25: 34.99B BET left the Betfin Liquidity Pool, 888M left behind (97.5%)."""
    BET = "0xbf7970d56a150cd0b60bd08388a4a75a27777777"
    LP = "0xbfb31f7f7f8e062d10e1b1c11a5d4fe9c4bc158a"
    cfg = {"wallets": [], "contracts": [{"name": "Betfin Liquidity Pool", "chain": "polygon", "address": LP, "tokens": [BET]}]}
    st = {"chainwatch": {"polygon": 1000}}
    logs = [tlog(BET, LP, "0xf87bb9e51ef3996bd9646972398e41dba7114119", 34_989_778_623 * 10**18, 1500, tx="0x04f5")]
    a = radar.check_chains(cfg, st, RpcHttp(2000, logs, balances={BET: 888_193_646 * 10**18}), T0, base_dir=tmp_path)
    assert len(a) == 1 and "CONTRACT DRAINED" in a[0].text and "98%" in a[0].text


def test_contract_admin_event(tmp_path):
    C = "0x5b64011a575d37a682107a7b3c6121ca4e2ca877"
    cfg = {"wallets": [], "contracts": [{"name": "DeGaming factory", "chain": "etherlink", "address": C}]}
    st = {"chainwatch": {"etherlink": 10}}
    logs = [{"address": C, "topics": [radar.TOPIC["OwnershipTransferred"], radar.pad("0x1"), radar.pad("0x2")], "data": "0x",
             "block": 20, "transactionHash": "0xown", "logIndex": "0x0"}]
    a = radar.check_chains(cfg, st, RpcHttp(30, logs), T0, base_dir=tmp_path)
    assert len(a) == 1 and "OWNERSHIPTRANSFERRED" in a[0].text


# ================================================================ messages, hacks, proposals
ONCHAIN_MSG = ("Please stop further transfers or swaps and contact operations@onchaintechnologies.io to discuss "
               "the safe return of the funds and a potential reward payment.")


def test_decode_message():
    assert radar.decode_message("0x" + ONCHAIN_MSG.encode().hex()) == ONCHAIN_MSG
    assert radar.decode_message("0xa9059cbb000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd") is None
    assert radar.decode_message("0x") is None


def test_onchain_message_to_attacker(tmp_path):
    cfg = {"wallets": [{"name": "Betmode attacker", "chain": "etherlink", "address": "0x8a54", "kind": "parked"}]}
    st = {}
    radar.check_messages(cfg, st, FakeHttp([("transactions", Resp({"items": [{"hash": "0x1", "raw_input": "0x"}]}))]), T0, base_dir=tmp_path)
    items = [{"hash": "0x2", "raw_input": "0x" + ONCHAIN_MSG.encode().hex(), "from": {"hash": "0x5a15"}}]
    a = radar.check_messages(cfg, st, FakeHttp([("transactions", Resp({"items": items}))]), T0 + M30, base_dir=tmp_path)
    assert len(a) == 1 and "ON-CHAIN MESSAGE to Betmode attacker" in a[0].text and "safe return" in a[0].text


def test_hacks_feed():
    st = {}
    radar.check_hacks({"hacks": {"every_minutes": 0}}, st, FakeHttp([("llama", Resp([{"name": "Old", "date": 1}]))]), T0)
    rows = [{"name": "Old", "date": 1},
            {"name": "DeGaming bankroll", "date": 1795392000, "amount": 5260000, "chain": ["Etherlink"], "targetType": "Gambling",
             "technique": "Private Key Compromised"},
            {"name": "Some DEX", "date": 1795392000, "amount": 300000, "chain": ["Base"], "targetType": "DeFi Protocol"}]
    a = radar.check_hacks({"hacks": {"every_minutes": 0}}, st, FakeHttp([("llama", Resp(rows))]), T0 + M30)
    lv = {x.text.split(":")[1].split("(")[0].strip(): x.level for x in a}
    assert lv["DeGaming bankroll"] == "HIGH" and lv["Some DEX"] == "LOW"


def test_freeze_proposal_seize():
    st = {}
    radar.check_freeze_proposals({}, st, FakeHttp([("proposals", Resp({"items": []}))]), T0)
    st["proposals"]["seen"] = ["x"]
    p = [{"token": "USDT", "action": "seize", "selector": "destroyBlackFunds", "status": "pending",
          "confirmations": 1, "required": 2, "submitted_at": "2026-11-20T19:22:00Z"}]
    a = radar.check_freeze_proposals({"freeze_rules": {"proposal_chains": ["tron"]}}, st, FakeHttp([("proposals", Resp({"items": p}))]), T0)
    assert len(a) == 1 and a[0].level == "HIGH" and "PENDING USDT SEIZE" in a[0].text


# ================================================================ outlets
FEED = """<rss><channel>
<item><title>Celníci zadrželi youtubery spojené s kryptoměnovým kasinem Betfin</title><link>https://x/1</link>
<pubDate>Thu, 15 Oct 2026 07:00:00 GMT</pubDate></item>
<item><title><![CDATA[Crypto casino bankroll drained by attacker]]></title><link>https://x/2</link>
<pubDate>Thu, 15 Oct 2026 07:00:00 GMT</pubDate></item>
<item><title>Weather is nice today</title><link>https://x/3</link><pubDate>Thu, 15 Oct 2026 07:00:00 GMT</pubDate></item>
</channel></rss>"""


def test_parse_feed_rss_and_atom():
    assert [i["title"][:9] for i in radar.parse_feed(FEED)] == ["Celníci z", "Crypto ca", "Weather i"]
    atom = '<feed><entry><title>Kalshi hearing</title><link href="https://y/1"/><updated>2026-11-21T10:00:00Z</updated></entry></feed>'
    assert radar.parse_feed(atom)[0]["link"] == "https://y/1"


def test_outlets_rotation_and_matching(tmp_path):
    (tmp_path / "outlets.txt").write_text("https://cz.example/rss cc:CZ\nhttps://sec.example/feed security\n")
    cfg = {"news": {"brands": ["Betfin"], "editions": [{"lang": "cs", "country": "CZ", "words": ["zadrželi"]}]},
           "forum": {"brands": []}, "outlets": {"feeds_per_run": 10, "trigger_words": ["drained"]}}
    st = {}
    t = dt.datetime(2026, 10, 15, 6, 0, tzinfo=dt.timezone.utc)
    http = FakeHttp([("example", Resp(text="<rss></rss>"))])
    radar.check_outlets(cfg, st, http, t, base_dir=tmp_path)  # discovery + baseline
    st["outlets"]["seen"] = ["seed"]
    sec_feed = FEED.replace("https://x/", "https://sec/")
    a = radar.check_outlets(cfg, st, FakeHttp([("cz.example", Resp(text=FEED)), ("sec.example", Resp(text=sec_feed))]),
                            t + dt.timedelta(hours=2), base_dir=tmp_path)
    texts = {x.text.split("] ")[1][:20]: (x.level, x.text.split("]")[0]) for x in a}
    assert texts["Celníci zadrželi you"][0] == "HIGH"          # brand + Czech trigger word
    assert ("Crypto casino bankro" in texts) and texts["Crypto casino bankro"][0] == "HIGH"  # security outlet, gambling + trigger
    assert not any("Weather" in k for k in texts)


def test_discover_feed_from_homepage():
    page = '<html><head><link rel="alternate" type="application/rss+xml" href="/feeds/all.xml"></head></html>'
    http = FakeHttp([("news.example", Resp(text=page, url="https://news.example/"))])
    assert radar.discover_feed(http, "news.example") == "https://news.example/feeds/all.xml"


# ================================================================ v4 additions
def test_site_notice_and_move():
    page = "<title>Casino</title>" + "word " * 500 + " Withdrawals are temporarily paused while we investigate."
    http = FakeHttp([("https://", Resp(text=page, url="https://stake.com/"))])
    assert radar.classify_site(http, "stake.com")[0] == "notice"
    http = FakeHttp([("https://", Resp(text=OK_PAGE, url="https://newbrand.io/"))])
    s, why = radar.classify_site(http, "oldcasino.com")
    assert s == "moved" and "newbrand.io" in why


def test_freeze_linked_to_casino(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = {"wallets": [{"name": "Stake.com hot wallet", "chain": "eth", "address": "0x974caa59e49682cda0ad2bbe82983419a2ecc400"}]}
    st = {}
    radar.check_freezes(cfg, st, FakeHttp([("acts", Resp({"items": [act(0, 1)]}))]), T0)

    def route(url):
        if "/graph" in url:
            return Resp({"nodes": [{"hop": 1, "address": "0x974CAA59e49682CdA0AD2bbe82983419A2ECC400"}]})
        return Resp({"freeze": [{"token": "USDT", "frozen_usd6": 50_000e6}]})
    http = FakeHttp([("acts", Resp({"items": [act(0, 1), act(9, 30)]})), ("/v1/addresses/", route)])
    a = radar.check_freezes(cfg, st, http, T0 + M30)
    assert any("LINKED TO A CASINO" in x.text and "Stake.com" in x.text for x in a)


def test_big_payout_from_hot_wallet(tmp_path):
    cfg = {"wallets": [{"name": "Stake.com hot wallet", "chain": "eth", "address": HOT, "kind": "hot"}], "chains": {}}
    st = {"chainwatch": {"eth": 100}}
    logs = [tlog(USDT, HOT, "0x" + "ee" * 20, 3_000_000 * 10**6, 150)]
    a = radar.check_chains(cfg, st, RpcHttp(200, logs, nonces={"0x" + "ee" * 20: 500}), T0, base_dir=tmp_path)
    assert len(a) == 1 and a[0].level == "HIGH" and "big win payout" in a[0].text


def test_telegram_channel_parse():
    page = ('<div class="tgme_widget_message" data-post="stakecom/101"><div class="tgme_widget_message_text js-message_text" dir="auto">'
            'Withdrawals are temporarily paused due to maintenance.</div></div>')
    cfg = {"telegram_channels": {"list": [{"name": "stakecom", "kind": "casino"}]}, "news": {"brands": ["Stake.com"]},
           "forum": {"brands": []}, "outlets": {"trigger_words": ["paused"]}}
    st = {"tg": {"seen": ["x"]}}
    a = radar.check_telegram(cfg, st, FakeHttp([("t.me", Resp(text=page))]), T0)
    assert len(a) == 1 and a[0].level == "HIGH" and "stakecom/101" in a[0].text


def test_private_merge_and_csv(monkeypatch, tmp_path):
    monkeypatch.setenv("RADAR_PRIVATE_YAML", "wallets:\n  - {name: Secret lead, chain: eth, address: '0xabc', kind: parked}\n")
    monkeypatch.setenv("RADAR_WALLETS_CSV", "CSV lead,polygon,0xdef,parked,1000")
    cfg = radar.merge_private({"wallets": [{"name": "Public", "chain": "eth", "address": "0x1"}]})
    pinned, _ = radar.load_wallets(cfg, {}, tmp_path)
    assert {w["name"] for w in pinned} == {"Public", "Secret lead", "CSV lead"}


def test_learned_outlets_from_google_news(tmp_path):
    rss = RSS.format("<item><title>Policie zadržela provozovatele kasina</title><link>https://x/9</link>"
                     "<pubDate>Thu, 15 Oct 2026 07:00:00 GMT</pubDate><source url=\"https://www.krimi-zpravy.cz\">Krimi</source></item>")
    cfg = {"news": {"brands": ["Betfin"], "queries_per_run": 10, "editions": [{"lang": "cs", "country": "CZ", "words": ["policie"]}]},
           "outlets": {"files": ["none.txt"]}}
    st = {}
    radar.check_news(cfg, st, FakeHttp([("news.google", Resp(text=rss))]), T0)
    assert "krimi-zpravy.cz" in st["learned_outlets"]
    assert any(o["src"] == "krimi-zpravy.cz" for o in radar.load_outlets(cfg, tmp_path, st))


def test_state_encryption(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_STATE_KEY", "secret key")
    p = str(tmp_path / "state.json")
    radar.save_state(p, {"digest": ["private lead"]})
    assert b"private lead" not in open(p, "rb").read()
    assert radar.load_state(p) == {"digest": ["private lead"]}
    monkeypatch.setenv("RADAR_STATE_KEY", "wrong")
    assert radar.load_state(p) == {}


def test_deposit_collapse_flags_betfin_shape():
    t = dt.datetime(2026, 11, 21, 6, 0, tzinfo=dt.timezone.utc)
    days = {(t - dt.timedelta(days=d)).strftime("%Y-%m-%d"): 400000 for d in range(2, 9)}
    days[(t - dt.timedelta(days=1)).strftime("%Y-%m-%d")] = 30000
    st = {"flows": {"etherlink:0xbank": days}}
    w = {"etherlink": {"0xbank": ("Betfin bankroll", "hot", 0)}}
    a = radar.deposit_drops({}, st, w, t)
    assert len(a) == 1 and "DEPOSITS COLLAPSED" in a[0].text and "92%" in a[0].text
    assert radar.is_urgent({}, a[0])
    assert radar.deposit_drops({}, st, w, t) == []  # once a day
    st2 = {"flows": {"etherlink:0xbank": {(t - dt.timedelta(days=1)).strftime("%Y-%m-%d"): 1}}}
    assert radar.deposit_drops({}, st2, w, t) == []  # not enough history


def test_seizure_banner_is_urgent():
    class H:
        def snippet(self, url):
            r = Resp(text="<html><title>Seized</title>This domain has been seized by the FBI</html>")
            r.url, r._snip = url, r.text
            return r
    assert radar.classify_site(H(), "badcasino.io")[0] == "seized"
    assert radar.is_urgent({}, radar.Alert("LOW", "sites", "site:badcasino.io:1", "badcasino.io is seized: page shows a seizure banner"))
