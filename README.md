# Casino radar

Watches casinos, their wallets and contracts, freezes, hacks, licences, forums and news in dozens of
languages, and messages you on Telegram. Runs every 10 minutes on GitHub for free. No AI.

## What you get on Telegram

- **🚨 URGENT**: its own message, with sound, the moment it is found. Every urgent message starts with 🚨 URGENT.
- **🛰 Update** (every 10 minutes, only when something is new): one short line per story, grouped by type, silent.
- **📚 5-hour report**: every story from the last 5 hours, each story once, urgent ones on top, plus any check that stopped working.

The same story from several outlets or checks is merged into one line with "(+N sources)", never sent twice.
Search Telegram for `#urgent`, `#report`, `#onchain`, `#news` or a brand tag like `#betfin` to find past items.

### What counts as urgent

| Area | Urgent when |
|---|---|
| On-chain | casino contract drained, owner/admin changed, upgraded or paused; parked hack money moves; casino wallet sends $250K+ to a brand-new address or a mixer/bridge; hot wallet or bankroll loses 60% in 24h; **deposits into a casino wallet fall 75%+ against its 7-day average** |
| Messages | on-chain message to or from a hack or attacker wallet |
| Sites | several brands on one licence down together; 8+ casinos down at once; priority casino down or in maintenance; **any** casino showing "withdrawals paused", "closing", "security incident" or a **seizure banner** |
| Freezes | a frozen wallet that traded with a casino wallet |
| Hacks | new hack logged on a gambling target |
| Tokens | casino token −25% in 24h |
| Licences | known brand's licence removed or status changed |
| News | casino brand in the same headline as hack, exploit, drained, stolen, arrested, raid, charged, detained, seized, frozen, insolvent, shut down or withdrawals paused (in every language listed) |
| Forum | second scam thread on the same casino within a week |
| Telegram | a casino's own channel posting maintenance, withdrawal or hack news |

Everything else (big win payouts, fines, lawsuits, new licences) goes in the update. Change thresholds in `config.yaml`.

## What it covers

| Check | Scale | Fires when |
|---|---|---|
| **chains** | every new block on 7 chains (Ethereum, Polygon, BNB, Arbitrum, Base, Optimism, Etherlink); all watched wallets in one request per chain | watched wallet sends $250K+ to a **fresh address** or a **mixer/bridge**; casino wallet pays $2M+ (possible big win); watched contract changes owner/role, is upgraded or paused, or **sends out most of a token balance** (Betfin pool drain) |
| **messages** | latest transactions of every watched wallet | readable text sent to or from a watched wallet (hack negotiations) |
| **deposits** | daily deposits into every hot wallet and bankroll | deposits yesterday 75%+ below the 7-day average (the Betfin pattern) |
| **wallets** | pinned + private list + every casino wallet labelled on Blockscout (116 brands, 4 chains, refreshed weekly) | hot wallet or bankroll loses 60% in 24h; parked money moves |
| **freezes** | every USDT/USDC freeze on 7 chains + Tether's **pending** proposals | freeze batches; big freezes; a pending seizure; **a frozen wallet that traded with a casino wallet** |
| **hacks** | DefiLlama hack database | new hack logged; gambling or $20M+ is urgent |
| **tokens** | casino tokens | −20% in 6h or −25% in 24h |
| **sites** | ~105 priority casinos + every Anjouan and Curaçao domain (~4,500), full sweep about every 30 min | maintenance, down, parked, **withdrawals paused / closing / security notice**, or **redirects to a new domain**; several on one licence = licence cluster |
| **registers** | Anjouan (1,292 licences) every 6h, Curaçao certificates continuously | licence gone, status change, domains dropped, new licence with **copied brands** |
| **outlets** | **1,270 outlet feeds** in 140 countries + every outlet Google News shows us (learned automatically, up to 8,000) + Reddit + court dockets | casino brand next to a trigger word; security/iGaming/court sources on any gambling story |
| **news** | Google News in 41 editions, ~470 searches in rotation | brand + local trigger words |
| **telegram** | public Telegram channels (casino announcements, ZachXBT, Lookonchain, PeckShield, CertiK, Cyvers, SlowMist and other hack trackers) | casino channel posts maintenance/withdrawal/hack words; tracker posts a gambling story |
| **forum** | BitcoinTalk scam + gambling boards, every run | new scam thread naming a casino; repeats |
| **pages** | UKGC, Sweden, ACMA, KSA, ANJ, OFAC, Anjouan, Curaçao press, Czech police, NY AG, CFTC, Europol | new enforcement items |

The 5-hour report also lists any check that has stopped working, so you know the radar is healthy.
The first run only records the current state. Alerts start from the next run.

## Setup (public repo, about 15 minutes, once)

1. **New GitHub account** (recommended) with a neutral name, so the repo isn't tied to you. Create a **public** repository with a neutral name.
2. **Upload** every file from `casino-radar.zip`. If the hidden `.github` folder doesn't upload, use "Add file" → "Create new file", name it `.github/workflows/radar.yml`, and paste that file's contents.
   **Never upload** `private_watchlist.yaml` or `private_wallets.csv` (sent separately).
3. **Secrets**: repo → Settings → Secrets and variables → Actions → New repository secret. Add five:
   | Secret | What to paste |
   |---|---|
   | `TELEGRAM_TOKEN` | your bot's token (below) |
   | `TELEGRAM_CHAT_ID` | your chat ID (below) |
   | `RADAR_PRIVATE_YAML` | the whole content of `private_watchlist.yaml` |
   | `RADAR_WALLETS_CSV` | the lines of `private_wallets.csv` |
   | `RADAR_STATE_KEY` | any long random sentence (encrypts the radar's memory) |
4. **Block strangers' workflows**: Settings → Actions → General → "Fork pull request workflows from outside collaborators" → **Require approval for all outside collaborators**. Never approve a pull request from someone else.
5. **Start**: Actions tab → enable workflows → "radar" → "Run workflow". After that it runs every 10 minutes by itself.

GitHub pauses scheduled runs on a public repo after 60 days without a commit. Editing any file (adding a wallet or outlet) restarts them; doing that once a month is enough.

## Connect your Telegram bot

You need two things: the bot's **token** and your **chat ID**.

1. **Token.** If you already have a bot, open `@BotFather` in Telegram, send `/mybots`, pick your bot → "API Token". If not, send `/newbot` and follow the steps.
2. **Start the bot.** Open your bot in Telegram and press Start (or send any message). A bot can't message you until you have messaged it once.
3. **Chat ID.** Message `@userinfobot` in Telegram; it replies with your ID (a number). For a group: add your bot to the group, then use the group's ID (starts with `-100`).
   - Other way: open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy the number after `"chat":{"id":`. If it says "Conflict" or shows nothing, your bot is already connected to something else; use `@userinfobot` instead. Sending alerts still works either way.
4. **Put both in GitHub.** Repo → Settings → Secrets and variables → Actions → New repository secret:
   - `TELEGRAM_TOKEN` = the token
   - `TELEGRAM_CHAT_ID` = the number
5. **Test.** Actions tab → "radar" → "Run workflow". You get a message as soon as something new is found, and the first 5-hour report 5 hours after the first run. To test immediately, open the run's log: each check prints its alert count.

## Adding things

- **Public wallets**: `wallets.csv`. **Leads you don't want seen**: add them to the `RADAR_WALLETS_CSV` secret instead (same format) — `name,chain,address,kind,min_usd`. Chains: eth, base, arbitrum, optimism, etherlink, gnosis, polygon, bsc, tron. kind = hot (casino wallet or bankroll) or parked (stolen or frozen money). Hundreds are fine.
- **Contracts or big holders to watch for drains and admin changes**: `contracts:` in `config.yaml` (public) or in the `RADAR_PRIVATE_YAML` secret (private), with the token addresses they hold.
- **Mixers and bridges**: `chains: mixers:` in `config.yaml`.
- **Outlets**: one per line in `outlets.txt` (`outlets_global.txt` is the big generated list) — a domain is enough, the radar finds its feed. Add `security`, `crypto` or `igaming` to flag specialist outlets.
- **Telegram channels**: `telegram_channels:` in `config.yaml`. The casino channel names there are best guesses; dead ones are skipped, so replace them with the real ones when you see them.
- **Casinos, brands, languages, regulator pages**: in `config.yaml`, each section is commented.
- **Too noisy**: raise `outflow_min_usd`, a wallet's `min_usd`, `cluster_min`, or the token percentages.
- **Telegram topics** (optional): make a Telegram group with Topics, add the bot, create topics "urgent", "updates", "reports", and put their ids under `telegram: topics:` in `config.yaml`. Without topics everything goes to one chat, which works fine.

## Test locally (optional)

    pip install -r requirements.txt pytest
    python -m pytest -q tests     # 62 offline tests, replays past stories
    python radar.py --dry         # one live run, prints alerts instead of sending

## Running private instead

Private works too, with less checking: set `run_budget_seconds: 30` in `config.yaml` and the schedule in `.github/workflows/radar.yml` to `"7,37 * * * *"`. Then the free 2,000 minutes a month are enough.
