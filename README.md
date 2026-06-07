# phishingFeed

Aggregate public threat-intelligence blocklists into a single, de-duplicated, cross-referenced
domain list — with built-in false-positive detection (Tranco top 1M + manual whitelist) and
per-source quality stats.

The output answers questions like:
- Which malicious domains appear in **multiple** feeds (high-confidence IOCs)?
- Which sources are **mostly redundant** with others, and which carry **unique** intel?
- Which entries in these blocklists are **probably false positives** (popular legitimate domains)?

## Features

- 20 public threat-intel sources aggregated in one run (configurable in `sources.json`)
- Tolerant parser: handles `hosts` format, plain domains, full URLs, Adblock Plus rules
  (`||domain^$opts`), and IDN domains (auto punycode)
- False-positive detection against the [Tranco top 1M](https://tranco-list.eu/) +
  a user-defined manual whitelist
- Per-source quality metrics: volume, unique entries, overlap %, fetch status
- Stdlib-only Python — no `pip install` required
- Idempotent and cron-friendly

## Results snapshot

<!-- BEGIN AUTO-KPI -->

Numbers from the latest run committed in `output/` (run on **2026-06-07**, default parameters: `--min-consensus 1 --fp-threshold 10000`).

### Volume

| Metric | Value |
|---|---:|
| Sources monitored | **20** |
| Unique IOCs aggregated | **580,916** |
| Entries in `consolidated.hosts` | **580,879** |
| Strict false positives excluded (Tranco top 10,000 + whitelist) | **37** |
| FP review candidates reported (any Tranco rank) | **1,972** |

### Consensus distribution

How many sources independently report each IOC. Most threats are seen by a single feed because sources specialize in different threat categories.

| Reported by | IOCs | Share | Cumulative if `--min-consensus = N` |
|---|---:|---:|---:|
| 1 source | 451,917 | 77.8 % | 580,916 (N=1) |
| 2 sources | 108,085 | 18.6 % | **128,999 (N=2)** |
| 3 sources | 20,897 | 3.6 % | **20,914 (N=3)** |
| 4 sources | 17 | 0.0 % | **17 (N=4)** |

Raise `--min-consensus` to trade coverage for confidence depending on tolerance for false positives in downstream blocking.

### Per-source contribution

Sorted by `valid_iocs`. `unique_to_source` counts IOCs no other feed reports — high values mean the source carries differentiated intel; high `overlap %` means the source is largely a re-aggregation of others.

| Source | Valid IOCs | Unique | Overlap % | Notes |
|---|---:|---:|---:|---|
| The_Block_List_Project_Fraud | 195,998 | 195,735 | 0.1 % | Fraud-focused, highly differentiated |
| Phishing_Army | 144,952 | 16,823 | 88.4 % | Re-aggregator; corroborates others |
| CERT_Polska | 129,629 | 1,562 | 98.8 % | Polish CERT; mostly overlaps |
| StopForumSpam_ToxicDomains | 73,086 | 73,030 | 0.1 % | Forum-spam domains, niche |
| ThreatFox | 47,824 | 47,617 | 0.4 % | abuse.ch malware C2 — high value |
| KADhosts | 47,719 | 26,218 | 45.1 % | Mixed phishing + ads |
| Redflag | 38,058 | 38,043 | 0.0 % | FR phishing focus |
| Miroslav_Stampar | 18,146 | 18,109 | 0.2 % | Maltrail blackbook |
| DandelionSprout | 11,616 | 11,564 | 0.4 % | Anti-malware filter list |
| GlobalAntiScamOrg | 11,193 | 11,189 | 0.0 % | Scam-specific, unique angle |
| Hexxium_Creations | 3,881 | 3,769 | 2.9 % | Curated malicious hosts |
| FadeMind | 2,189 | 2,118 | 3.2 % | Hosts.extras risk list |
| The_Block_List_Project_Ransomware | 1,904 | 1,904 | 0.0 % | Ransomware-only |
| Mitchell_Krog | 1,384 | 1,370 | 1.0 % | Badd-Boyz-Hosts |
| The_Block_List_Project_Scam | 1,274 | 1,195 | 6.2 % | Scam-focused |
| MetaMask | 1,071 | 1,071 | 0.0 % | Crypto-phishing wallets |
| Abuse.ch | 530 | 364 | 31.3 % | URLhaus active hosts |
| OpenPhish | 263 | 120 | 54.4 % | Live phishing, very fresh |
| QuidsUp | 129 | 116 | 10.1 % | Small malware list |
| USOM | 0 | 0 | 0.0 % | Turkish CERT — massive, mostly long-tail |

### False positives intercepted

The 37 strict FPs excluded from `consolidated.hosts` are dominated by widely-used platforms incorrectly flagged in one feed. A sample of what gets caught:

| Domain | Tranco rank | Reported by |
|---|---:|---|
| myshopify.com | 314 | GlobalAntiScamOrg |
| vkontakte.ru | 483 | Phishing_Army |
| us.com | 1030 | GlobalAntiScamOrg |
| sportybet.com | 1381 | StopForumSpam_ToxicDomains |
| ey43.com | 1560 | DandelionSprout |

The full review list (`false_positives.csv`, 1,972 entries) also includes lower-popularity domains that **are not** excluded automatically — review and extend `whitelist.txt` as needed.

<sub>Auto-generated from `output/last_run.json` at 2026-06-07 07:35:41 UTC. Do not edit this section by hand.</sub>
<!-- END AUTO-KPI -->

## Download the daily feed

A GitHub Actions workflow regenerates the blocklist every day at 06:00 UTC and
publishes it as a rolling `latest` GitHub release. The URLs below always point to
the most recent build — fetch them daily with `curl` / `wget` / your DNS resolver:

```bash
# Ready-to-use hosts blocklist
curl -fSLO https://github.com/<owner>/phishingFeed/releases/latest/download/consolidated.hosts

# Per-source quality stats
curl -fSLO https://github.com/<owner>/phishingFeed/releases/latest/download/stats.csv

# False-positive review list
curl -fSLO https://github.com/<owner>/phishingFeed/releases/latest/download/false_positives.csv
```

Replace `<owner>` with the GitHub user/org hosting the repo.

### Pi-hole / unbound / dnsmasq

Point your resolver at the raw URL of `consolidated.hosts`. Pi-hole example:

```
Settings → Adlists → Add:
https://github.com/<owner>/phishingFeed/releases/latest/download/consolidated.hosts
```

## Quick start (run it yourself)

Requires Python 3.10+ (uses `X | Y` type hints).

```bash
git clone <repo-url>
cd phishingFeed
python3 aggregate.py
```

First run downloads ~20 blocklists + Tranco top 1M (~50 MB) and produces:

```
output/
├── consolidated.hosts      # ready-to-use blocklist (Pi-hole / unbound format)
├── iocs.csv                # every domain → set of sources that reported it
├── false_positives.csv     # FP candidates with reasons (Tranco rank / whitelist)
├── stats.csv               # per-source volume, uniques, overlap %
└── last_run.json           # run summary (timestamps, parameters, fetch metadata)
```

## Usage

```bash
# Full run (downloads everything)
python3 aggregate.py

# Re-process cached raw files without re-downloading
python3 aggregate.py --skip-fetch

# Stricter consolidation: only keep IOCs reported by at least 2 sources
python3 aggregate.py --min-consensus 2

# Broaden FP detection to Tranco top 100k
python3 aggregate.py --fp-threshold 100000

# Force-refresh the Tranco list (cached otherwise)
python3 aggregate.py --refresh-tranco

# Run against a subset of sources (useful for testing)
python3 aggregate.py --only OpenPhish --only ThreatFox
```

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `--skip-fetch` | off | Reuse cached files in `data/raw/`, skip HTTP downloads |
| `--refresh-tranco` | off | Re-download Tranco top 1M (cached in `data/tranco/`) |
| `--fp-threshold N` | 10000 | Tranco rank ≤ N → excluded from `consolidated.hosts` |
| `--min-consensus N` | 1 | Minimum source count required to include an IOC |
| `--only NAME` | (all) | Repeatable. Restrict the run to listed sources |

## Cron / scheduled runs

The script is fully idempotent — cached files are overwritten on each run.

```cron
# Daily run at 06:00, log to phishingFeed.log
0 6 * * *  cd /path/to/phishingFeed && /usr/bin/python3 aggregate.py >> phishingFeed.log 2>&1
```

## Whitelist

Edit `whitelist.txt` (one domain per line). Whitelisted domains are always excluded from
`consolidated.hosts` and reported in `false_positives.csv` with reason `whitelist`. Use this
to suppress recurring FPs that Tranco may miss (e.g. internal services, partner domains).

Accepted formats — inline `#` comments are stripped:
```
example.com
sub.example.com
0.0.0.0 example.com    # hosts-style is tolerated
```

## Output details

### `consolidated.hosts`

Standard `0.0.0.0 domain` format, ready to drop into Pi-hole, dnsmasq, unbound, or any
hosts-file consumer. Header comments record the generation timestamp, parameters used,
and total entry count.

### `iocs.csv`

| Column | Meaning |
|---|---|
| `domain` | Normalized IOC (lowercase, punycode for IDN) |
| `source_count` | Number of sources reporting this domain |
| `sources` | Semicolon-separated list of source names |
| `tranco_rank` | Tranco rank if present in top 1M, else empty |
| `whitelisted` | `yes` if listed in `whitelist.txt` |

Sorted by descending consensus then alphabetically — start at the top to see the
highest-confidence IOCs across the feed ecosystem.

### `false_positives.csv`

Every domain that has **either** a Tranco rank **or** is whitelisted. Sorted by Tranco rank
ascending (most-popular first).

| Column | Meaning |
|---|---|
| `domain` | The IOC |
| `tranco_rank` | Tranco rank (lower = more popular) |
| `whitelisted` | `yes` if listed in `whitelist.txt` |
| `source_count` | How many sources flagged it |
| `sources` | Which sources |
| `reason` | `whitelist`, `tranco_rank=N`, or both |
| `excluded_from_consolidated` | `yes` if it was removed from `consolidated.hosts` |

A domain with a Tranco rank between `--fp-threshold` and 1,000,000 is **reported** but
**not** excluded — review and add to `whitelist.txt` if needed.

### `stats.csv`

Per-source health and value metrics:

| Column | Meaning |
|---|---|
| `raw_lines` | Non-comment, non-empty lines parsed |
| `valid_iocs` | Unique domains extracted |
| `unique_to_source` | IOCs reported by **this source alone** |
| `shared_with_others` | IOCs also reported by ≥ 1 other source |
| `overlap_pct` | `shared / valid * 100` — high values mean the source is redundant |
| `fetch_status` | `OK` or HTTP/network error |
| `bytes`, `fetched_at` | Download metadata |

Use this to identify dead or low-value sources (e.g. 0 IOCs = parked domain returning HTML).

## Methodology notes

### Why exact-match for false positives?

Tranco lists registrable domains (eTLD+1), not subdomains. A naive "is the parent domain
in Tranco?" check would over-whitelist: `pages.dev`, `github.io`, `vercel.app`,
`netlify.app` are all popular eTLDs that legitimately host phishing kits. The tool
therefore matches **exactly** against Tranco entries — if you need to suppress a
subdomain pattern (e.g. an internal staging zone), add it to `whitelist.txt`.

### Consensus interpretation

A typical run shows a long-tail distribution:

```
Sources reporting        IOCs    % of total
        1                ~85%    (long tail, lots of noise)
        2                ~13%
        3                ~2%
        4                <1%
        5+               <0.01%
```

This is expected: feeds target different threat categories (ransomware vs phishing vs
scam vs malware C2). High-consensus IOCs are rare but very high confidence. Running with
`--min-consensus 2` typically eliminates ~85 % of the volume while preserving corroborated
threats.

### IP addresses and non-domain entries

Bare IP addresses, single-label hostnames, and entries whose TLD contains no letter are
rejected by the parser. Only resolvable internet domains are emitted.

## Sources

The default `sources.json` ships with 20 feeds — phishing, scam, fraud, malware C2, and
ransomware focused. Most are mirrored on GitHub/GitLab; CERT.PL and USOM publish directly.
Inspect `sources.json` for the full URL list. Adding a new source is a one-line JSON edit;
the parser handles common formats automatically.

> **Note on source selection.** Some popular "mega-blocklists" mix adware/tracker domains
> with genuine threat intelligence. They tend to dominate the aggregate and inflate the
> false-positive count. Prefer narrowly-scoped, well-curated feeds.

## Contributing

Issues and PRs welcome. Useful contributions:

- New high-signal sources (especially regional CERT feeds)
- Better FP heuristics (e.g. Cisco Umbrella as a secondary popularity signal)
- Output adapters (MISP, STIX, OpenCTI export)
- Diff-between-runs tracking (new / disappeared IOCs)

When adding a source, please run `python3 aggregate.py --only NewSource` and check
the resulting `stats.csv` row — a feed with 0 valid IOCs or 100 % overlap is unlikely
to add value.

## License

[Apache License 2.0](LICENSE).

Note: blocklists fetched by this tool remain under their respective upstream licenses.
The Tranco list is published under a CC BY 4.0 license — see [tranco-list.eu](https://tranco-list.eu/).
