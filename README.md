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

## Quick start

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
