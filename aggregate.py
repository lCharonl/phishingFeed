#!/usr/bin/env python3
"""Agrégateur de feeds threat intel.

Télécharge les sources définies dans sources.json, normalise les IOCs
(domaines), croise les sources, écarte les faux positifs candidats
(Tranco top N + whitelist manuelle) et produit trois sorties dans output/ :

  - consolidated.hosts      liste prête à l'emploi (format hosts)
  - false_positives.csv     domaines candidats faux positifs (raison + rank)
  - stats.csv               stats par source (volume, uniques, overlap %)
  - iocs.csv                table complète domain → sources + rank Tranco
  - last_run.json           résumé du run (idempotent / cron-friendly)

Stdlib only. Lancer simplement : `python3 aggregate.py`.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import ssl
import sys
import urllib.request
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
SOURCES_FILE = ROOT / "sources.json"
WHITELIST_FILE = ROOT / "whitelist.txt"
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
TRANCO_DIR = DATA_DIR / "tranco"
OUTPUT_DIR = ROOT / "output"

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
USER_AGENT = "ListFeeds-Aggregator/1.0 (+threat-intel-aggregation)"
HTTP_TIMEOUT = 60
HTTP_RETRIES = 2
FETCH_WORKERS = 8

SSL_CTX = ssl.create_default_context()

COMMENT_RE = re.compile(r"^\s*[#!;]")
HOSTS_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+(\S+)")
DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)

SKIP_HOSTS = {
    "localhost", "localhost.localdomain", "broadcasthost", "local",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
}


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def normalize_line(line: str) -> str | None:
    """Extrait un domaine canonique d'une ligne de feed (hosts/URL/adblock/plain)."""
    line = line.strip()
    if not line or COMMENT_RE.match(line):
        return None
    if "#" in line:
        line = line.split("#", 1)[0].strip()
    if not line:
        return None

    m = HOSTS_RE.match(line)
    if m:
        candidate = m.group(1)
    elif line.lower().startswith(("http://", "https://")):
        try:
            candidate = urlparse(line).hostname or ""
        except ValueError:
            return None
    else:
        candidate = line.split()[0]
        if "$" in candidate:
            candidate = candidate.split("$", 1)[0]
        candidate = candidate.strip("|").strip("^").strip("/")

    if not candidate:
        return None
    candidate = candidate.lower().strip(".")
    if candidate in SKIP_HOSTS:
        return None
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass
    if not DOMAIN_RE.match(candidate):
        return None
    # Le TLD doit contenir au moins une lettre (sinon on a une IP comme 1.2.3.4)
    tld = candidate.rsplit(".", 1)[-1]
    if not any(c.isalpha() for c in tld):
        return None
    return candidate


def fetch(name: str, url: str, dest: Path) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_err = None
    for attempt in range(HTTP_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=SSL_CTX) as resp:
                data = resp.read()
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                return {
                    "ok": True,
                    "status": resp.status,
                    "bytes": len(data),
                    "sha256": sha256(data).hexdigest(),
                    "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
        except Exception as e:  # noqa: BLE001
            last_err = f"{type(e).__name__}: {e}"
    return {
        "ok": False,
        "error": last_err,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def fetch_all(sources: dict[str, str]) -> dict[str, dict]:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    meta: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        futs = {
            ex.submit(fetch, name, url, RAW_DIR / f"{name}.txt"): name
            for name, url in sources.items()
        }
        for fut in as_completed(futs):
            name = futs[fut]
            meta[name] = fut.result()
            tag = "OK  " if meta[name].get("ok") else "FAIL"
            extra = (
                f"{meta[name].get('bytes', 0):>10} B"
                if meta[name].get("ok")
                else meta[name].get("error", "?")
            )
            log(f"  [{tag}] {name:<35} {extra}")
    return meta


def load_tranco(force: bool = False) -> dict[str, int]:
    TRANCO_DIR.mkdir(parents=True, exist_ok=True)
    csv_cache = TRANCO_DIR / "top-1m.csv"
    if force or not csv_cache.exists():
        log("Downloading Tranco top 1M...")
        zpath = TRANCO_DIR / "top-1m.csv.zip"
        req = urllib.request.Request(TRANCO_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=SSL_CTX) as r:
            zpath.write_bytes(r.read())
        with zipfile.ZipFile(zpath) as z:
            inner = next(n for n in z.namelist() if n.endswith(".csv"))
            with z.open(inner) as src:
                csv_cache.write_bytes(src.read())
    ranks: dict[str, int] = {}
    with csv_cache.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            rank_s, _, domain = line.strip().partition(",")
            if domain and rank_s.isdigit():
                ranks[domain.lower()] = int(rank_s)
    return ranks


def load_sources() -> dict[str, str]:
    text = SOURCES_FILE.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        # Tolère l'ancien format Python (`sources = {...}`)
        _, _, rest = text.partition("=")
        text = rest.strip()
    return json.loads(text)


def load_whitelist() -> set[str]:
    if not WHITELIST_FILE.exists():
        return set()
    wl: set[str] = set()
    for line in WHITELIST_FILE.read_text(encoding="utf-8").splitlines():
        d = normalize_line(line)
        if d:
            wl.add(d)
    return wl


def parse_source(path: Path) -> tuple[set[str], int]:
    """Retourne (domaines uniques, lignes utiles non-vides non-commentaires)."""
    if not path.exists():
        return set(), 0
    out: set[str] = set()
    raw_lines = 0
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        s = line.strip()
        if not s or COMMENT_RE.match(s):
            continue
        raw_lines += 1
        d = normalize_line(line)
        if d:
            out.add(d)
    return out, raw_lines


def write_iocs_csv(path: Path, ioc_sources: dict[str, set[str]],
                   tranco: dict[str, int], whitelist: set[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "source_count", "sources", "tranco_rank", "whitelisted"])
        for d in sorted(ioc_sources, key=lambda x: (-len(ioc_sources[x]), x)):
            srcs = sorted(ioc_sources[d])
            w.writerow([
                d,
                len(srcs),
                ";".join(srcs),
                tranco.get(d, ""),
                "yes" if d in whitelist else "",
            ])


def write_fp_csv(path: Path, ioc_sources: dict[str, set[str]],
                 tranco: dict[str, int], whitelist: set[str],
                 fp_threshold: int) -> tuple[int, int]:
    """Write FP candidates. Returns (strict_excluded_count, total_reported_count)."""
    strict_count = 0
    rows = []
    for d, srcs in ioc_sources.items():
        rank = tranco.get(d)
        in_wl = d in whitelist
        if rank is None and not in_wl:
            continue
        reasons = []
        strict = False
        if in_wl:
            reasons.append("whitelist")
            strict = True
        if rank is not None:
            reasons.append(f"tranco_rank={rank}")
            if rank <= fp_threshold:
                strict = True
        if strict:
            strict_count += 1
        rows.append((rank if rank is not None else 10**9, d, rank, in_wl,
                     len(srcs), sorted(srcs), reasons, strict))
    rows.sort()
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "tranco_rank", "whitelisted", "source_count",
                    "sources", "reason", "excluded_from_consolidated"])
        for _, d, rank, in_wl, sc, srcs, reasons, strict in rows:
            w.writerow([d, rank if rank is not None else "",
                        "yes" if in_wl else "", sc, ";".join(srcs),
                        "+".join(reasons), "yes" if strict else ""])
    return strict_count, len(rows)


def write_stats_csv(path: Path, sources: dict[str, str],
                    per_source_domains: dict[str, set[str]],
                    per_source_raw_lines: dict[str, int],
                    ioc_sources: dict[str, set[str]],
                    meta: dict[str, dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "source", "raw_lines", "valid_iocs", "unique_to_source",
            "shared_with_others", "overlap_pct", "fetch_status",
            "bytes", "fetched_at",
        ])
        for name in sources:
            domains = per_source_domains.get(name, set())
            valid = len(domains)
            unique = sum(1 for d in domains if ioc_sources[d] == {name})
            shared = valid - unique
            pct = (shared / valid * 100) if valid else 0.0
            m = meta.get(name, {})
            w.writerow([
                name,
                per_source_raw_lines.get(name, 0),
                valid,
                unique,
                shared,
                f"{pct:.1f}",
                "OK" if m.get("ok") else (m.get("error") or "skipped"),
                m.get("bytes", ""),
                m.get("fetched_at", ""),
            ])


def write_consolidated(path: Path, ioc_sources: dict[str, set[str]],
                       excluded: set[str], min_consensus: int,
                       fp_threshold: int) -> int:
    kept = sorted(
        d for d, srcs in ioc_sources.items()
        if len(srcs) >= min_consensus and d not in excluded
    )
    with path.open("w", encoding="utf-8") as f:
        f.write("# Liste consolidée — threat intel\n")
        f.write(f"# Généré: {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
        f.write(f"# Consensus minimum: {min_consensus} source(s)\n")
        f.write(f"# Tranco top {fp_threshold} exclu, whitelist appliquée\n")
        f.write(f"# Total: {len(kept)} entrées (sur {len(ioc_sources)} IOCs uniques)\n")
        f.write("#\n")
        for d in kept:
            f.write(f"0.0.0.0 {d}\n")
    return len(kept)


def run(args: argparse.Namespace) -> int:
    sources = load_sources()
    log(f"Configured sources: {len(sources)}")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    if args.skip_fetch:
        log("-> skip-fetch: using cached raw files")
        meta = {}
    else:
        log("Fetching sources...")
        meta = fetch_all(sources)

    log("Loading Tranco...")
    tranco = load_tranco(force=args.refresh_tranco)
    log(f"  {len(tranco):,} Tranco domains")

    whitelist = load_whitelist()
    log(f"Whitelist: {len(whitelist)} entries")

    log("Parsing feeds...")
    ioc_sources: dict[str, set[str]] = defaultdict(set)
    per_source_domains: dict[str, set[str]] = {}
    per_source_raw_lines: dict[str, int] = {}
    for name in sources:
        domains, raw_lines = parse_source(RAW_DIR / f"{name}.txt")
        per_source_domains[name] = domains
        per_source_raw_lines[name] = raw_lines
        for d in domains:
            ioc_sources[d].add(name)
        log(f"  {name:<35} {len(domains):>8,} IOCs ({raw_lines:>8,} lines)")

    log(f"Total unique IOCs: {len(ioc_sources):,}")

    iocs_path = OUTPUT_DIR / "iocs.csv"
    stats_path = OUTPUT_DIR / "stats.csv"
    fp_path = OUTPUT_DIR / "false_positives.csv"
    cons_path = OUTPUT_DIR / "consolidated.hosts"

    write_iocs_csv(iocs_path, ioc_sources, tranco, whitelist)
    log(f"-> {iocs_path.relative_to(ROOT)}")

    strict_fp, total_fp = write_fp_csv(fp_path, ioc_sources, tranco, whitelist, args.fp_threshold)
    log(f"-> {fp_path.relative_to(ROOT)} ({strict_fp} strict FPs excluded, "
        f"{total_fp} candidates reported)")

    write_stats_csv(stats_path, sources, per_source_domains,
                    per_source_raw_lines, ioc_sources, meta)
    log(f"-> {stats_path.relative_to(ROOT)}")

    excluded = {
        d for d in ioc_sources
        if d in whitelist
        or (tranco.get(d) is not None and tranco[d] <= args.fp_threshold)
    }
    kept_n = write_consolidated(cons_path, ioc_sources, excluded,
                                args.min_consensus, args.fp_threshold)
    log(f"-> {cons_path.relative_to(ROOT)} ({kept_n:,} entries, "
        f"consensus >= {args.min_consensus})")

    consensus_dist: dict[int, int] = defaultdict(int)
    for srcs in ioc_sources.values():
        consensus_dist[len(srcs)] += 1

    summary = {
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_unique_iocs": len(ioc_sources),
        "consolidated_kept": kept_n,
        "false_positives_excluded": len(excluded),
        "false_positives_reported": total_fp,
        "consensus_distribution": {str(k): consensus_dist[k] for k in sorted(consensus_dist)},
        "sources": {name: len(per_source_domains.get(name, set())) for name in sources},
        "fetch_meta": meta,
        "params": {
            "min_consensus": args.min_consensus,
            "fp_tranco_threshold": args.fp_threshold,
        },
    }
    (OUTPUT_DIR / "last_run.json").write_text(json.dumps(summary, indent=2))
    log(f"-> {(OUTPUT_DIR / 'last_run.json').relative_to(ROOT)}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--skip-fetch", action="store_true",
                   help="ne pas re-télécharger, utiliser les fichiers data/raw cachés")
    p.add_argument("--refresh-tranco", action="store_true",
                   help="force le re-téléchargement de la liste Tranco top 1M")
    p.add_argument("--fp-threshold", type=int, default=10_000,
                   help="rank Tranco ≤ N → exclu de consolidated (défaut: 10000)")
    p.add_argument("--min-consensus", type=int, default=1,
                   help="nombre min. de sources pour inclure un IOC (défaut: 1)")
    p.add_argument("--only", action="append", default=None,
                   help="restreindre à une source (peut être répété, pour tests)")
    args = p.parse_args()

    if args.only:
        original = load_sources()
        keep = {k: v for k, v in original.items() if k in set(args.only)}
        if not keep:
            log(f"No source matches --only {args.only}")
            return 2
        globals()["load_sources"] = lambda: keep
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
