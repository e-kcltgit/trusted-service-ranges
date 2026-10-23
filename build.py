#!/usr/bin/env python3
"""Build the trusted-service-ranges lists.

Reads sources.conf, fetches every source, validates the ranges, applies the safety
guards and writes:

    lists/sources/<category>--<name>.txt   one validated list per source
    lists/<category>.txt                   aggregated (collapsed) list per category
    lists/meta.json                        counts and status of every source

Safety guards (a source that trips one keeps its previous list):
    - ranges wider than /MIN_PREFIX or not globally routable are rejected;
    - fewer valid ranges than the source minimum → source considered broken;
    - address count growing by more than MAX_GROWTH_PCT % (+ GROWTH_SLACK) in one run
      → refused, unless --accept-growth;
    - fetch or parse failure → previous list kept.

Standard library only. The spf and dnstxt source types need the `dig` command.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

CATEGORIES = ("web", "dns", "mail", "grey")
PORTS = {"web": "tcp/80,443", "dns": "udp+tcp/53", "mail": "tcp/25", "grey": None}
MIN_PREFIX = 12
MAX_GROWTH_PCT = 100
GROWTH_SLACK = 65536  # one /16: lets small lists grow without tripping the guard
MAX_DOWNLOAD = 50 * 1024 * 1024
TIMEOUT = 90
USER_AGENT = "trusted-service-ranges (+https://github.com/e-kcltgit/trusted-service-ranges)"
IPV4_RX = re.compile(r"(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)(?![0-9.])")
NAME_RX = re.compile(r"^[a-z0-9-]+$")

Net = ipaddress.IPv4Network


class SourceError(Exception):
    """A source could not be fetched or parsed."""


@dataclass(frozen=True)
class Source:
    category: str
    name: str
    type: str
    argument: str
    option: str
    minimum: int

    @property
    def key(self) -> str:
        return f"{self.category}--{self.name}"


@dataclass
class Result:
    source: Source
    status: str = "ok"  # ok | kept-previous | missing
    ranges: int = 0
    addresses: int = 0
    added: int = 0
    removed: int = 0
    message: str = ""
    rejected: list[str] = field(default_factory=list)
    nets: list[Net] = field(default_factory=list)


def parse_sources(path: Path) -> tuple[list[Source], list[str]]:
    """Parse sources.conf; returns the sources and the warnings for invalid lines."""
    sources: list[Source] = []
    warnings: list[str] = []
    seen: set[str] = set()
    with path.open(encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) != 6:
                warnings.append(f"sources.conf:{lineno}: expected 6 fields, got {len(parts)}")
                continue
            category, name, type_, argument, option, minimum = (p.strip() for p in parts)
            if category not in CATEGORIES or not NAME_RX.match(name) or not minimum.isdigit():
                warnings.append(f"sources.conf:{lineno}: invalid line ignored")
                continue
            src = Source(category, name, type_, argument, option, int(minimum))
            if src.key in seen:
                warnings.append(f"sources.conf:{lineno}: duplicate source {category}/{name} ignored")
                continue
            seen.add(src.key)
            sources.append(src)
    return sources, warnings


def fetch_url(url: str) -> str:
    """Download an https URL (no other scheme, bounded size)."""
    if not url.startswith("https://"):
        raise SourceError(f"refusing non-https URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (https only)
            if not resp.geturl().startswith("https://"):
                raise SourceError(f"redirected to non-https URL: {resp.geturl()}")
            data = resp.read(MAX_DOWNLOAD + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SourceError(f"download failed: {exc}") from exc
    if len(data) > MAX_DOWNLOAD:
        raise SourceError("response larger than the download limit")
    return data.decode("utf-8", errors="replace")


def dig_txt(name: str) -> list[str]:
    """TXT records of a DNS name, each record's strings concatenated."""
    if not shutil.which("dig"):
        raise SourceError("the dig command is required for spf and dnstxt sources")
    proc = subprocess.run(
        ["dig", "+short", "+time=5", "+tries=2", "TXT", name],
        capture_output=True, text=True, timeout=60, check=False,
    )
    if proc.returncode != 0:
        raise SourceError(f"dig failed for {name}: {proc.stderr.strip()}")
    # dig prints one record per line as "chunk1" "chunk2": chunks are joined without separator.
    # Only quoted lines are records: with +short, dig also prints diagnostics on stdout
    # (";; communications error to 127.0.0.100#53: timed out" on GitHub runners) whose
    # addresses must never be read as ranges.
    return [line.replace('" "', "").replace('"', "")
            for line in proc.stdout.splitlines() if line.startswith('"')]


def suffix_allowed(domain: str, suffixes: list[str]) -> bool:
    domain = domain.lower().rstrip(".")
    return any(domain == s or domain.endswith("." + s) for s in suffixes if s)


def spf_ranges(record: str, suffixes: list[str], notes: list[str], depth: int = 0) -> list[str]:
    """ip4: mechanisms of an SPF record, following include:/redirect= only to allowed domains.

    A mailbox provider's SPF sometimes includes the pool of a shared emailing service,
    which must not be exempted: those includes are skipped and reported in notes.
    """
    if depth > 5:
        return []
    spf = next((r for r in dig_txt(record) if r.lower().startswith("v=spf1")), "")
    if not spf:
        if depth == 0:
            raise SourceError(f"no SPF record for {record}")
        notes.append(f"{record}: no SPF record")
        return []
    out: list[str] = []
    for term in spf.split()[1:]:
        term = term.lstrip("+?~-")
        low = term.lower()
        if low.startswith("ip4:"):
            out.append(term[4:])
        elif low.startswith(("include:", "redirect=")):
            target = re.split(r"[:=]", term, maxsplit=1)[1]
            if suffix_allowed(target, suffixes):
                out.extend(spf_ranges(target, suffixes, notes, depth + 1))
            else:
                notes.append(f"skipped (domain not allowed): {term}")
        elif low.split(":")[0] in ("a", "mx", "ptr", "exists"):
            notes.append(f"skipped (cannot be turned into ranges): {term}")
    return out


def extract(text: str, mode: str, path: str) -> list[str]:
    """IPv4 addresses/CIDRs found in a response, according to the source option."""
    if mode == "json":
        obj = json.loads(text)
        for key in (k for k in path.split(".") if k):
            obj = obj[key]
        tokens: list[str] = []
        stack = [obj]
        while stack:
            item = stack.pop()
            if isinstance(item, str):
                tokens.extend(IPV4_RX.findall(item))
            elif isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        return tokens
    if mode == "csv":
        return [t for line in text.splitlines() for t in IPV4_RX.findall(line.split(",", 1)[0])]
    return IPV4_RX.findall(text)


def collect(src: Source, notes: list[str]) -> list[str]:
    """Raw tokens of a source, before validation."""
    if src.type == "url":
        text = fetch_url(src.argument)
        if src.option == "csv":
            return extract(text, "csv", "")
        if src.option:
            try:
                return extract(text, "json", src.option)
            except (ValueError, KeyError, TypeError) as exc:
                raise SourceError(f"unexpected JSON ({type(exc).__name__}: {exc})") from exc
        return extract(text, "text", "")
    if src.type == "spf":
        return spf_ranges(src.argument, [s.strip() for s in src.option.split(",")], notes)
    if src.type == "dnstxt":
        return IPV4_RX.findall("\n".join(dig_txt(src.argument)))
    if src.type == "static":
        return [t.strip() for t in src.argument.split(",") if t.strip()]
    raise SourceError(f"unknown source type: {src.type}")


def validate(tokens: list[str]) -> tuple[list[Net], list[str]]:
    """Keep routable IPv4 ranges no wider than /MIN_PREFIX; report the others."""
    ok: set[Net] = set()
    rejected: list[str] = []
    for token in tokens:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            rejected.append(f"{token} (invalid)")
            continue
        if not isinstance(net, Net):
            continue
        if net.prefixlen < MIN_PREFIX:
            rejected.append(f"{token} (wider than /{MIN_PREFIX})")
        elif not net.is_global:
            rejected.append(f"{token} (not globally routable)")
        else:
            ok.add(net)
    return sorted(ok), rejected


def address_count(nets: list[Net]) -> int:
    return sum(n.num_addresses for n in ipaddress.collapse_addresses(nets))


def read_list(path: Path) -> list[Net]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [ipaddress.IPv4Network(line.strip()) for line in fh if line.strip()]


def write_list(path: Path, nets: list[Net]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        fh.writelines(f"{n}\n" for n in nets)


def process(src: Source, out_dir: Path, accept_growth: bool) -> Result:
    """Fetch, validate and guard one source; falls back to its previous list on any problem."""
    res = Result(src)
    previous = read_list(out_dir / "sources" / f"{src.key}.txt")
    prev_addresses = address_count(previous) if previous else 0
    notes: list[str] = []
    problem = ""
    nets: list[Net] = []
    try:
        nets, res.rejected = validate(collect(src, notes))
        new_addresses = address_count(nets)
        if len(nets) < src.minimum:
            problem = f"only {len(nets)} valid range(s), minimum {src.minimum}"
        elif (not accept_growth and prev_addresses
              and new_addresses > prev_addresses * (100 + MAX_GROWTH_PCT) // 100 + GROWTH_SLACK):
            problem = (f"growth refused ({prev_addresses} → {new_addresses} addresses); "
                       "check the source, then run with --accept-growth")
    except SourceError as exc:
        problem = str(exc)
    if notes:
        res.message = "; ".join(notes)
    if problem:
        res.message = problem + (f" | {res.message}" if res.message else "")
        if previous:
            res.status, res.nets = "kept-previous", previous
        else:
            res.status, res.nets = "missing", []
    else:
        res.nets = nets
        prev_set, new_set = set(previous), set(nets)
        res.added, res.removed = len(new_set - prev_set), len(prev_set - new_set)
    res.ranges = len(res.nets)
    res.addresses = address_count(res.nets) if res.nets else 0
    return res


def annotate(level: str, text: str) -> None:
    """Print a line; on GitHub Actions also emit a workflow annotation."""
    print(f"{level.upper():7} {text}")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{text}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--sources", type=Path, default=Path("sources.conf"))
    parser.add_argument("--out", type=Path, default=Path("lists"))
    parser.add_argument("--accept-growth", action="store_true",
                        help="accept a growth refused by the guard (after manual review)")
    parser.add_argument("--dry-run", action="store_true", help="report only, write nothing")
    args = parser.parse_args()

    sources, warnings = parse_sources(args.sources)
    for w in warnings:
        annotate("warning", w)
    results = [process(src, args.out, args.accept_growth) for src in sources]

    for r in results:
        label = f"{r.source.category}/{r.source.name}"
        if r.status == "ok":
            print(f"OK      {label}: {r.ranges} ranges (+{r.added} -{r.removed})")
            if r.message:
                print(f"        {r.message}")
        else:
            warnings.append(label)
            annotate("warning", f"{label}: {r.message} → {r.status} ({r.ranges} ranges)")
        if r.rejected:
            warnings.append(label)
            annotate("warning", f"{label}: {len(r.rejected)} range(s) rejected: "
                                + "; ".join(r.rejected[:3]))

    categories: dict[str, list[Net]] = {}
    for cat in CATEGORIES:
        nets = [n for r in results if r.source.category == cat for n in r.nets]
        categories[cat] = list(ipaddress.collapse_addresses(nets))
        print(f"LIST    {cat}: {len(categories[cat])} aggregated ranges, "
              f"{sum(n.num_addresses for n in categories[cat])} addresses")

    if not any(categories.values()):
        annotate("error", "every category is empty: nothing written")
        return 1
    if args.dry_run:
        print(f"Dry run: nothing written ({len(warnings)} warning(s)).")
        return 0

    sources_dir = args.out / "sources"
    sources_dir.mkdir(parents=True, exist_ok=True)
    keep = {f"{r.source.key}.txt" for r in results if r.nets}
    for stale in sources_dir.glob("*.txt"):
        if stale.name not in keep:
            stale.unlink()  # source removed from sources.conf
    for r in results:
        if r.nets:
            write_list(sources_dir / f"{r.source.key}.txt", r.nets)
    for cat, nets in categories.items():
        write_list(args.out / f"{cat}.txt", nets)

    meta = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "policy": {"min_prefix": MIN_PREFIX, "max_growth_pct": MAX_GROWTH_PCT,
                   "growth_slack": GROWTH_SLACK, "ip_version": 4},
        "categories": {
            cat: {"ports": PORTS[cat], "ranges": len(nets),
                  "addresses": sum(n.num_addresses for n in nets)}
            for cat, nets in categories.items()
        },
        "sources": [
            {"category": r.source.category, "name": r.source.name, "type": r.source.type,
             "status": r.status, "ranges": r.ranges, "addresses": r.addresses,
             "message": r.message}
            for r in results
        ],
    }
    with (args.out / "meta.json").open("w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"Written to {args.out}/ ({len(warnings)} warning(s)).")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write(f"warnings={len(warnings)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
