#!/bin/bash
# load-ipsets.sh — load the trusted-service-ranges lists into ipsets (run as root, e.g. daily).
#
# EN  Creates or refreshes one hash:net ipset per category (tsr-web, tsr-dns, tsr-mail,
#     tsr-grey) through an atomic swap. A list that fails to download or looks broken
#     leaves the current ipset untouched.
# FR  Crée ou rafraîchit un ipset hash:net par catégorie (tsr-web, tsr-dns, tsr-mail,
#     tsr-grey) par échange atomique. Une liste absente ou suspecte laisse l'ipset en place.
#
# Usage: load-ipsets.sh [BASE]
#   BASE  where the lists live; default: this repository's main branch on GitHub.
#         Pin a commit for reproducibility, or give a local directory (a clone's lists/).
set -euo pipefail

BASE="${1:-https://raw.githubusercontent.com/e-kcltgit/trusted-service-ranges/main/lists}"
PREFIX="tsr"
MAXELEM=262144
# Minimum number of lines expected per category: below it, the download is considered broken
declare -A MIN_LINES=([web]=500 [dns]=30 [mail]=30 [grey]=1000)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for cat in web dns mail grey; do
    set_name="${PREFIX}-${cat}"
    file="$tmp/${cat}.txt"
    if [[ "$BASE" == /* ]]; then
        cp "$BASE/${cat}.txt" "$file"
    elif ! curl -fsS --proto '=https' --max-time 60 -o "$file" "$BASE/${cat}.txt"; then
        echo "WARN ${cat}: download failed, ipset ${set_name} left unchanged" >&2
        continue
    fi
    # Only strict CIDR lines are ever loaded
    grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' "$file" > "${file}.ok" || true
    lines=$(wc -l < "${file}.ok")
    if (( lines < MIN_LINES[$cat] )); then
        echo "WARN ${cat}: only ${lines} ranges (expected >= ${MIN_LINES[$cat]}), ipset ${set_name} left unchanged" >&2
        continue
    fi
    ipset create "$set_name" hash:net family inet maxelem "$MAXELEM" -exist
    ipset destroy "${set_name}-new" 2>/dev/null || true
    ipset create "${set_name}-new" hash:net family inet maxelem "$MAXELEM"
    sed "s|^|add ${set_name}-new |" "${file}.ok" | ipset restore -!
    ipset swap "${set_name}-new" "$set_name"
    ipset destroy "${set_name}-new"
    echo "OK   ${set_name}: ${lines} ranges"
done
