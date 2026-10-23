#!/bin/bash
# iptables-exemption.sh — exempt listed services from COLLECTIVE blocks, on their own ports only.
#
# EN  Packets from a listed address to the ports of its category get a netfilter mark in
#     mangle/PREROUTING. Your collective blocks (/24 bans, country bans, reputation lists)
#     then skip marked packets. This is NOT an ACCEPT: per-IP bans (fail2ban jails…) still
#     apply, so a crawler that tries to log in is still banned.
# FR  Les paquets d'une adresse listée vers les ports de sa catégorie reçoivent une marque
#     en mangle/PREROUTING. Les blocages collectifs (/24, pays, réputation) ignorent ces
#     paquets. Ce n'est PAS un ACCEPT : les bans par IP (jails fail2ban…) s'appliquent toujours.
#
# Requires the ipsets created by load-ipsets.sh. Run as root after each load (idempotent).
#
# BOOT WARNING / PIÈGE AU DÉMARRAGE
#   EN  If you persist your rules with iptables-save/iptables-restore, the mangle rules below
#       reference ipsets that do not exist yet at boot, and ONE such rule makes the whole
#       iptables-restore fail: no firewall rule at all is loaded. Strip them before restoring
#       (sed -E '/--match-set tsr-[a-z]+ /d') and run load-ipsets.sh + this script afterwards.
#   FR  Si vos règles sont restaurées par iptables-restore au démarrage, retirez d'abord les
#       règles qui citent les ipsets tsr-* : une seule fait échouer tout le chargement.
set -euo pipefail

MARK="0x100000"        # pick a bit no other tool uses on your host
CHAIN="tsr-exempt"

iptables -t mangle -N "$CHAIN" 2>/dev/null || iptables -t mangle -F "$CHAIN"
iptables -t mangle -C PREROUTING -j "$CHAIN" 2>/dev/null || iptables -t mangle -I PREROUTING 1 -j "$CHAIN"
iptables -t mangle -A "$CHAIN" -p tcp -m multiport --dports 80,443 -m set --match-set tsr-web src -j MARK --set-xmark "$MARK/$MARK"
iptables -t mangle -A "$CHAIN" -p udp --dport 53 -m set --match-set tsr-dns src -j MARK --set-xmark "$MARK/$MARK"
iptables -t mangle -A "$CHAIN" -p tcp --dport 53 -m set --match-set tsr-dns src -j MARK --set-xmark "$MARK/$MARK"
iptables -t mangle -A "$CHAIN" -p tcp --dport 25 -m set --match-set tsr-mail src -j MARK --set-xmark "$MARK/$MARK"
# tsr-grey is deliberately never exempted

cat <<EOF
Marking in place. Now make your collective blocks skip marked packets, for example:

  # a chain holding /24 bans: leave it first for marked packets
  iptables -I MY-SUBNET-BANS 1 -m mark --mark $MARK/$MARK -j RETURN

  # an ipset-based blocklist (country, reputation…)
  iptables -A INPUT -m set --match-set my-blocklist src -m mark ! --mark $MARK/$MARK -j DROP
EOF
