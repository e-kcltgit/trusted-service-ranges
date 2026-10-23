# trusted-service-ranges

**[Version française](README.fr.md)**

Daily-updated IPv4 ranges of services that legitimately hit your servers — search engine and
AI crawlers, link-preview bots, payment webhooks, public DNS resolvers, outbound mail servers
of the big mailbox providers — built from the providers' **own** published data, validated,
and split by the **ports** each group actually needs.

They exist to stop collateral damage from *collective* blocking (banning a whole /24, a
country, a reputation list) without handing anyone a free pass: a listed address is exempted
only on its own ports, and only from collective blocks, never from per-IP bans.

> Why: a crawler that walks a site from several addresses of the same /24 and hits a few
> broken links looks exactly like a scanner to a "N distinct IPs in M minutes" rule. In
> production this banned Meta's link-preview crawler, Googlebot and Let's Encrypt validation
> perspectives — permanently.

## Lists

| Category | File | Ports to exempt | Content |
|---|---|---|---|
| `web` | [`lists/web.txt`](lists/web.txt) | tcp/80,443 | Googlebot (incl. special crawlers and user-triggered fetchers), Bingbot, Applebot, DuckDuckBot, Meta, LinkedIn, X (provider ASN via RIPEstat), OpenAI, Perplexity, Anthropic, Stripe webhooks |
| `dns` | [`lists/dns.txt`](lists/dns.txt) | udp+tcp/53 | Google Public DNS egress, Cloudflare |
| `mail` | [`lists/mail.txt`](lists/mail.txt) | tcp/25 | SPF ranges of Gmail, Microsoft 365, Outlook.com, iCloud, Orange/Wanadoo, Free, SFR, La Poste |
| `grey` | [`lists/grey.txt`](lists/grey.txt) | **none** | iCloud Private Relay egress — shared by many users: never exempt it, just never count it when banning a whole /24 |

- Raw URL: `https://raw.githubusercontent.com/e-kcltgit/trusted-service-ranges/main/lists/<category>.txt` (one CIDR per line, aggregated).
- Per-source lists: [`lists/sources/`](lists/sources/); counts and status: [`lists/meta.json`](lists/meta.json).
- Rebuilt every day at 04:23 UTC by [GitHub Actions](.github/workflows/update.yml); a commit is made only when a list changes.
- IPv4 only for now.

## Inclusion policy

**Only addresses operated by the provider itself.** Official list first; when a provider
publishes none, its own autonomous system through RIPEstat (Meta's documented method).

**Never included, on purpose:**
- rentable cloud space — AWS, Google Cloud, Azure, Oracle, DigitalOcean, Linode, Vultr,
  Cloudflare Workers on the web: this is where scanners run;
- shared emailing pools (Brevo, Mailjet, Mailgun, Mailchimp): SPF `include:` are only followed
  to the provider's own domains;
- Yahoo/AOL mail: its SPF publishes 34.2.64.0/19, which overlaps rentable Google Cloud space;
- OVH mail: its SPF relies on `ptr`, which cannot be turned into ranges.

Accepted exceptions, documented in [`sources.conf`](sources.conf): Stripe and Perplexity publish
single addresses hosted on AWS (allocated to them, removed from their lists when released);
SFR's SPF contains two single third-party addresses.

## Safety guards

Every source keeps its previous list when something looks wrong — the run is then marked as
failed so a human looks at it:

- ranges wider than /12 or not globally routable are rejected;
- fewer valid ranges than the source's minimum → source considered broken;
- address count more than doubling (+ one /16 of slack) in a day → refused until a maintainer
  re-runs the workflow with `accept_growth`;
- download, DNS or parsing failure → previous list.

## How to use them

**Exempt, never allow.** The safe pattern, used in production:

1. Load the lists into ipsets — [`examples/load-ipsets.sh`](examples/load-ipsets.sh) (atomic
   swap, keeps the current set if a download looks broken).
2. Mark packets from a listed address to **its** ports in `mangle/PREROUTING`, and make your
   collective blocks skip marked packets (`RETURN` in a /24-ban chain, `-m mark ! --mark` on
   ipset blocklists) — [`examples/iptables-exemption.sh`](examples/iptables-exemption.sh).
   Per-IP bans keep applying: a crawler that tries to log in is still banned.
3. In fail2ban, ignore listed addresses in **noise** jails only (404 floods, `.php` scans,
   refused DNS queries, rejected recipients) with `ignorecommand = ipset test …` —
   [`examples/fail2ban/`](examples/fail2ban/). Never in authentication jails nor in `recidive`.
4. Do not exempt `grey` from anything; only exclude its addresses when counting IPs per /24.

> ⚠️ **Boot pitfall.** If your firewall is restored with `iptables-restore` at boot (HestiaCP,
> iptables-persistent…), any saved rule that references an ipset which does not exist yet makes
> the **whole** restore fail — the host boots with no rule at all. Strip the rules that
> reference these ipsets before restoring, then load the ipsets and re-add the rules.

**Caveats.**
- User-triggered fetchers (ChatGPT-User, Perplexity-User, Google user-triggered fetchers) fetch
  URLs that *anyone* can ask for: that is why only noise jails should ignore them.
- These lists are a convenience built from third-party publications. Review them, pin a commit
  if you need reproducibility, and keep your own guards.

## Build locally

```bash
python3 build.py --dry-run          # report only
python3 build.py                    # writes lists/
python3 build.py --accept-growth    # after reviewing a refused growth
```

Python 3.9+ standard library only; `dig` is needed for the `spf` and `dnstxt` sources.

## Contributing

A new source must be (1) operated by the provider itself, (2) published by the provider or
derived from its own ASN, (3) useful on a precise port. Open an issue or a pull request that
edits [`sources.conf`](sources.conf) and explains the use case. Rentable cloud ranges and shared
emailing pools will be declined.

## License

Code: [MIT](LICENSE). The lists are derived from data the providers publish themselves;
they come with no warranty.
