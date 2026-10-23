# trusted-service-ranges

**[English version](README.md)**

Plages IPv4, mises à jour chaque jour, des services qui visitent légitimement vos serveurs :
robots des moteurs de recherche et des assistants IA, robots d'aperçu de liens, webhooks de
paiement, résolveurs DNS publics, serveurs mail sortants des grandes messageries. Elles sont
construites à partir des données publiées **par les fournisseurs eux-mêmes**, validées, et
réparties selon les **ports** dont chaque groupe a réellement besoin.

Leur rôle : éviter les dégâts collatéraux des blocages *collectifs* (bannir un /24 entier,
un pays, une liste de réputation) sans offrir de passe-droit. Une adresse listée n'est
exemptée que sur ses propres ports, et seulement des blocages collectifs, jamais des bans
par IP.

> Pourquoi : un robot qui parcourt un site avec plusieurs adresses du même /24 et tombe sur
> quelques liens cassés ressemble trait pour trait à un scanner pour une règle du type
> « N IP distinctes en M minutes ». En production, cela a banni à vie le robot d'aperçu de
> liens de Meta, Googlebot et des points de validation de Let's Encrypt.

## Listes

| Catégorie | Fichier | Ports à exempter | Contenu |
|---|---|---|---|
| `web` | [`lists/web.txt`](lists/web.txt) | tcp/80,443 | Googlebot (dont robots spéciaux et récupérations déclenchées par un utilisateur), Bingbot, Applebot, DuckDuckBot, Meta, LinkedIn, X (AS du fournisseur via RIPEstat), OpenAI, Perplexity, Anthropic, webhooks Stripe |
| `dns` | [`lists/dns.txt`](lists/dns.txt) | udp+tcp/53 | Sorties de Google Public DNS, Cloudflare |
| `mail` | [`lists/mail.txt`](lists/mail.txt) | tcp/25 | Plages SPF de Gmail, Microsoft 365, Outlook.com, iCloud, Orange/Wanadoo, Free, SFR, La Poste |
| `grey` | [`lists/grey.txt`](lists/grey.txt) | **aucun** | Sorties d'iCloud Private Relay, partagées par de nombreux utilisateurs : ne jamais les exempter, seulement ne jamais les compter pour bannir un /24 entier |

- URL brute : `https://raw.githubusercontent.com/e-kcltgit/trusted-service-ranges/main/lists/<catégorie>.txt` (un CIDR par ligne, agrégé).
- Listes par source : [`lists/sources/`](lists/sources/) ; comptes et état : [`lists/meta.json`](lists/meta.json).
- Reconstruites chaque jour à 04:23 UTC par [GitHub Actions](.github/workflows/update.yml) ; un commit n'est fait que si une liste change.
- IPv4 uniquement pour l'instant.

## Politique d'inclusion

**Uniquement des adresses exploitées par le fournisseur lui-même.** Sa liste officielle
d'abord ; à défaut, son propre système autonome via RIPEstat (méthode documentée par Meta).

**Jamais inclus, volontairement :**
- le cloud louable (AWS, Google Cloud, Azure, Oracle, DigitalOcean, Linode, Vultr,
  Cloudflare Workers sur le web) : c'est là que tournent les scanners ;
- les pools d'emailing partagés (Brevo, Mailjet, Mailgun, Mailchimp) : les `include:` SPF ne
  sont suivis que vers les domaines du fournisseur ;
- Yahoo/AOL : son SPF publie 34.2.64.0/19, qui chevauche l'espace Google Cloud louable ;
- OVH : son SPF repose sur `ptr`, inconvertible en plages.

Exceptions acceptées, documentées dans [`sources.conf`](sources.conf) : Stripe et Perplexity
publient des adresses isolées hébergées chez AWS (attribuées à eux, retirées de leur liste
quand ils les rendent) ; le SPF de SFR contient deux adresses isolées de prestataires.

## Garde-fous

Chaque source conserve sa liste précédente dès que quelque chose semble anormal ; l'exécution
est alors marquée en échec pour qu'un humain regarde :

- plage plus large qu'un /12 ou non routable → rejetée ;
- moins de plages valides que le minimum de la source → source jugée cassée ;
- nombre d'adresses plus que doublé (+ un /16 de marge) en un jour → refusé jusqu'à ce qu'un
  mainteneur relance le workflow avec `accept_growth` ;
- échec de téléchargement, de DNS ou d'analyse → liste précédente.

## Utilisation

**Exempter, jamais autoriser.** Le schéma sûr, utilisé en production :

1. Charger les listes dans des ipsets — [`examples/load-ipsets.sh`](examples/load-ipsets.sh)
   (échange atomique, garde l'ipset en place si un téléchargement paraît cassé).
2. Marquer en `mangle/PREROUTING` les paquets d'une adresse listée vers **ses** ports, et faire
   ignorer ces paquets par vos blocages collectifs (`RETURN` dans une chaîne de bans /24,
   `-m mark ! --mark` sur les listes noires en ipset) —
   [`examples/iptables-exemption.sh`](examples/iptables-exemption.sh). Les bans par IP
   continuent de s'appliquer : un robot qui tente de se connecter est banni quand même.
3. Dans fail2ban, ignorer les adresses listées dans les jails de **bruit** seulement (rafales
   de 404, scans de `.php`, requêtes DNS refusées, destinataires rejetés) avec
   `ignorecommand = ipset test …` — [`examples/fail2ban/`](examples/fail2ban/). Jamais dans
   les jails d'authentification ni dans `recidive`.
4. N'exempter `grey` de rien ; seulement exclure ses adresses du comptage par /24.

> ⚠️ **Piège au démarrage.** Si votre pare-feu est restauré par `iptables-restore` au boot
> (HestiaCP, iptables-persistent…), une seule règle sauvegardée qui cite un ipset encore
> inexistant fait échouer **toute** la restauration : la machine démarre sans aucune règle.
> Retirez ces règles avant la restauration, puis chargez les ipsets et reposez les règles.

**Limites.**
- Les récupérations déclenchées par un utilisateur (ChatGPT-User, Perplexity-User, récupérations
  Google) visitent des URL que *n'importe qui* peut demander : c'est pourquoi seules les jails
  de bruit doivent les ignorer.
- Ces listes sont une commodité construite à partir de publications de tiers. Relisez-les,
  épinglez un commit si vous avez besoin de reproductibilité, et gardez vos propres garde-fous.

## Construire localement

```bash
python3 build.py --dry-run          # rapport seul
python3 build.py                    # écrit lists/
python3 build.py --accept-growth    # après vérification d'une croissance refusée
```

Python 3.9+, bibliothèque standard uniquement ; `dig` est nécessaire pour les sources `spf`
et `dnstxt`.

## Contribuer

Une nouvelle source doit être (1) exploitée par le fournisseur lui-même, (2) publiée par lui ou
dérivée de son propre AS, (3) utile sur un port précis. Ouvrez une issue ou une pull request
qui modifie [`sources.conf`](sources.conf) en expliquant l'usage. Les plages de cloud louable et
les pools d'emailing partagés seront refusés.

## Licence

Code : [MIT](LICENSE). Les listes sont dérivées de données publiées par les fournisseurs
eux-mêmes ; elles sont fournies sans aucune garantie.
