# IPInvestigator

Entrée : **une adresse IP**. Sortie : **un rapport HTML autonome** (capture d'écran intégrée) + un fichier JSON.

## Ce que fait l'outil

| Section du rapport | Contenu | Source |
|---|---|---|
| Fiche d'identité | cible, nom du site, applications, localisation, nature, réseau, opérateur, noms d'hôte, contact abus | synthèse |
| Adresse | localisation estimée, précision (détection anycast/CDN), titulaire du bloc, FAI, DNS inverse, carte | DB-IP lite (local) + ipwho.is |
| Bases locales | comparaison des sources de géolocalisation | `data/dbip-*-lite.mmdb` |
| Registre Internet (RDAP) | plage, CIDR, type, bloc parent, dates, titulaire, contacts abus / NOC | rdap.org → ARIN/RIPE/APNIC… |
| Opérateur (PeeringDB) | nom, type de réseau, portée, site, politique de peering | peeringdb.com |
| Exposition déjà relevée | ports, noms d'hôte, CPE, CVE connues | Shodan InternetDB (gratuit, sans clé) |
| Port 80 / 443 | état, réponse, redirections, titre, h1, serveur, technologies, cookies, formulaires, en-têtes de sécurité présents/absents, robots.txt, security.txt, certificat TLS, **capture d'écran** | scan direct + Chromium |

## Installation (Windows)

1. Installer Python 3.10+ (cocher *Add Python to PATH*).
2. Double-cliquer sur `installer.bat` (dépendances, Chromium, bases DB-IP).
3. Double-cliquer sur `IPInvestigator.bat`, taper l'IP → le rapport s'ouvre dans le navigateur.

Installation manuelle (Windows / Linux / macOS) :

```bash
pip install -r requirements.txt
python -m playwright install chromium
python ipinvestigator.py --update-db      # bases DB-IP (à refaire chaque mois)
```

## Utilisation

```bash
python ipinvestigator.py                    # demande l'IP
python ipinvestigator.py 15.197.175.4
python ipinvestigator.py 15.197.175.4 -p 80,443,8080,8443
python ipinvestigator.py exemple.com        # un domaine est résolu en IP
```

Options : `--no-screenshot`, `--offline` (aucune API en ligne), `--no-open`, `-o DOSSIER`.

Les rapports sont écrits dans `rapports/` (`<ip>-<date>.html` et `.json`), les captures dans `rapports/captures/`.
Le HTML est autonome : on peut l'envoyer ou l'ouvrir sur un téléphone, la capture est intégrée.

## Limites et cadre légal

- La géolocalisation IP donne la zone de l'équipement réseau de l'opérateur, pas l'adresse d'une personne.
  Pour les CDN / anycast (Cloudflare, AWS Global Accelerator…), la ville n'est qu'un point d'entrée.
- N'analysez que des adresses pour lesquelles vous êtes autorisé (vos serveurs, un périmètre de mission).
  Le scan se limite à une connexion TCP et à une requête HTTP par port, comme un navigateur.
- Données de géolocalisation : DB-IP Lite, licence CC BY 4.0.
