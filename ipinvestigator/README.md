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

## Installation et utilisation (Windows)

1. Installer Python depuis python.org (cocher *Add Python to PATH*). Rien d'autre à installer.
2. Double-cliquer sur **`IPInvestigator.bat`** : une page s'ouvre dans le navigateur.
3. Saisir l'adresse IP → **Analyser** → l'avancement s'affiche, puis le rapport apparaît dans la page
   (boutons : ouvrir en plein écran, télécharger le HTML / le JSON). Les rapports précédents restent listés.

Laisser la fenêtre noire ouverte pendant l'utilisation (c'est le serveur local).

Autres lanceurs :
- `IPInvestigator-telephone.bat` : même interface, accessible aussi depuis un téléphone sur le même Wi-Fi
  (l'adresse à taper sur le téléphone s'affiche dans la fenêtre).
- `IPInvestigator-console.bat` : version texte, sans navigateur.

### Dépendances

Le programme fonctionne avec **la seule bibliothèque standard de Python** ; la capture d'écran utilise
Microsoft Edge (ou Chrome) déjà installé. Au premier lancement, il tente d'ajouter des modules facultatifs
(`requirements.txt`) si pypi.org est joignable — sinon il continue sans eux :

| Module | Apport |
|---|---|
| beautifulsoup4 | analyse HTML plus fine |
| maxminddb | géolocalisation via les bases DB-IP locales (en plus du service en ligne) |
| cryptography | détail des certificats auto-signés |
| playwright | captures via Playwright au lieu d'Edge/Chrome |

Sur un réseau d'entreprise, si un proxy est configuré dans Windows, il est utilisé automatiquement pour les
sources en ligne, et pour lire la page cible si la connexion directe est bloquée.

### Ligne de commande

```bash
python webapp.py [--lan] [--port 8765]
python ipinvestigator.py 15.197.175.4 [-p 80,443,8080] [--no-screenshot] [--offline] [--no-open]
python ipinvestigator.py --update-db      # bases DB-IP (si maxminddb est installé)
```

Les rapports sont écrits dans `rapports/` (`<ip>-<date>.html` et `.json`), les captures dans `rapports/captures/`.
Le HTML est autonome : on peut l'envoyer ou l'ouvrir sur un téléphone, la capture est intégrée.

## Limites et cadre légal

- La géolocalisation IP donne la zone de l'équipement réseau de l'opérateur, pas l'adresse d'une personne.
  Pour les CDN / anycast (Cloudflare, AWS Global Accelerator…), la ville n'est qu'un point d'entrée.
- N'analysez que des adresses pour lesquelles vous êtes autorisé (vos serveurs, un périmètre de mission).
  Le scan se limite à une connexion TCP et à une requête HTTP par port, comme un navigateur.
- Données de géolocalisation : DB-IP Lite, licence CC BY 4.0.
