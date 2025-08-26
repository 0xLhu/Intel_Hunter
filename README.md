<p align="center">
  <img src="Intel_Hunter.png" alt="Intel Hunter logo" width="500"/>
</p>


# Intel Hunter (Threat-Hunting-MVP)

Collecte, enrichit, score et **pivote** automatiquement des IOC récents depuis **Urlscan**, **URLhaus**, **ThreatFox** ; pivots via **Shodan**, **crt.sh** et **VirusTotal** ; export **STIX** et **Elastic ECS**.

## ✨ Fonctions

- **Collecte multi-sources** : Urlscan (live search), URLhaus, ThreatFox.
- **Normalisation & enrichissement** : canonicalisation URL, extraction host, DNS A, RDAP/ASN.
- **Scoring** : ponderation par reputation, mots-cles, hébergeurs “bulletproof”, etc.
- **Exports** :
  - `out_stix_bundle.json` (STIX)
  - `out_elastic_threat.jsonl` (Elastic ECS Threat Intel)
- **Pivot automatique** :
  - Shodan (IP → hostnames, domain → subdomains + IPs)
  - crt.sh (subdomains par certificats)
  - VirusTotal (passive DNS : domain ↔ IP, subdomains)
- **Concurrence contrôlée** pour accelerer l’enrichissement.

## 🧱 Arborescence

Threat-Hunting-MVP/
├─ cli.py
└─ hunter/
├─ init.py
├─ collectors/
│ ├─ urlscan_live.py
│ ├─ urlhaus.py
│ └─ threatfox.py
├─ enrichers.py
├─ normalize.py
├─ scoring.py
├─ models.py
├─ export_stix.py
└─ pivot.py

## 🚀 Installation rapide

```bash
# 1) create  venv
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# 2) dependencies
pip install -r requirements.txt
```

Variable Par defaut Description
HUNTER_USE_URLSCAN 1 Active Urlscan (1/0)
HUNTER_USE_URLHAUS 1 Active URLhaus (1/0)
HUNTER_USE_THREATFOX 1 Active ThreatFox (1/0)
HUNTER_URLSCAN_HOURS 12 Fenêtre temporelle Urlscan
HUNTER_URLSCAN_SIZE 200 Taille du lot Urlscan
HUNTER_THREATFOX_DAYS 2 Fenêtre ThreatFox (1–7)
HUNTER_MAX_IOCS 600 Cap d’IOC apres dedup
HUNTER_ENRICH_CONCURRENCY 20 Concurrence enrichissement
HUNTER_PIVOT_MIN_SCORE 50 Score minimum pour pivoter
HUNTER_PIVOT_MAX_DOMAINS 50 Max domaines “seed”
HUNTER_PIVOT_MAX_IPS 50 Max IP “seed”
HUNTER_PIVOT_FRESH_HOURS 48 Fraîcheur max des seeds
HUNTER_DNS_TIMEOUT 1.5 Timeout DNS (s)
HUNTER_WHOIS_TIMEOUT 4.0 Timeout WHOIS (s)

# Usage

python sight_hunt.py

# Conseils & limites

VirusTotal (gratuit) : ~4 req/min → le code applique un backoff.
Ajuste max*seed*\* ou agrandis fresh_hours si tu touches 429.

Shodan : selon le plan, certains endpoints sont limites.

crt.sh : public, mais peut etre lent → le code gere les “timeouts”.

## 🔒 Sécurité & conformité

Utiliser uniquement sur des donnees legitimes et dans le respect des ToS des services.

Ne blackliste pas les domaines racine d’ISP/hébergeurs sur la seule base des pivots.

Stocke tes cles API dans des variables d’environnement, pas dans le dépôt.

## 🐞 Depannage

“Empty response / non-JSON” : verifie la connectivite (proxy, firewall).

Beaucoup d’IOC “ISP” : monte HUNTER_PIVOT_MIN_SCORE et/ou applique un filtre metier avant pivot.

L’exécution est longue : baisse HUNTER*ENRICH_CONCURRENCY, HUNTER_MAX_IOCS, ou désactive une source (HUNTER_USE*\*=0) pour tester.

## 📌 Roadmap

Integrer Censys/ZoomEye/GreyNoise/BinaryEdge etc.

Enrichissement WHOIS domaine (registrar, dates).

Export OpenCTI direct (connector).

Score “pivot” (pondération multi-sources).

Link to MISP

# Licence

MIT
