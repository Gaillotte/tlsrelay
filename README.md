# tlsrelay

Relais TCP en ligne de commande, fonctionnant par paire (client / serveur), qui transporte les données d'une application vers une destination selon trois modes :

| Port | Mode |
|---|---|
| 1 | Clair |
| 2 | TLS 1.3 |
| 3 | mTLS (TLS 1.3, authentification mutuelle) |

Principales caractéristiques :

- C++20, OpenSSL 3 (liaison dynamique), Windows 64 bits et Linux
- Plusieurs canaux en parallèle par port
- Rotation à chaud des bi-clés, certificats et AC jusqu'à la racine, sans interruption de service
- Durée d'inactivité et durée de session maximales, avec renégociation complète et transparente
- Liste blanche des pairs côté serveur (IP + sujet du certificat + AC émettrice)
- Service au démarrage du système, arrêt / redémarrage / arrêt forcé, instances nommées
- Mode verbose (logs d'activité et des opérations de configuration)
- Éditeur Windows de configuration et de PKI (`tlsrelay-admin`, livraison 1.1)

## Documentation

- [Plan de développement](docs/PLAN.md) : décisions, architecture, planning, stratégie de tests, recette
- [Spécification technique](docs/SPEC.md) : TLS, protocole de tunnel, liste blanche, PKI, configuration, cycle de vie

## État

Phase 0 : spécification.
