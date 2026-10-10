# tlsrelay — Plan de développement

> Version 1.0 du plan, consolidée à partir des décisions prises lors du cadrage.
> La spécification technique détaillée est dans [`SPEC.md`](SPEC.md).

## 1. Objet

`tlsrelay` est un relais TCP en ligne de commande qui transporte les données d'une application vers une destination, à travers un réseau non maîtrisé, selon trois niveaux de protection :

| Port | Mode | Protection |
|---|---|---|
| Port 1 | Clair | Aucune (relais simple) |
| Port 2 | TLS 1.3 | Chiffrement, authentification du serveur |
| Port 3 | mTLS (TLS 1.3) | Chiffrement, authentification mutuelle par certificats |

Il fonctionne toujours **par paire** : un `tlsrelay` en mode client et un `tlsrelay` en mode serveur.

```
App ──clair──► [tlsrelay CLIENT] ══ clair / TLS 1.3 / mTLS ══► [tlsrelay SERVEUR] ──clair──► Destination
                                    (protocole de tunnel)                               (adresse:port)
```

Le projet comprend deux livrables :

- **Livraison 1** : le service `tlsrelay` (Windows 64 bits et Linux), avec une mini-AC en ligne de commande.
- **Livraison 1.1** : l'éditeur graphique Windows `tlsrelay-admin` (configuration et PKI).

## 2. Décisions de cadrage

| Sujet | Décision |
|---|---|
| Langage | C++20 (coroutines) |
| Réseau | Asio (IOCP sous Windows, epoll sous Linux) |
| TLS | OpenSSL via `asio::ssl`, liaison dynamique |
| Version OpenSSL | 3.0 minimum (API 3.0 uniquement). Linux : OpenSSL de la distribution. Windows : OpenSSL 3.5 LTS livré avec l'application |
| FIPS | Non requis |
| Plateformes | Windows 10 / Server 2019 et plus (64 bits), Linux (Ubuntu 22.04, RHEL 9 et équivalents) |
| Build | CMake + vcpkg ; MSVC 2022, GCC ≥ 12, Clang ≥ 16 |
| Bibliothèques | yaml-cpp, spdlog, CLI11, GoogleTest ; Qt 6 pour l'éditeur (v1.1) |
| Mode client | Entrée en clair depuis l'application ; sortie clair, TLS 1.3 ou mTLS vers le `tlsrelay` serveur selon le port |
| Mode serveur | Entrée clair, TLS 1.3 ou mTLS ; sortie **en clair** vers une destination unique (adresse et port) configurable |
| Pair distant | Toujours un `tlsrelay`. Protocole de tunnel obligatoire, identifiant ALPN `tlsrelay/1` |
| Canaux | Plusieurs canaux en parallèle par port ; une session tunnel par canal |
| Rotation à chaud | Bi-clé, certificat, AC intermédiaires et racine. Les nouvelles connexions passent sur la nouvelle génération ; les connexions ouvertes finissent sur l'ancienne, qui est libérée quand elle n'a plus de connexion |
| Changement de racine | Procédure en 3 étapes : pré-confiance, bascule, retrait |
| Inactivité | `idle_timeout` sur les 3 ports |
| Durée de session | `session_lifetime` sur les ports 2 et 3 uniquement |
| Renégociation | Handshake complet (nouvelles clés, nouveaux certificats, nouvelle vérification de la chaîne), **transparente** pour l'application et la destination |
| Destination indisponible | 3 essais avec attente croissante, puis fermeture du canal |
| PROXY protocol | Non |
| Liste blanche (serveur) | Pairs autorisés à se connecter, définis par IP (ou plage CIDR) et sujet, limitables à certains ports. Ports 1 et 2 : contrôle de l'IP. Port 3 : IP + sujet (DN exact) + émission par l'AC Clients |
| Hiérarchie PKI | Une racine (ECDSA P-384), deux AC intermédiaires : AC Serveurs (`serverAuth`) et AC Clients (`clientAuth`), en P-384. Certificats des `tlsrelay` en ECDSA P-256 |
| Remise des bi-clés | Par demande de signature (CSR) : la clé privée est générée sur la machine `tlsrelay` et ne la quitte jamais |
| AC racine | Sur un poste d'administration dédié, clé chiffrée au repos |
| Logs | Niveaux `error`, `info`, `debug` (`-v`), `trace` (`-vv`) ; catégories `activity` et `config` ; changement de niveau à chaud ; aucun secret ni contenu relayé dans les logs |
| Cycle de vie | Service systemd / Windows ; démarrage au boot ; `stop` (drain de 30 s par défaut), `restart`, `kill`, `reload` ; instances nommées |
| Éditeur Windows | Qt 6, partage la bibliothèque `libtlsrelay-core` (mêmes règles de validation que le service), intègre l'AC racine |

## 3. Architecture

```
             ┌───────────────────────────────┐
             │       libtlsrelay-core        │  C++20 + OpenSSL 3
             │  config · validation · PKI    │
             │  protocole de tunnel · logs   │
             └───────┬───────────────┬───────┘
                     │               │
          ┌──────────▼───┐    ┌──────▼─────────────┐
          │  tlsrelay    │    │  tlsrelay-admin    │
          │  (service)   │    │  (éditeur Windows) │
          │ Win + Linux  │    │  Livraison 1.1     │
          └──────────────┘    └────────────────────┘
```

Modules principaux de `libtlsrelay-core` :

| Module | Rôle |
|---|---|
| `config` | Lecture YAML, modèle de configuration, validation (partagée avec l'éditeur) |
| `whitelist` | Chargement et correspondance de la liste blanche |
| `pki` | Générations de certificats, chargement et validation des répertoires PKI, CSR, mini-AC |
| `tls` | Un `SSL_CTX` par génération ; vérification des chaînes et de l'AC émettrice |
| `tunnel` | Encodage des trames, numérotation, ACK, reprise (`RESUME`) |
| `channel` | Machine à états d'un canal, timers (inactivité, durée de vie) |
| `relay` | Listeners, dialers, copie bidirectionnelle |
| `admin` | Canal d'administration (socket Unix / named pipe) |
| `log` | Journalisation structurée, niveaux et catégories |
| `platform` | Abstractions OS : service, signaux, droits sur fichiers |

## 4. Planning

### Livraison 1 : service `tlsrelay` — environ 12 semaines

| Phase | Contenu | Charge |
|---|---|---|
| 0 | Spécification : protocole de tunnel, config, liste blanche, états d'un canal, rotation | 2 j |
| 1 | Socle : CMake et vcpkg, `libtlsrelay-core`, CLI, logs et mode verbose, relais clair, multi-canaux, `idle_timeout` | 5 j |
| 2 | TLS 1.3 avec OpenSSL et `asio::ssl`, ALPN `tlsrelay/1` | 3 j |
| 3 | mTLS et liste blanche (IP, sujet, AC émettrice) | 4 j |
| 4 | Rotation à chaud jusqu'à la racine, un `SSL_CTX` par génération, `check-pki` | 6 j |
| 5 | Protocole de tunnel, renégociation transparente, 3 essais vers la destination | 8 j |
| 6 | Cycle de vie : services systemd et Windows, boot, stop, restart, kill, instances nommées, canal d'administration, métriques | 4 j |
| 7 | PKI en ligne de commande : `pki gen-csr`, `pki install`, mini-AC (`ca init`, `ca sign`) | 3 j |
| 8 | Durcissement : sanitizers, fuzzing, analyse statique | 6 j |
| 9 | Outillage de test : `tlsrelay-testkit`, fabrique de PKI de test, environnements croisés, perturbations réseau, endurance | 10 j |
| 10 | Campagne de sécurité interne, kit et cahier de recette, grille de test d'intrusion | 5 j |
| 11 | Packaging (`.deb`, `.rpm`, `.msi` avec OpenSSL 3.5) et documentation | 3 j |
| | Recette | 2 j |

### Livraison 1.1 : éditeur `tlsrelay-admin` — environ 6 semaines

| Lot | Contenu | Charge |
|---|---|---|
| A | Adaptation de `libtlsrelay-core` pour l'éditeur | 3 j |
| B | Éditeur de configuration Qt : formulaires, validation à la saisie, liste blanche, aperçu des différences, export des paquets de déploiement | 8 j |
| C | Module PKI : AC racine et intermédiaires, signature des CSR, inventaire, révocation (CRL), assistant de rotation et de changement de racine, journal d'audit ; reprise du répertoire de la mini-AC | 10 j |
| D | Tests (Qt Test, parité de validation éditeur/service), installeur, documentation | 9 j |

## 5. Stratégie de tests

### 5.1 Principes

- **Traçabilité** : chaque exigence est reliée aux tests qui la vérifient (matrice de traçabilité). Une exigence sans test vert n'est pas livrée.
- **Tests écrits avec le code** : une phase n'est terminée que si ses tests passent.
- **Double plateforme** : tous les tests automatisés passent sous Windows et Linux, contre OpenSSL 3.0 et 3.5.
- **Intégrité de bout en bout** : un générateur envoie un flux pseudo-aléatoire reproductible ; le récepteur compare l'empreinte SHA-256. Cela prouve l'absence de perte, de doublon et de réordonnancement, notamment pendant les renégociations.
- **Horloge injectable** : les tests unitaires des délais (inactivité, durée de vie, essais vers la destination) sont déterministes et rapides.

### 5.2 Niveaux de tests

| Niveau | Outils | Contenu | Objectif |
|---|---|---|---|
| Unitaires | GoogleTest | Config et validation ; liste blanche ; trames ; numérotation et ACK ; jeton de reprise ; générations ; machines à états ; essais vers la destination ; masquage des secrets dans les logs | Couverture ≥ 85 % de `libtlsrelay-core` ; 100 % des branches du décodeur de trames, de la liste blanche et de la validation |
| Intégration | GoogleTest + OpenSSL réel en local | Handshakes TLS 1.3 et mTLS, rotation, renégociation, inactivité | Tous les scénarios du catalogue |
| Système | Binaires réels + `tlsrelay-testkit` | Chaîne complète, combinaisons croisées Windows ↔ Linux | Toutes les exigences, sur les deux OS |
| Perturbations réseau | toxiproxy, `tc netem` | Latence, pertes, coupures pendant un transfert et une renégociation | Reprise sans perte, ou fermeture propre |
| Sécurité | Voir 5.4 | Cas d'attaque, fuzzing, analyse TLS | Aucun défaut critique |
| Performance et endurance | testkit | Débit, latence ajoutée, nombre de canaux, handshakes ; endurance 72 h | Voir 5.6 |
| Cycle de vie | VM Windows et Linux | Installation, boot, stop, restart, kill, instances nommées, droits du canal d'administration | 100 % des scénarios |
| Recette | Kit de recette | Scénarios métier | Procès-verbal signé |

### 5.3 Catalogue de scénarios (extrait de la matrice de traçabilité)

| Exigence | Scénarios |
|---|---|
| 3 ports / 3 modes | Transfert dans chaque mode, empreinte vérifiée ; port 2 refuse TLS 1.2 ; port 3 exige un certificat |
| Multi-canaux | 1, 100 puis 5 000 canaux en parallèle avec vérification par canal ; pas de fuite de mémoire, de descripteurs ou de handles |
| Rotation bi-clé / certificat | Canaux longs sur gen1, rotation, nouveaux canaux sur gen2, gen1 libérée quand son compteur tombe à 0 |
| Rotation des AC jusqu'à la racine | Les 3 étapes ; bascule prématurée (échec attendu, message clair) ; répertoire incomplet ou clé incohérente (rejet, service maintenu) ; rotation d'une seule AC intermédiaire |
| `idle_timeout` | Fermeture à l'échéance ; les trames de service ne repoussent pas l'échéance ; s'applique aussi à la liaison vers la destination |
| Renégociation transparente | Transfert continu de plusieurs Go pendant 20 renégociations : empreinte identique, application et destination jamais coupées ; renégociation pendant une rotation ; pair qui ne renégocie pas (fermeture à la fin du délai de grâce) |
| Liste blanche | IP non listée (rejet avant handshake) ; IP et DN de deux entrées différentes ; certificat de l'AC Serveurs présenté comme client ; pair retiré pendant une session ; ports 1 et 2 avec contrôle IP seul |
| Destination indisponible | Exactement 3 essais, délais mesurés ; `OPEN_FAIL` ; aucune perte si l'essai 2 ou 3 réussit |
| Mode verbose | Contenu attendu à chaque niveau ; changement à chaud ; recherche automatique de secrets et de données relayées dans tous les logs (aucune occurrence tolérée) |
| Cycle de vie | stop avec drain ; restart ; kill pendant un transfert puis redémarrage propre ; démarrage au boot ; deux instances nommées ; commande refusée à un non-administrateur |
| PKI en ligne de commande | `gen-csr` → `ca sign` → `pki install` ; refus d'une demande RSA ou d'un sujet en double ; extensions demandées ignorées ; certificats vérifiés aussi par `openssl verify` |

### 5.4 Campagne de sécurité

- **Cas d'attaque automatisés** : TLS 1.2, absence d'ALPN `tlsrelay/1`, certificat expiré / pas encore valide / d'une autre PKI / avec un mauvais usage, jeton de reprise rejoué ou falsifié, trame trop grande ou mal formée, numéro de séquence incohérent, inondation de connexions sans handshake.
- **Fuzzing (libFuzzer)** : décodeur de trames, chargeurs de config et de liste blanche, analyse des CSR. 1 h par nuit ; 24 h cumulées sans crash avant chaque livraison.
- **Erreurs mémoire** : AddressSanitizer, UndefinedBehaviorSanitizer, ThreadSanitizer (Linux) ; Application Verifier (Windows).
- **Analyse statique** : `clang-tidy`, `cppcheck`, MSVC `/analyze` ; zéro alerte de sévérité haute.
- **Configuration TLS** : `testssl.sh` et `sslyze` sur les ports 2 et 3.
- **Vulnérabilités des dépendances** : vérification à chaque build.
- **Test d'intrusion interne** avant la mise en production, selon une grille fondée sur les recommandations de l'ANSSI pour TLS.

### 5.5 Intégration continue

| Déclenchement | Contenu | Durée cible |
|---|---|---|
| Chaque commit / pull request | Compilation Windows et Linux, tests unitaires et d'intégration, sanitizers (sélection), `clang-tidy` | < 15 min |
| Chaque nuit | Bout en bout croisés, perturbations réseau, fuzzing 1 h, ThreadSanitizer complet, OpenSSL 3.0 et 3.5, mesures de performance comparées | < 3 h |
| Avant livraison | Endurance 72 h, fuzzing cumulé 24 h, `sslyze` / `testssl.sh`, test d'intrusion interne, recette | ~1 semaine |

### 5.6 Objectifs de performance

| Indicateur | Objectif |
|---|---|
| Canaux simultanés | 5 000 |
| Débit par canal | 100 Mbit/s |
| Latence ajoutée (local) | < 1 ms |
| Endurance | 72 h avec rotations et renégociations continues ; mémoire, handles et nombre de générations stables |

### 5.7 Recette

Réalisée par le responsable du projet, sur **une seule station Windows** :

```
                              station Windows
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ testkit app ──► tlsrelay@rc-client ══(toxiproxy)══► tlsrelay@rc-server ──► testkit destination │
│  127.0.0.1        127.0.0.2                          127.0.0.3              127.0.0.4          │
│                                                                                          │
│ VM Hyper-V Ubuntu 22.04 (commutateur interne) : instance Linux pour les tests croisés    │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

- Adresses de bouclage multiples pour tester la liste blanche par IP (option `source_address` côté client).
- Script `recette.ps1` : crée la PKI de test (mini-AC), installe les instances Windows, déploie le paquet `.deb` dans la VM, lance les scénarios Windows ↔ Windows, Windows → Linux et Linux → Windows.
- Cahier de recette : étapes, résultat attendu, case OK/KO ; étapes manuelles guidées (redémarrage pour le boot, `kill`, changement de racine, niveaux de log).
- Rapport généré : résultats, empreintes, extraits de logs, versions (`tlsrelay`, OpenSSL, OS).
- Non couvert sur une seule station : vrai réseau entre machines (NAT, pare-feu, MTU) ; compensé par les tests croisés en intégration continue. Un essai complémentaire sur deux machines est recommandé avant la production.
- Prérequis : Windows 10/11 Pro ou Entreprise (Hyper-V).

### 5.8 Critères de sortie d'une livraison

- 100 % des exigences couvertes par des tests verts, sur les deux OS.
- Aucun défaut critique ou majeur ouvert.
- Seuils de couverture atteints.
- 24 h de fuzzing sans crash ; aucune alerte des sanitizers.
- Endurance de 72 h réussie.
- Objectifs de performance atteints.
- Procès-verbal de recette signé.

## 6. Risques

| Risque | Mesure |
|---|---|
| Défauts mémoire en C++ sur un composant réseau exposé | RAII sur tous les objets OpenSSL, sanitizers, fuzzing, analyse statique, protections du compilateur |
| Complexité de la renégociation transparente | Spécification formelle des états, tests de bout en bout avec vérification d'empreinte, perturbations réseau |
| Coupure de service lors d'un changement de racine | Procédure en 3 étapes, garde-fou anti-coupure dans la validation, `check-pki` avant bascule |
| OpenSSL 3.0 en fin de support | API 3.0 seulement ; OpenSSL 3.5 LTS livré sous Windows ; correctifs Linux via la distribution |
| Compromission de l'AC racine | Poste d'administration dédié, clé chiffrée, racine utilisée uniquement pour signer les intermédiaires |
| Recette limitée à une station | Tests croisés entre machines en intégration continue ; essai complémentaire sur deux machines recommandé |
