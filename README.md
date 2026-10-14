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

- [Design document (English)](docs/DESIGN.md) : architecture, sécurité, protocole, PKI, éditeur, qualité ; en 10 slides : [tlsrelay-design-slides.pdf](docs/tlsrelay-design-slides.pdf)
- [Éditeur tlsrelay-admin](docs/EDITEUR.md) : configuration, liste blanche, paquets de déploiement, mini-AC (livraison 1.1)
- [Installation](docs/INSTALLATION.md) : paquets `.deb`, `.rpm` et `.msi`, première instance, mise à jour, désinstallation
- [Exploitation](docs/EXPLOITATION.md) : commandes courantes, journaux, supervision, PKI, sauvegarde, dépannage
- [Plan de développement](docs/PLAN.md) : décisions, architecture, planning, stratégie de tests, recette
- [Spécification technique](docs/SPEC.md) (en anglais) : TLS, protocole de tunnel, liste blanche, PKI, configuration, cycle de vie
- [Plan et rapport de tests](docs/TESTS.md) (en anglais) : stratégie, environnements, description de tous les tests, couverture des exigences
- [Grille de test d'intrusion](docs/PENTEST.md) : points de contrôle, méthode, résultat attendu, couverture automatisée
- [Cahier de recette](docs/RECETTE.md) et [procès-verbal](docs/PV-RECETTE.md) : scénarios automatisés (`tools/recette.ps1`) et étapes manuelles

## État

| Phase | Contenu | État |
|---|---|---|
| 0 | Spécification | Terminée |
| 1 | Socle : CMake/vcpkg, configuration et validation, logs et mode verbose, relais en clair, multi-canaux, `idle_timeout`, essais vers la destination, arrêt propre | Terminée |
| 2 | TLS 1.3 sur OpenSSL : port `tls`, ALPN `tlsrelay/1`, vérification du nom et de l'AC émettrice du serveur, chargement et contrôle de la PKI | Terminée |
| 3 | mTLS (certificat client émis par l'AC Clients) et liste blanche des pairs (IP, sujet, ports), rechargée à chaud | Terminée |
| 4 | Rotation à chaud des certificats et des AC jusqu'à la racine (générations, drain, garde-fou, `check-pki`, `pki activate`, `SIGHUP`) | Terminée |
| 5 | Protocole de tunnel `tlsrelay/1` (trames, acquittements, contre-pression, demi-fermeture), renégociation transparente à l'échéance de `session_lifetime`, reprise de session après coupure | Terminée |
| 6 | Cycle de vie : services systemd et Windows (boot, start, stop, restart, kill), instances nommées, canal d'administration, métriques Prometheus, journalisation à chaud | Terminée |
| 7 | PKI en ligne de commande : `pki gen-csr`, `pki install`, mini-AC (`ca init`, `ca sign`, `ca list`) | Terminée |
| 8 | Durcissement : PING périodique (lien muet), fuzzing libFuzzer (6 cibles, nuit de 1 h), clang-tidy et cppcheck sans alerte, scan TLS (sslyze), OpenSSL 3.5 sous Linux | Terminée |
| 9 | Outillage de test `tlsrelay-testkit` (charge, débit, latence, perturbations réseau, PKI de test), objectifs de performance mesurés, endurance | Terminée |
| 10 | Campagne de sécurité : cas d'attaque automatisés, testssl.sh, MSVC `/analyze`, durcissement et dépendances vérifiés en CI, grille de test d'intrusion ; kit de recette (`recette.ps1`, cahier, procès-verbal) | Terminée |
| 11 | Paquets `.deb`, `.rpm` et `.msi` (OpenSSL 3.5 LTS sous Windows), testés à l'installation sur Ubuntu 22.04 et 24.04, Debian 12, RHEL 9 et équivalents, Windows ; guides d'installation et d'exploitation | Terminée |

Livraison 1.1 (éditeur `tlsrelay-admin`, [PLAN §4](docs/PLAN.md)) :

| Phase | Contenu | État |
|---|---|---|
| 12 | Socle de l'éditeur : écriture normalisée de la configuration et de la liste blanche, différences ; mini-AC : révocation (`ca revoke`), CRL (`ca crl`), journal d'audit chaîné (`ca audit`) ; CRL appliquées par le service (`pki crl`, rechargement à chaud) | Terminée |
| 13 | Application Qt `tlsrelay-admin` : formulaire de configuration et liste blanche validés par les règles du service, aperçu des différences et copie `.bak` à l'enregistrement, export des paquets de déploiement (Linux, Windows) | Terminée |
| 14 | Module PKI de l'éditeur : reprise ou création de la mini-AC, inventaire (filtres, expirations), signature et renouvellement des demandes, révocation et CRL, journal d'audit, assistant de changement de racine (`ca root-change` en ligne de commande) | Terminée |
| 15 | Éditeur dans le MSI (fonctionnalité « tlsrelay-admin » : DLL Qt déployées, raccourci, textes LGPL et GPL), contrôle sans fenêtre (`--check`), guide de l'éditeur, scénarios de recette E01 à E10 | Terminée |

Les trois ports sont disponibles. Le client et le serveur dialoguent avec le protocole de tunnel (SPEC §4) : sur les ports `tls` et `mtls`, le client renégocie la session à l'échéance de `session_lifetime` (nouvelle connexion, handshake complet avec la génération PKI courante) sans que l'application ne voie de coupure, et reprend la session si la connexion tombe. Le serveur n'accepte que des tlsrelay clients : une application ne peut pas s'y connecter directement.

En mode serveur, la liste blanche est obligatoire (exemple commenté : [examples/whitelist.yaml](examples/whitelist.yaml)).

## Compilation

### Linux

Dépendances (Ubuntu 24.04) :

```sh
sudo apt-get install cmake ninja-build g++ libssl-dev libasio-dev libyaml-cpp-dev \
    libspdlog-dev libcli11-dev libgtest-dev
```

```sh
cmake --preset linux-release
cmake --build --preset linux-release
ctest --preset linux-release
```

Avec AddressSanitizer et UBSan (Clang, paquet `libclang-rt-18-dev`) : préréglage `linux-asan`.

Durcissement (Linux) :

```sh
tools/run-clang-tidy.sh build/linux-release          # analyse statique (paquet clang-tidy-18)
tools/run-cppcheck.sh build/linux-release            # analyse statique (paquet cppcheck)
cmake --preset linux-fuzz && cmake --build --preset linux-fuzz
tools/run-fuzz.sh build/linux-fuzz 60                # 60 s par cible libFuzzer
tests/lifecycle/tls-scan.sh build/linux-release/src/app/tlsrelay   # configuration TLS (sslyze)
tools/coverage.sh build/coverage                     # couverture de code (paquet gcovr) : build/coverage/coverage/index.html
```

Couverture mesurée et nouveaux tests à réaliser : [TESTS.md §6](docs/TESTS.md#6-code-coverage).

### Éditeur tlsrelay-admin (Qt 6)

L'éditeur se compile avec l'option `-DTLSRELAY_BUILD_ADMIN=ON` (Qt 6.4 ou plus récent, liaison dynamique) :

```sh
sudo apt-get install qt6-base-dev          # Linux (paquet de la distribution)
cmake --preset linux-release -DTLSRELAY_BUILD_ADMIN=ON
cmake --build --preset linux-release && build/linux-release/src/admin/tlsrelay-admin examples/server.yaml
```

Sous Windows, Qt 6.8 LTS (msvc2022_64) est indiqué par `-DCMAKE_PREFIX_PATH=<répertoire de Qt>`. Les tests de l'éditeur (Qt Test) tournent sans affichage (`QT_QPA_PLATFORM=offscreen`) et vérifient notamment que l'éditeur et le service signalent exactement les mêmes erreurs.

L'éditeur ouvre une configuration et, en mode serveur, sa liste blanche ; chaque saisie est validée par le chargeur du service. L'enregistrement montre les différences, réécrit les fichiers sous une forme normalisée (les commentaires ne sont pas conservés) et garde l'original en `.bak`. L'onglet « PKI » reprend un répertoire de mini-AC (créé par `tlsrelay ca init` ou par l'éditeur) : inventaire des certificats émis (révoqués en rouge, expirant dans 30 jours en orange), signature d'une demande examinée avant signature, assistant de renouvellement, révocation suivie de la publication des CRL, journal d'audit et contrôle de son intégrité, assistant de changement de racine (fichiers de confiance et commandes des trois étapes). La phrase de passe de l'AC est demandée à chaque opération et n'est jamais conservée.

« Exporter le paquet de déploiement » crée un répertoire à copier sur la machine de l'instance : configuration, liste blanche, kit PKI et CRL éventuels, `install.sh` ou `install.ps1` et `LISEZMOI.txt`.

### Paquets

```sh
# Linux, dans un conteneur de la distribution la plus ancienne visée (dépendances embarquées) :
docker run --rm -v "$PWD:/src" -w /src ubuntu:22.04 packaging/build-linux.sh paquets   # .deb
docker run --rm -v "$PWD:/src" -w /src rockylinux:9 packaging/build-linux.sh paquets   # .rpm
docker run --rm -v "$PWD:/src" -w /src debian:12 packaging/test-linux-package.sh paquets   # test d'installation
```

```bat
rem Windows, après la compilation :
cd build\windows-msvc && cpack -C Release -G WIX
```

`-DTLSRELAY_FETCH_DEPS=ON` remplace les dépendances du système (Asio, CLI11, spdlog, yaml-cpp) par des versions épinglées, liées statiquement ; seul OpenSSL reste celui de la distribution. Licence : [LICENSE](LICENSE) ; composants tiers : [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt).

### Windows (x64)

Prérequis : Visual Studio 2022 et [vcpkg](https://github.com/microsoft/vcpkg), avec la variable `VCPKG_ROOT`. Les dépendances, dont OpenSSL, sont installées par vcpkg à partir de `vcpkg.json`.

```bat
cmake --preset windows-msvc
cmake --build --preset windows-release
ctest --preset windows-release
```

## Utilisation

```sh
tlsrelay check-config -c examples/server.yaml   # valide une configuration
tlsrelay run -c examples/server.yaml            # serveur, au premier plan
tlsrelay run -c examples/client.yaml -v         # client, mode verbose (-vv : trace)
tlsrelay version                                # versions de tlsrelay et d'OpenSSL
```

### Essai en TLS

La PKI est lue dans le répertoire `credentials.pki_root` (format décrit dans [SPEC §7.2](docs/SPEC.md)). Pour un essai, `tools/make-test-pki.sh` crée une PKI de test (racine, AC Serveurs, AC Clients, certificats) et les deux répertoires prêts à l'emploi :

```sh
tools/make-test-pki.sh /tmp/pki-test          # nécessite la commande openssl
```

```yaml
# serveur                                   # client
credentials: { pki_root: /tmp/pki-test/serveur }   credentials: { pki_root: /tmp/pki-test/client }
ports:                                      ports:
  tls: { listen: "0.0.0.0:9002" }             tls: { listen: "127.0.0.1:7002", upstream: "relais:9002", server_name: relay.test }
```

Pour le port `mtls`, le client présente le certificat `CN=client.test,O=tlsrelay-test` de la PKI de test ; la liste blanche du serveur doit contenir ce sujet :

```yaml
peers:
  - { name: poste-local, ip: 127.0.0.1, ports: [mtls], subject: "CN=client.test,O=tlsrelay-test" }
```

Les clés produites par ce script ne sont pas chiffrées : il est réservé aux essais. Pour une PKI réelle, utiliser la mini-AC (ci-dessous).

### PKI de production : mini-AC et demandes de signature

La clé de chaque instance est générée sur sa machine et ne la quitte jamais ; seule la demande de signature (CSR) circule. L'AC (racine, AC Serveurs, AC Clients, clés chiffrées par phrase de passe) reste sur un poste d'administration.

```sh
# Poste d'administration, une seule fois
tlsrelay ca init --dir /ac --org MonEntreprise

# Machine du serveur tlsrelay
tlsrelay pki gen-csr -c serveur.yaml --subject "CN=relais.exemple,O=MonEntreprise" --san relais.exemple
#   → transmettre <pki_root>/v1/request.csr au poste d'administration

# Poste d'administration : signature selon la politique de l'AC
tlsrelay ca sign --dir /ac --role server --csr request.csr --san relais.exemple --out kit-relais
#   → retransmettre le répertoire kit-relais

# Machine du serveur
tlsrelay pki install  -c serveur.yaml --from kit-relais   # complète v1 et la contrôle
tlsrelay pki activate -c serveur.yaml v1
```

Même parcours pour un client mTLS avec `--role client` (sans `--san`). La politique de l'AC impose une clé ECDSA P-256 et ses propres extensions (celles de la demande sont ignorées), refuse un sujet déjà attribué (sauf `--renew`) et tient l'inventaire (`tlsrelay ca list --dir /ac`). La phrase de passe est demandée au clavier, ou lue dans `--passphrase-file` ou la variable `TLSRELAY_CA_PASSPHRASE`.

Révocation : `tlsrelay ca revoke --dir /ac --serial <série> --reason keyCompromise --out crl.pem` publie les CRL, à installer sur chaque instance avec `tlsrelay pki crl -c <config> crl.pem` ; le certificat est refusé au handshake et les canaux qui l'utilisent sont fermés (SPEC §7.7). Les CRL se republient avant échéance (`tlsrelay ca crl`, 30 jours par défaut). Toutes les opérations de l'AC sont tracées dans un journal d'audit chaîné par SHA-256 (`tlsrelay ca audit --dir /ac`).

### Rotation des certificats

Une génération PKI est un répertoire `vN` du `pki_root` ; le fichier `current` désigne la génération en service. Pour renouveler un certificat (nouvelle clé) :

```sh
tlsrelay pki gen-csr -c serveur.yaml --subject "CN=relais.exemple,O=MonEntreprise"   # crée v2
tlsrelay ca sign --dir /ac --role server --csr request.csr --san relais.exemple --renew --out kit-v2
tlsrelay pki install  -c serveur.yaml --from kit-v2   # fichiers de confiance repris de v1 ; garde-fou vérifié
tlsrelay pki activate -c serveur.yaml v2              # prise en compte en 2 s par le service en cours
```

Les nouvelles connexions utilisent v2. Les canaux déjà ouverts restent sur v1 jusqu'à leur prochaine renégociation (au plus `limits.session_lifetime`, 1 h par défaut), qui les fait passer sur v2 sans coupure ; v1 est libérée quand plus aucune connexion ne l'utilise. Pour changer de racine, suivre les 3 étapes de [SPEC §7.5](docs/SPEC.md).

### Renégociation

Sur les ports `tls` et `mtls`, chaque canal change de connexion TLS à l'échéance de `limits.session_lifetime` (± `session_jitter`). Les données continuent de passer pendant la renégociation et l'application ne voit aucune coupure. Le même mécanisme reprend la session si la connexion tombe, dans la limite de `limits.renegotiation_grace` (30 s par défaut). Avec `logging.level: debug`, chaque renégociation est journalisée.

### Outillage de test : tlsrelay-testkit

```sh
tlsrelay-testkit pki --out /tmp/pki                         # PKI de test (relancé : nouvelle génération)
tlsrelay-testkit echo --listen 127.0.0.1:8080               # destination d'écho
tlsrelay-testkit load --target 127.0.0.1:7003 --channels 5000 --bytes 1MiB --hold 10s   # empreinte SHA-256 par canal
tlsrelay-testkit throughput --target 127.0.0.1:7003 --duration 10s     # --rate 200 : débit limité (Mbit/s)
tlsrelay-testkit latency --target 127.0.0.1:7003            # comparer avec --target 127.0.0.1:8080 (direct)
tlsrelay-testkit proxy --listen 127.0.0.1:9100 --target 127.0.0.1:9003 --delay 20ms --cut-every 60s
```

`--json` donne un résultat exploitable par un script. `tests/perf/perf.sh <build> [canaux]` vérifie les objectifs de performance ; `tests/perf/soak.sh <build> <minutes>` mène l'endurance (72 h : 4320 minutes, sur une machine dédiée).

Mesures (Linux, poste de développement, chaîne mTLS complète client → serveur) :

| Indicateur | Objectif | Mesuré |
|---|---|---|
| Canaux simultanés | 5 000 | 5 000, tous intègres |
| Débit par canal | 100 Mbit/s | ≈ 800 Mbit/s |
| Latence ajoutée (aller-retour) | < 1 ms | ≈ 0,35 ms |
| Mémoire | — | ≈ 50 Kio par canal ouvert et par relais (≈ 250 Mio pour 5 000 canaux) |

En CI, `perf.sh` mesure le débit cadencé à 500 Mbit/s (variable `RATE`, 0 : sans limite) et le flux continu de l'endurance tourne à 200 Mbit/s (`STREAM_RATE`).

**Limite connue : flux saturé sur la boucle locale.** Un canal poussé à son maximum dans les deux sens à la fois (≈ 1 Gbit/s, relais et destination sur la même machine) peut se figer plusieurs dizaines de secondes, sans perte ni corruption de données. Le relais applique alors sa contre-pression et suspend la lecture d'une socket ; le noyau jette des segments en réception (`TCPRcvQDrop` dans `nstat`) au lieu de fermer la fenêtre à temps, et l'émetteur attend entre deux retransmissions un délai qui double à chaque essai (jusqu'à 25 s et plus). Observé sur les machines de CI GitHub, non reproduit sur un poste de développement ; l'analyse continue hors de la CI de chaque push. `tlsrelay channels` (état du contrôle de flux de chaque canal) et le workflow « Stress performances » servent au diagnostic.

### Sécurité et recette

| Outil | Vérifie |
|---|---|
| `tests/test_attacks.cpp` | Certificats expirés ou pas encore valides, mauvais usage, faux serveur, trames hostiles, inondation sans handshake, injection et secrets dans les journaux |
| `tests/lifecycle/tls-scan.sh` | Configuration TLS vue de l'extérieur (sslyze ; testssl.sh avec `TESTSSL=<chemin>`) |
| `tools/check-hardening.sh`, `tools/check-hardening.ps1` | PIE, RELRO, NX, protection de pile, FORTIFY ; ASLR, DEP, CFG |
| `tools/check-deps.sh` | OpenSSL livré sous Windows à la dernière version corrective de la branche 3.5 |
| `cmake -DTLSRELAY_MSVC_ANALYZE=ON` | Analyse statique MSVC (`/analyze`) |
| `tools/recette.ps1` | Recette automatisée sur une station (voir le [cahier de recette](docs/RECETTE.md)) |

```powershell
.\tools\recette.ps1 -BuildDir 'C:\Program Files\tlsrelay' -Services -Keep   # rapport.md dans %ProgramData%\tlsrelay\recette-<date>
```

Sous Linux (PowerShell 7), en mode console : `pwsh tools/recette.ps1 -BuildDir build/linux-release/src/app -TestkitDir build/linux-release/src/testkit`.

### Service et administration

```sh
sudo tlsrelay service install --instance agence --boot   # config : /etc/tlsrelay/agence.yaml
sudo tlsrelay start   --instance agence
sudo tlsrelay status  --instance agence                  # PID, OpenSSL, génération PKI, canaux par port
sudo tlsrelay reload  --instance agence                  # liste blanche, PKI, niveaux de journalisation
sudo tlsrelay stop    --instance agence --timeout 30s    # drain puis arrêt ; kill : arrêt immédiat
```

Sous Windows, dans une console administrateur : mêmes commandes (service `tlsrelay-agence`, configuration `%ProgramData%\tlsrelay\agence.yaml`, compte `NT SERVICE\tlsrelay-agence`). Le compte du service doit pouvoir lire la configuration, la liste blanche et la PKI.

Une instance lancée en console (`tlsrelay run`) se pilote de la même façon avec `-c <config>` au lieu de `--instance`. Autres commandes : `channels` (canaux ouverts), `metrics` (format Prometheus), `log-level debug` (journalisation à chaud), `log-reopen` (rotation). Détails : [SPEC §10](docs/SPEC.md).

- Ctrl+C (ou `SIGTERM`) : arrêt propre, avec drain des canaux pendant `limits.shutdown_timeout` ; un second Ctrl+C force l'arrêt immédiat.
- Codes de sortie : 0 (succès), 1 (erreur d'exécution), 2 (configuration invalide).
