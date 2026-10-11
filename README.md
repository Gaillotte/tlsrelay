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

| Phase | Contenu | État |
|---|---|---|
| 0 | Spécification | Terminée |
| 1 | Socle : CMake/vcpkg, configuration et validation, logs et mode verbose, relais en clair, multi-canaux, `idle_timeout`, essais vers la destination, arrêt propre | Terminée |
| 2 | TLS 1.3 sur OpenSSL : port `tls`, ALPN `tlsrelay/1`, vérification du nom et de l'AC émettrice du serveur, chargement et contrôle de la PKI | Terminée |
| 3 | mTLS (certificat client émis par l'AC Clients) et liste blanche des pairs (IP, sujet, ports), rechargée à chaud | Terminée |
| 4 | Rotation à chaud des certificats et des AC jusqu'à la racine (générations, drain, garde-fou, `check-pki`, `pki activate`, `SIGHUP`) | Terminée |
| 5 | Protocole de tunnel `tlsrelay/1` (trames, acquittements, contre-pression, demi-fermeture), renégociation transparente à l'échéance de `session_lifetime`, reprise de session après coupure | Terminée |
| 6 | Cycle de vie : services Windows/systemd, instances nommées, canal d'administration, métriques | À venir |

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

Les clés produites par ce script ne sont pas chiffrées : il est réservé aux essais.

### Rotation des certificats

Une génération PKI est un répertoire `vN` du `pki_root` ; le fichier `current` désigne la génération en service. Pour renouveler un certificat ou une AC :

```sh
cp -r /chemin/pki/v1 /chemin/pki/v2      # puis remplacer les fichiers à renouveler dans v2
tlsrelay check-pki   -c serveur.yaml v2  # contrôles et garde-fou, sans bascule
tlsrelay pki activate -c serveur.yaml v2 # bascule : prise en compte en 2 s par le service en cours
```

Les nouvelles connexions utilisent v2. Les canaux déjà ouverts restent sur v1 jusqu'à leur prochaine renégociation (au plus `limits.session_lifetime`, 1 h par défaut), qui les fait passer sur v2 sans coupure ; v1 est libérée quand plus aucune connexion ne l'utilise. Pour changer de racine, suivre les 3 étapes de [SPEC §7.5](docs/SPEC.md).

### Renégociation

Sur les ports `tls` et `mtls`, chaque canal change de connexion TLS à l'échéance de `limits.session_lifetime` (± `session_jitter`). Les données continuent de passer pendant la renégociation et l'application ne voit aucune coupure. Le même mécanisme reprend la session si la connexion tombe, dans la limite de `limits.renegotiation_grace` (30 s par défaut). Avec `logging.level: debug`, chaque renégociation est journalisée.

- Ctrl+C (ou `SIGTERM`) : arrêt propre, avec drain des canaux pendant `limits.shutdown_timeout` ; un second Ctrl+C force l'arrêt immédiat.
- Codes de sortie : 0 (succès), 1 (erreur d'exécution), 2 (configuration invalide).
