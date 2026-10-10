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
| 2 | TLS 1.3 | À venir |

Dans cette version, seul le port `plain` est disponible ; les ports `tls` et `mtls` sont acceptés par la validation mais refusés au démarrage. Le protocole de tunnel arrive en phase 5 : d'ici là, le client et le serveur se relaient un flux TCP brut.

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

- Ctrl+C (ou `SIGTERM`) : arrêt propre, avec drain des canaux pendant `limits.shutdown_timeout` ; un second Ctrl+C force l'arrêt immédiat.
- Codes de sortie : 0 (succès), 1 (erreur d'exécution), 2 (configuration invalide).
