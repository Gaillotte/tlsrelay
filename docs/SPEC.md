# tlsrelay — Spécification technique

> Version 0.1 (brouillon de la phase 0). Le plan de développement est dans [`PLAN.md`](PLAN.md).
> Les valeurs marquées « par défaut » sont modifiables dans la configuration.

## 1. Vocabulaire

| Terme | Définition |
|---|---|
| **Application** | Programme qui se connecte en clair au `tlsrelay` client |
| **Pair** | Un `tlsrelay` client autorisé à se connecter au `tlsrelay` serveur (liste blanche) |
| **Destination** | Machine (adresse, port) vers laquelle le `tlsrelay` serveur relaie en clair |
| **Canal** | Une connexion de l'application relayée de bout en bout jusqu'à la destination |
| **Session tunnel** | État d'un canal entre les deux `tlsrelay`, identifié par un id de session ; survit aux renégociations |
| **Connexion de transport** | La connexion TCP (et TLS pour les ports 2 et 3) qui porte une session tunnel à un instant donné |
| **Génération** | Ensemble cohérent bi-clé + chaîne + racines de confiance, chargé depuis un répertoire PKI versionné |
| **Renégociation** | Remplacement de la connexion de transport d'une session par une nouvelle, avec handshake complet |

## 2. Topologie et rôles

```
App ──TCP clair──► [client] ══ transport (port 1 clair | port 2 TLS 1.3 | port 3 mTLS) ══► [serveur] ──TCP clair──► Destination
```

| | Client | Serveur |
|---|---|---|
| Écoute | 3 ports locaux, en clair, pour l'application | 3 ports : clair, TLS 1.3, mTLS |
| Se connecte à | Le `tlsrelay` serveur (un `upstream` par port) | La destination unique (3 essais) |
| Présente un certificat | Port 3 : certificat émis par l'AC Clients | Ports 2 et 3 : certificat émis par l'AC Serveurs |
| Vérifie | Certificat du serveur : chaîne vers la racine **et** émis par l'AC Serveurs | Port 3 : chaîne vers la racine, émis par l'AC Clients, sujet et IP dans la liste blanche |
| Initie la renégociation | Oui | Non (l'exige, et ferme la session si elle n'a pas lieu) |

## 3. Paramètres TLS

| Paramètre | Valeur |
|---|---|
| Version | TLS 1.3 uniquement (`SSL_CTX_set_min_proto_version` et `max` = `TLS1_3_VERSION`) |
| Suites | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256` (par défaut) |
| Groupes | `X25519:P-256:P-384` (par défaut) ; `X25519MLKEM768` optionnel si OpenSSL ≥ 3.5 |
| ALPN | `tlsrelay/1`, obligatoire ; handshake refusé sinon |
| SNI | Envoyé par le client (`server_name` de la config) ; vérification du nom d'hôte du certificat serveur |
| Reprise de session | Désactivée pour les renégociations (aucun ticket présenté) ; clés de tickets propres à chaque `SSL_CTX` |
| mTLS (port 3) | `SSL_VERIFY_PEER \| SSL_VERIFY_FAIL_IF_NO_PEER_CERT` |
| Vérification de l'émetteur | Callback de vérification : l'AC qui a émis le certificat feuille doit être l'AC attendue (AC Serveurs côté client, AC Clients côté serveur) |
| Usages | `X509_PURPOSE_SSL_SERVER` / `X509_PURPOSE_SSL_CLIENT` vérifiés sur toute la chaîne |

## 4. Protocole de tunnel `tlsrelay/1`

### 4.1 Format des trames

Tous les entiers sont en ordre réseau (big-endian).

```
 0       1       2       3       4                               8
 +-------+-------+-------+-------+-------------------------------+
 | type  | flags |   réservé (0) |      longueur (u32)           |
 +-------+-------+-------+-------+-------------------------------+
 |                charge utile (longueur octets)                 |
 +---------------------------------------------------------------+
```

- En-tête de 8 octets. `longueur` est la taille de la charge utile seule.
- Taille maximale d'une charge utile : 16 Kio + 64 octets. Au-delà, la connexion est fermée avec l'erreur `FRAME_TOO_LARGE`.
- Un type inconnu, un champ réservé non nul ou une charge utile de taille incohérente avec le type ferment la connexion (`PROTOCOL_ERROR`).

### 4.2 Types de trames

| Code | Trame | Sens | Charge utile |
|---|---|---|---|
| `0x01` | `OPEN` | C → S | `version` u16 (=1), `session_id` 16 octets, `port_kind` u8 (1, 2 ou 3) |
| `0x02` | `OPEN_OK` | S → C | vide |
| `0x03` | `OPEN_FAIL` | S → C | `code` u16, `message` UTF-8 (≤ 256 octets) |
| `0x10` | `DATA` | ↔ | `seq` u64, données (≤ 16 Kio) |
| `0x11` | `ACK` | ↔ | `seq` u64 : dernier numéro reçu en séquence (acquittement cumulatif) |
| `0x12` | `SHUTDOWN_WR` | ↔ | `final_seq` u64 : plus aucune donnée dans ce sens après ce numéro |
| `0x13` | `CLOSE` | ↔ | `code` u16, `message` UTF-8 (≤ 256 octets) |
| `0x20` | `RESUME` | C → S | `session_id` 16 octets, `token` 32 octets, `last_rx_seq` u64 |
| `0x21` | `RESUMED` | S → C | `last_rx_seq` u64 |
| `0x22` | `RESUME_FAIL` | S → C | `code` u16 |
| `0x30` | `PING` | ↔ | `nonce` u64 |
| `0x31` | `PONG` | ↔ | `nonce` u64 |

- `session_id` : 128 bits issus de `RAND_bytes`, choisis par le client.
- Les numéros `seq` commencent à 1 dans chaque sens, et sont propres à chaque sens.
- `PING`/`PONG` servent à détecter un transport mort ; ils ne repoussent **pas** l'échéance d'inactivité.

### 4.3 Ouverture d'un canal

1. L'application se connecte au port N du client.
2. Le client ouvre la connexion de transport vers `upstream` du port N (handshake TLS pour les ports 2 et 3), puis envoie `OPEN`.
3. Le serveur contrôle la liste blanche (section 6), puis se connecte à la destination : jusqu'à 3 essais (section 5.4).
4. En cas de succès : `OPEN_OK`. Sinon : `OPEN_FAIL`, puis fermeture.
5. Entre `OPEN` et `OPEN_OK`, le client lit déjà les données de l'application et les met en tampon, dans la limite de `resume_buffer`.

### 4.4 Transfert et acquittements

- Chaque côté conserve les trames `DATA` envoyées et non acquittées, dans la limite de `resume_buffer` (4 Mio par défaut et par sens).
- Quand le tampon est plein, la lecture de la source (application ou destination) est suspendue : contre-pression, sans perte.
- Un `ACK` est envoyé après 64 Kio reçus ou 100 ms sans acquittement, selon ce qui arrive en premier.
- Une trame `DATA` dont le `seq` n'est pas exactement le suivant attendu est une erreur de protocole, sauf pendant le renvoi qui suit une reprise (section 4.5), où les doublons déjà reçus sont ignorés.

### 4.5 Renégociation transparente (ports 2 et 3)

**Jeton de reprise**

```
token_n = SSL_export_keying_material(connexion_n,
            label   = "EXPORTER-tlsrelay-resume",
            context = session_id || u32(n),
            longueur = 32)
```

- `n` est le numéro de la connexion de transport dans la session (1 pour la première).
- Les deux côtés calculent le jeton dès l'établissement de la connexion `n`. Il sert à reprendre la session sur la connexion `n+1` ; il est à usage unique.

**Déroulement**

1. Échéance : à `session_lifetime × (1 ± session_jitter)` depuis l'établissement de la connexion courante, le client ouvre une nouvelle connexion de transport : handshake complet, sans reprise de session, avec la **génération courante** de certificats et de racines.
2. Le serveur applique les mêmes contrôles qu'à l'ouverture : liste blanche (IP + sujet + AC émettrice). L'entrée de liste blanche doit être **la même** que pour la connexion précédente.
3. Le client envoie `RESUME(session_id, token_n, last_rx_seq)`.
4. Le serveur vérifie le jeton (comparaison à temps constant), le marque comme consommé, répond `RESUMED(last_rx_seq)`.
5. Chaque côté renvoie, sur la nouvelle connexion, les trames non acquittées au-delà du `last_rx_seq` de l'autre, puis reprend le flux normal.
6. L'ancienne connexion est fermée proprement (`close_notify`).

**Échecs**

- Échec du handshake, de la liste blanche ou du jeton : `RESUME_FAIL`, la nouvelle connexion est fermée. Le client réessaie tant que le délai de grâce n'est pas écoulé.
- Le serveur ferme la session (application et destination comprises) si aucun `RESUME` valide n'a eu lieu à `session_lifetime + renegotiation_grace`.
- On ne revient jamais à une connexion de transport plus ancienne.

**Reprise après coupure** (option `resume_on_failure`, activée par défaut) : si la connexion de transport tombe avant l'échéance, le client applique la même procédure, dans la limite de `renegotiation_grace`.

**Port 1** : pas de `session_lifetime` ni de reprise (le jeton ne peut pas être protégé sans TLS). Seul `idle_timeout` s'applique.

### 4.6 Fermeture

- Fin d'un sens : `SHUTDOWN_WR(final_seq)`, puis `shutdown(SD_SEND)` côté application ou destination une fois toutes les données livrées.
- Le canal est fermé quand les deux sens sont terminés et acquittés, ou sur `CLOSE`.
- Codes de fermeture :

| Code | Nom | Cause |
|---|---|---|
| 0 | `NORMAL` | Fin normale |
| 1 | `IDLE_TIMEOUT` | Inactivité |
| 2 | `LIFETIME_EXCEEDED` | Pas de renégociation dans le délai de grâce |
| 3 | `PEER_REVOKED` | Pair retiré de la liste blanche |
| 4 | `DEST_UNREACHABLE` | 3 essais vers la destination échoués |
| 5 | `SHUTDOWN` | Arrêt du service |
| 6 | `PROTOCOL_ERROR` | Trame invalide |
| 7 | `FRAME_TOO_LARGE` | Trame trop grande |
| 8 | `BUFFER_OVERFLOW` | Dépassement du tampon de reprise |
| 9 | `NOT_AUTHORIZED` | Refus de la liste blanche |
| 10 | `INTERNAL_ERROR` | Erreur interne |

## 5. Canaux et délais

### 5.1 États d'un canal

```
            OPEN envoyé                 OPEN_OK
 OPENING ───────────────► DIALING ─────────────────► ESTABLISHED ◄──────────┐
    │                       │ OPEN_FAIL                 │   │                 │ RESUMED
    │                       ▼                           │   │ échéance /      │
    └──────────────────► CLOSED ◄───────────────────────┘   │ coupure         │
                            ▲    CLOSE / timeout /           ▼                 │
                            │    les deux sens finis      MIGRATING ──────────┘
                            └───────────────────────────────┘ délai de grâce dépassé
```

`DIALING` n'existe que côté serveur (connexion à la destination) ; côté client, l'état équivalent est l'attente de `OPEN_OK`.

### 5.2 Paramètres

| Paramètre | Défaut | Portée |
|---|---|---|
| `idle_timeout` | 5 min | Ports 1, 2, 3 ; aucune donnée applicative dans aucun des deux sens |
| `session_lifetime` | 1 h | Ports 2, 3 |
| `session_jitter` | 10 % | Ports 2, 3 |
| `renegotiation_grace` | 30 s | Ports 2, 3 |
| `resume_buffer` | 4 Mio | Par sens et par canal |
| `handshake_timeout` | 10 s | Ports 2, 3 |
| `max_channels` | 5 000 | Par port |

Règles de cohérence : `idle_timeout` < `session_lifetime` ; `renegotiation_grace` < `session_lifetime` / 2 ; `session_jitter` ≤ 50 %.

### 5.3 Inactivité

L'échéance est repoussée par toute trame `DATA` (dans les deux sens) et par toute donnée reçue de l'application ou de la destination. Les trames `ACK`, `PING`, `PONG` et la renégociation ne la repoussent pas.

### 5.4 Connexion à la destination

- Jusqu'à `dial_retries` essais (3 par défaut), chacun limité par `dial_timeout` (5 s).
- Attente avant l'essai suivant : `dial_backoff` (1 s), doublée à chaque essai (1 s, puis 2 s).
- Après le dernier échec : `OPEN_FAIL(DEST_UNREACHABLE)` et métrique `station_dial_failures`.

## 6. Liste blanche (mode serveur)

### 6.1 Format

```yaml
# whitelist.yaml
peers:
  - name: agence-lyon            # unique
    ip: 192.0.2.10               # adresse ou plage CIDR, IPv4 ou IPv6
    ports: [mtls]                # sous-ensemble de [plain, tls, mtls] ; défaut : tous
    subject: "CN=relay-lyon.example,O=MonEntreprise"   # obligatoire pour mtls
  - name: labo-test
    ip: 198.51.100.0/28
    ports: [plain, tls]
```

### 6.2 Règles

| Port | Contrôle à l'acceptation TCP | Contrôle après handshake |
|---|---|---|
| 1 (`plain`) | IP dans une entrée autorisant `plain` | — |
| 2 (`tls`) | IP dans une entrée autorisant `tls` | — |
| 3 (`mtls`) | IP dans une entrée autorisant `mtls` (rejet avant handshake sinon) | Chaîne valide jusqu'à une racine de confiance, feuille émise par l'AC Clients, DN **exactement** égal au `subject` d'une entrée qui contient aussi l'IP |

- Comparaison du DN : forme canonique (`X509_NAME_cmp`), donc insensible à la casse et aux espaces superflus, mais sensible à l'ordre des composants. Le DN s'écrit au format RFC 4514, le composant le plus spécifique en premier ; les noms à plusieurs valeurs (`+`) et les valeurs hexadécimales (`#`) ne sont pas acceptés.
- `ports` absent : tous les ports, sauf `mtls` si l'entrée n'a pas de `subject`.
- Validation du fichier : clés connues uniquement, noms uniques, syntaxe IP/CIDR (bits d'hôte nuls) et DN, `subject` obligatoire si `mtls` est explicitement autorisé, un même `subject` ne peut pas figurer dans deux entrées. Une liste vide est acceptée avec un avertissement.
- Rechargement : le contenu du fichier est comparé toutes les 2 secondes ; tout changement entraîne un rechargement (commande `reload` en phase 6). Un fichier invalide est rejeté et la liste en vigueur est conservée. Le journal `config` indique les pairs ajoutés, retirés et modifiés.
- Une adresse IPv4 reçue sur une socket IPv6 (`::ffff:a.b.c.d`) est comparée comme une IPv4.
- Pairs retirés : leurs canaux sont fermés immédiatement (`PEER_REVOKED`) ; option `revoke_mode: next_renegotiation` pour attendre plutôt la prochaine renégociation.
- Les contrôles sont rejoués à chaque renégociation.

## 7. PKI

### 7.1 Hiérarchie

| Certificat | Clé | Validité (défaut) | Extensions |
|---|---|---|---|
| AC Racine | ECDSA P-384 | 15 ans | `CA:true`, `keyCertSign`, `cRLSign` |
| AC Serveurs | ECDSA P-384 | 5 ans | `CA:true, pathlen:0`, `keyCertSign`, `cRLSign`, `extendedKeyUsage=serverAuth` |
| AC Clients | ECDSA P-384 | 5 ans | `CA:true, pathlen:0`, `keyCertSign`, `cRLSign`, `extendedKeyUsage=clientAuth` |
| Certificat serveur | ECDSA P-256 | 1 an | `CA:false`, `digitalSignature`, `serverAuth`, SAN DNS et/ou IP |
| Certificat client | ECDSA P-256 | 1 an | `CA:false`, `digitalSignature`, `clientAuth` |

### 7.2 Répertoire PKI d'une instance

```
<pki_root>/
  ├── v1/
  │   ├── key.pem            # clé privée (droits restreints)
  │   ├── cert.pem           # certificat feuille
  │   ├── chain.pem          # AC intermédiaire qui a émis la feuille
  │   ├── trust-roots.pem    # une ou plusieurs racines de confiance
  │   └── trust-issuer.pem   # AC attendue(s) chez le pair (AC Serveurs côté client, AC Clients côté serveur) :
  │                          # une par racine, donc deux pendant un changement de racine
  ├── v2/ ...
  └── current                # fichier texte contenant « v2 », remplacé par renommage atomique
```

- `key.pem` : PKCS#8 en clair, protégé par les droits du système (propriétaire seul sous Linux, ACL SYSTEM et Administrateurs sous Windows). Un avertissement est émis si les droits sont trop larges.
- Une génération = le contenu complet d'un répertoire `vN`.

### 7.3 Validation d'une génération (avant bascule)

1. Tous les fichiers sont présents et lisibles.
2. La clé correspond au certificat feuille.
3. La chaîne feuille → `chain.pem` → racine se vérifie avec `trust-roots.pem`.
4. Contraintes des AC : `CA:true`, `keyCertSign`, `pathlen`, racine auto-signée.
5. Dates valides sur toute la chaîne ; avertissement si une expiration survient dans moins de `expiry_warning` (30 jours).
6. Usage de la feuille conforme au rôle (`serverAuth` / `clientAuth`).
7. Garde-fou de rotation, par rapport à la génération courante :
   - au moins une racine de confiance commune ;
   - le nouveau certificat (s'il y en a un) se rattache à une racine de confiance de la génération courante.
   
   Les deux conditions sont toujours remplies par la procédure en 3 étapes (§7.5) ; elles refusent un passage direct d'une racine à une autre. `trust-roots.pem` est lu dès qu'il est présent, même quand il ne sert pas à vérifier un pair (serveur sans port mtls), pour que ce contrôle soit possible. `pki activate --force` permet de passer outre (urgence).

Un échec conserve la génération courante et produit une erreur dans la catégorie `config`.

### 7.4 Bascule et drain

- Déclenchement : le contenu de `<pki_root>/current` est comparé toutes les 2 secondes (si `credentials.watch` vaut `true`), ou rechargement explicite (`SIGHUP` sous Linux ; commande `reload` en phase 6).
- Chaque génération correspond à un `SSL_CTX` par port TLS. Les contextes courants sont remplacés sous verrou ; chaque connexion garde une référence sur le sien.
- Une génération retirée est libérée quand sa dernière connexion se ferme ; le journal `config` l'indique (« génération vN libérée »).
- Une génération refusée (contrôles ou garde-fou) laisse la génération courante en service ; l'erreur est journalisée.
- Comme les renégociations utilisent la génération courante, une génération retirée est libérée au plus tard après `session_lifetime + renegotiation_grace` (ports 2 et 3), ou à la fermeture des canaux (port 1).
- `reload --kill-old` : ferme immédiatement les connexions des générations retirées (révocation d'urgence).

### 7.5 Changement de racine

| Étape | `trust-roots.pem` | Feuille et `chain.pem` | Condition pour passer à l'étape suivante |
|---|---|---|---|
| 1. Pré-confiance | ancienne + nouvelle racine | ancienne PKI | Tous les `tlsrelay` sont à l'étape 1 |
| 2. Bascule | ancienne + nouvelle racine | nouvelle PKI | Tous les `tlsrelay` sont à l'étape 2 |
| 3. Retrait | nouvelle racine | nouvelle PKI | — |

### 7.6 Commandes PKI (livraison 1)

| Commande | Effet |
|---|---|
| `tlsrelay pki gen-csr --role server\|client --subject DN [--san ...]` | Génère une clé P-256 dans le prochain `vN` et écrit `request.csr` |
| `tlsrelay pki install --cert cert.pem --chain chain.pem --roots roots.pem --issuer issuer.pem` | Complète le répertoire `vN` |
| `tlsrelay check-pki -c <config> [vN]` | Applique la validation de la section 7.3, garde-fou compris, sans bascule (par défaut : génération courante) |
| `tlsrelay pki activate -c <config> <vN> [--force]` | Contrôle comme `check-pki`, puis met à jour `current` (renommage atomique) |
| `tlsrelay ca init --dir <ca_dir>` | Crée la racine et les deux AC intermédiaires (clés chiffrées, phrase de passe demandée) |
| `tlsrelay ca sign --role server\|client --csr request.csr` | Signe une demande avec l'AC correspondante ; applique la politique de l'AC (usages, durée) en ignorant les extensions demandées ; refuse une clé non P-256 ou un sujet déjà attribué |

Clés des AC : PKCS#8 chiffré AES-256-CBC, dérivation scrypt.

## 8. Configuration

### 8.1 Mode client

```yaml
mode: client
instance: rc-client
logging:
  level: info
  categories: { activity: info, config: info }
  format: text                 # text | json
  output: stderr               # stderr | <chemin> | syslog | eventlog
credentials:
  pki_root: /etc/tlsrelay/rc-client/pki
  watch: true
  expiry_warning: 30d
limits:
  idle_timeout: 5m
  session_lifetime: 1h
  session_jitter: 10%
  renegotiation_grace: 30s
  resume_buffer: 4MiB
  handshake_timeout: 10s
  max_channels: 5000
  shutdown_timeout: 30s
ports:
  plain: { listen: "127.0.0.1:7001", upstream: "relay.example:9001" }
  tls:   { listen: "127.0.0.1:7002", upstream: "relay.example:9002", server_name: relay.example }
  mtls:  { listen: "127.0.0.1:7003", upstream: "relay.example:9003", server_name: relay.example }
source_address: 0.0.0.0        # adresse source des connexions vers le serveur (optionnel)
```

### 8.2 Mode serveur

```yaml
mode: server
instance: rc-server
destination:
  address: 10.0.0.42
  port: 8080
  dial_timeout: 5s
  dial_retries: 3
  dial_backoff: 1s
whitelist:
  file: /etc/tlsrelay/rc-server/whitelist.yaml
  revoke_mode: immediate       # immediate | next_renegotiation
credentials: { pki_root: /etc/tlsrelay/rc-server/pki, watch: true }
limits: { ... }                # identique au mode client
ports:
  plain: { listen: "0.0.0.0:9001" }
  tls:   { listen: "0.0.0.0:9002" }
  mtls:  { listen: "0.0.0.0:9003" }
```

Un port absent de la configuration n'est pas ouvert.

### 8.3 Règles de validation (partagées avec l'éditeur)

- `mode` ∈ {client, server} ; `destination` obligatoire en mode serveur, interdite en mode client ; `upstream` obligatoire pour chaque port en mode client.
- Ports dans 1–65535, sans doublon d'adresse d'écoute.
- Durées et tailles au format `<nombre><unité>` ; règles de cohérence de la section 5.2.
- `pki_root` obligatoire si `tls` ou `mtls` est configuré ; génération courante valide (section 7.3).
- `whitelist.file` obligatoire en mode serveur ; fichier valide (section 6.2).
- Niveaux de log ∈ {error, info, debug, trace}.

## 9. Journalisation

| Niveau | Contenu |
|---|---|
| `error` | Erreurs |
| `info` | Démarrage, arrêt, rechargements, rejets de liste blanche, échecs vers la destination, **toutes les opérations de configuration** |
| `debug` | Ouverture et fermeture de chaque canal, renégociations, générations retirées et libérées |
| `trace` | Détail des handshakes (version, suite, chaîne présentée), trames (type, `seq`, taille), essais de connexion |

- Champs de contexte : `instance`, `channel_id`, `session_id` (tronqué), `generation`, `peer`, `port`.
- Jamais journalisés : clés privées, jetons, secrets dérivés, contenu des données relayées.
- Changement à chaud : `tlsrelay log-level <niveau>` ou `tlsrelay log-level <catégorie>=<niveau>`.
- `tlsrelay log-reopen` (et `SIGUSR1` sous Linux) rouvre le fichier de log.

## 10. Ligne de commande et cycle de vie

| Commande | Effet |
|---|---|
| `tlsrelay run -c <config> [-v\|-vv\|-q]` | Exécution en console (Ctrl+C : arrêt propre ; second Ctrl+C : arrêt immédiat) |
| `tlsrelay service install [--instance N] [--boot]` | Installe le service (systemd `tlsrelay@N`, service Windows `tlsrelay-N`) |
| `tlsrelay service uninstall [--instance N]` | Arrête et désinstalle |
| `tlsrelay start\|stop\|restart [--instance N] [--timeout 30s]` | Démarrage ; arrêt propre avec drain ; redémarrage |
| `tlsrelay kill [--instance N]` | Arrêt immédiat |
| `tlsrelay reload [--instance N] [--kill-old] [--force]` | Recharge config, liste blanche, PKI, sans arrêt |
| `tlsrelay status [--instance N] [--channels]` | État, PID, durée, version OpenSSL, génération courante, canaux par port |
| `tlsrelay check-config -c <config>` | Valide une configuration sans la charger |

- Canal d'administration : socket Unix `/run/tlsrelay/<instance>.sock` (root ou groupe `tlsrelay`) ; named pipe `\\.\pipe\tlsrelay-<instance>` (Administrateurs et SYSTEM).
- Verrou d'instance : une seule exécution par instance.
- Sockets d'écoute : `SO_REUSEADDR` (Linux), `SO_EXCLUSIVEADDRUSE` (Windows).
- Au démarrage : contrôle de la version d'OpenSSL chargée (≥ 3.0), écrite dans les logs.

## 11. Points ouverts

- Format exact des métriques (Prometheus texte via le canal d'administration, ou point HTTP local).
- Nommage définitif des paquets et chemins par défaut sous Windows (`%ProgramData%\tlsrelay\...`).
