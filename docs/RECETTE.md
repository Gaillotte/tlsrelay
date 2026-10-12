# tlsrelay — cahier de recette

Recette de la livraison 1 par le responsable du projet, sur une seule station Windows (PLAN §5.7). Le script `tools/recette.ps1` déroule les scénarios automatisés et produit le rapport ; les étapes manuelles de la section 5 complètent les points qu'un script ne peut pas vérifier seul (redémarrage de la station, droits d'un autre utilisateur, lecture des journaux). Les résultats sont reportés dans le procès-verbal ([PV-RECETTE.md](PV-RECETTE.md)).

## 1. Banc de recette

```
                                       station Windows
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│ testkit ──► tlsrelay rc-client ──(proxy du testkit, port mtls)──► tlsrelay rc-server ──► écho │
│              127.0.0.2                 127.0.0.5                       127.0.0.3      127.0.0.4│
│                                                                                               │
│ VM Hyper-V Ubuntu 22.04 (commutateur interne) : instances Linux des tests croisés (R13)       │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Élément | Adresse | Ports |
|---|---|---|
| Client `rc-client` | 127.0.0.2 (aussi adresse source vers le serveur) | 17101 plain, 17102 tls, 17103 mtls |
| Proxy de perturbations (testkit) | 127.0.0.5 | 19203 → 19103 du serveur |
| Serveur `rc-server` | 127.0.0.3 | 19101 plain, 19102 tls, 19103 mtls |
| Destination (écho du testkit) | 127.0.0.4 | 18080 |

Les ports plain et tls vont directement du client au serveur ; le port mtls passe par le proxy, qui coupe les connexions dans le scénario R06. La liste blanche du serveur n'autorise que 127.0.0.2, avec le sujet `CN=rc-client,O=Recette` sur le port mtls.

## 2. Prérequis

**Station Windows**
- Windows 10 ou 11, édition Professionnel ou Entreprise (Hyper-V pour les tests croisés) ; compte administrateur.
- tlsrelay et tlsrelay-testkit (paquet de la livraison, ou répertoire de compilation `build\windows-msvc\src\app\Release` et `...\src\testkit\Release`).
- PowerShell 5.1 (inclus dans Windows) ou PowerShell 7 ; client OpenSSH (inclus dans Windows 10 et 11) pour les tests croisés.
- Ports 17101 à 19303 libres sur les adresses de bouclage.

**VM Linux (facultatif, tests croisés R13)**
1. Hyper-V : créer un commutateur virtuel **interne** `tlsrelay-recette`, puis une VM Ubuntu 22.04 reliée à ce commutateur.
2. Adresses fixes, par exemple station `192.168.50.1/24` (carte « vEthernet (tlsrelay-recette) ») et VM `192.168.50.2/24`.
3. Sur la VM : `sudo apt install openssh-server` ; compiler tlsrelay pour cette distribution (README, section « Compilation », Linux) tant que le paquet `.deb` n'est pas livré (phase 11) : les binaires d'une autre distribution n'y fonctionnent pas (versions de bibliothèques différentes) ; ouvrir le port 29303 (`sudo ufw allow 29303/tcp` si le pare-feu est actif).
4. Sur la station : `ssh-keygen` puis copier `%USERPROFILE%\.ssh\id_ed25519.pub` dans `~/.ssh/authorized_keys` de la VM ; vérifier `ssh utilisateur@192.168.50.2` sans mot de passe.
5. Copier sur la station les binaires Linux compilés (`tlsrelay`, `tlsrelay-testkit`) dans un répertoire, par exemple `C:\recette\linux`.

## 3. Lancement

Dans un PowerShell **administrateur**, depuis la racine du dépôt (ou du paquet) :

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\tools\recette.ps1 -BuildDir 'C:\Program Files\tlsrelay' -Services -Keep `
    -LinuxHost recette@192.168.50.2 -LinuxBuildDir C:\recette\linux -LocalAddress 192.168.50.1
```

| Option | Effet |
|---|---|
| `-BuildDir` | Répertoire de `tlsrelay.exe` ; `-TestkitDir` si le testkit est ailleurs |
| `-Services` | Instances installées comme services Windows (`tlsrelay-rc-server`, `tlsrelay-rc-client`), sous leur compte virtuel, fichiers de chaque instance réservés à son compte et aux administrateurs. Sans cette option : processus en console |
| `-Keep` | Instances laissées en service après les scénarios, pour les étapes manuelles ; `arret-recette.ps1` (dans le répertoire de travail) arrête tout ensuite |
| `-LinuxHost`, `-LinuxBuildDir`, `-LocalAddress`, `-SshPort` | Tests croisés avec la VM (R13) |
| `-Quick` | Durées réduites (contrôle rapide) |
| `-WorkDir` | Répertoire de travail et du rapport (défaut : `%ProgramData%\tlsrelay\recette-<date>` en mode services, `.\recette-<date>` sinon) |

Durée : environ 10 minutes (3 minutes avec `-Quick`). Le rapport `rapport.md` du répertoire de travail donne les versions, les empreintes SHA-256 des binaires, le résultat et le détail de chaque scénario, et des extraits de journaux en cas d'échec. Le code de sortie vaut 0 si tous les scénarios automatisés sont OK.

## 4. Scénarios automatisés

| N° | Scénario | Résultat attendu |
|---|---|---|
| R01 | PKI de recette par la mini-AC : `ca init`, `pki gen-csr`, `ca sign`, `pki install`, `pki activate`, `check-pki` pour le serveur et le client | Hiérarchie créée, certificats émis et installés ; un second certificat pour le même sujet est refusé |
| R02 | Démarrage des instances (services ou console) | Configurations valides ; génération PKI v1 et liste blanche chargées ; services sous leur compte virtuel |
| R03 | Canaux simultanés sur les trois ports (500 par port, 100 avec `-Quick`) | Tous intègres (empreinte SHA-256 par canal) |
| R04 | Débit et latence | Débit ≥ 100 Mbit/s (mesuré cadencé à 200) ; latence ajoutée < 1 ms |
| R05 | Liste blanche : adresse du client retirée, `reload`, puis rétablie | Nouveaux canaux refusés puis de nouveau acceptés ; refus comptés |
| R06 | Coupures réseau toutes les 5 s sur le port mtls (proxy) | Flux continu intègre ; reprises de session effectuées |
| R07 | Renégociation (`session_lifetime` 30 s) pendant un flux continu | Au moins une renégociation ; flux intègre, application jamais coupée |
| R08 | Rotation de la PKI à chaud (génération v2 du serveur, `--renew`) | Bascule sans interruption ; nouveaux canaux sur v2 |
| R09 | Changement de racine en trois étapes (SPEC §7.5) avec une seconde AC, flux continu pendant toute la procédure | Canaux acceptés à chaque étape ; flux intègre ; aucune génération refusée |
| R10 | Journalisation : niveau `debug` à chaud, marqueur relayé | Canaux journalisés en `debug` ; ni données relayées, ni clé privée, ni phrase de passe dans les journaux |
| R11 | Administration : `status`, `channels`, `metrics` | Réponses complètes |
| R12 | Cycle de vie : `stop` (drain) et redémarrage du client, `kill` et redémarrage du serveur ; `restart` du service | Service rétabli à chaque fois ; nouveau processus après `restart` ; aucune exception journalisée |
| R13 | Tests croisés (facultatif) : station → Linux et Linux → station, en mTLS | Tous les canaux intègres dans les deux sens |

## 5. Étapes manuelles

À dérouler après un lancement avec `-Services -Keep`. Commandes : `tlsrelay` désigne `C:\Program Files\tlsrelay-recette\tlsrelay.exe` (copie installée par le script) ; `$rc` désigne le répertoire de travail.

| N° | Étape | Résultat attendu | OK/KO |
|---|---|---|---|
| M01 | **Démarrage au boot.** Pour `rc-server` puis `rc-client` : `tlsrelay service uninstall --instance rc-server`, puis `tlsrelay service install --instance rc-server -c $rc\rc-server.yaml --boot` ; redémarrer la station, puis `tlsrelay status --instance rc-server` | Services démarrés sans intervention ; `status` répond « en service » | |
| M02 | **Arrêt de la station avec des canaux ouverts.** Lancer `tlsrelay-testkit throughput --target 127.0.0.2:17102 --duration 300s --rate 20`, puis redémarrer la station | Après le redémarrage, le journal `$rc\logs\rc-server.log` montre « arrêt demandé », le drain puis « service arrêté » | |
| M03 | **Arrêt immédiat pendant un transfert.** Même flux, puis `tlsrelay kill --instance rc-server` ; ensuite `tlsrelay start --instance rc-server` et `tlsrelay-testkit load --target 127.0.0.2:17102 --channels 50` | Le flux en cours s'arrête (attendu) ; le service redémarre proprement ; les nouveaux canaux sont tous intègres | |
| M04 | **Commande refusée à un non-administrateur.** Ouvrir une session d'un utilisateur standard, puis `tlsrelay status --instance rc-server` | Accès refusé au canal d'administration | |
| M05 | **Niveaux de journalisation.** `tlsrelay log-level --instance rc-server trace`, un échange (`tlsrelay-testkit load --target 127.0.0.2:17103 --channels 5`), puis `log-level ... info` | En `trace` : détail des handshakes (version, suite, chaîne) et des trames ; retour au niveau `info` ; contenu conforme à SPEC §9 | |
| M06 | **Rotation des journaux.** Renommer `$rc\logs\rc-server.log`, puis `tlsrelay log-reopen --instance rc-server` | Nouveau fichier créé ; l'ancien n'est plus écrit | |
| M07 | **Droits des fichiers.** `icacls $rc\pki\rc-server` et `icacls $rc\rc-server.yaml` | Seuls SYSTEM, les Administrateurs et `NT SERVICE\tlsrelay-rc-server` y ont accès | |
| M08 | **Rapport.** Relire `$rc\rapport.md` | Versions de tlsrelay et d'OpenSSL (3.5 LTS) et empreintes conformes à la livraison ; tous les scénarios OK | |
| M09 | **Fin.** `& $rc\arret-recette.ps1` | Services désinstallés, processus arrêtés | |

## 6. Hors du périmètre d'une station unique

Une seule station ne couvre pas un vrai réseau entre machines (NAT, pare-feu, MTU, latence) : les tests croisés de la CI et R13 (VM sur un commutateur interne) le compensent en partie. Un essai complémentaire entre deux machines physiques est recommandé avant la mise en production (PLAN §6), par exemple avec `tools/recette-linux.ps1` depuis une seconde machine.
