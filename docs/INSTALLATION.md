# tlsrelay — installation

Installation des paquets de la livraison, mise en service d'une première instance, mise à jour et désinstallation. L'exploitation courante (supervision, journaux, rotation de la PKI, dépannage) est décrite dans [EXPLOITATION.md](EXPLOITATION.md) ; le format de la configuration et le comportement détaillé, dans [SPEC.md](SPEC.md).

## 1. Paquets

| Fichier | Systèmes | Contenu |
|---|---|---|
| `tlsrelay_<version>-1_amd64.deb` | Ubuntu 22.04 et plus récent, Debian 12 et plus récent | `tlsrelay`, documentation, exemples |
| `tlsrelay-testkit_<version>-1_amd64.deb` | idem | `tlsrelay-testkit` (outillage de test et de recette) |
| `tlsrelay-<version>-1.el9.x86_64.rpm` | RHEL 9, Rocky Linux 9, AlmaLinux 9 | `tlsrelay`, documentation, exemples |
| `tlsrelay-testkit-<version>-1.el9.x86_64.rpm` | idem | `tlsrelay-testkit` |
| `tlsrelay-<version>-win64.msi` | Windows 10 et 11, Windows Server 2019 et plus récent (64 bits) | `tlsrelay`, OpenSSL 3.5 LTS, runtime MSVC, documentation ; fonctionnalité facultative « tlsrelay-testkit » (outillage et scripts de recette) |

- Linux : `tlsrelay` utilise l'OpenSSL de la distribution (3.0 ou plus récent), mis à jour par ses correctifs de sécurité ; les autres bibliothèques sont intégrées au binaire.
- Windows : OpenSSL 3.5 LTS est livré dans le paquet ; une mise à jour corrective d'OpenSSL passe par une nouvelle version du paquet.
- `tlsrelay-testkit` n'est pas nécessaire en production ; il sert aux essais de charge, de perturbation et à la recette.

**Intégrité.** Chaque livraison est accompagnée d'un fichier `SHA256SUMS` :

```sh
sha256sum -c SHA256SUMS --ignore-missing          # Linux
```
```powershell
Get-FileHash -Algorithm SHA256 .\tlsrelay-0.1.0-win64.msi   # Windows : comparer avec SHA256SUMS
```

## 2. Installation sous Linux

```sh
# Debian, Ubuntu
sudo apt install ./tlsrelay_0.1.0-1_amd64.deb
# RHEL, Rocky Linux, AlmaLinux
sudo dnf install ./tlsrelay-0.1.0-1.el9.x86_64.rpm
```

Le paquet installe `/usr/bin/tlsrelay`, la documentation et les exemples dans `/usr/share/doc/tlsrelay/`, crée le compte système `tlsrelay` et le répertoire `/etc/tlsrelay` (`0750`, `root:tlsrelay`). Il n'installe ni ne démarre aucune instance : chaque instance est créée par l'administrateur (section 4).

## 3. Installation sous Windows

Double-cliquer sur le MSI, ou en mode silencieux depuis un PowerShell administrateur :

```powershell
msiexec /i tlsrelay-0.1.0-win64.msi /qn                    # tlsrelay seul
msiexec /i tlsrelay-0.1.0-win64.msi /qn ADDLOCAL=ALL       # avec tlsrelay-testkit et les scripts de recette
```

Arborescence : `C:\Program Files\tlsrelay\bin` (exécutables et DLL), `doc` (documentation, exemples), `tools` (scripts de recette, avec testkit). Le répertoire `bin` n'est pas ajouté au `PATH` : les commandes ci-dessous utilisent `tlsrelay` pour `& 'C:\Program Files\tlsrelay\bin\tlsrelay.exe'`.

## 4. Première instance

Exemple : une instance serveur `agence` qui accepte les tlsrelay clients en mTLS sur le port 9003 et relaie vers `10.0.0.5:8080`. Les étapes sont les mêmes pour une instance client (section 4.6).

### 4.1 Configuration

Partir de l'exemple livré :

| | Linux | Windows |
|---|---|---|
| Exemples | `/usr/share/doc/tlsrelay/examples/` | `C:\Program Files\tlsrelay\doc\examples\` |
| Configuration de l'instance | `/etc/tlsrelay/agence.yaml` | `%ProgramData%\tlsrelay\agence.yaml` |
| PKI de l'instance | par exemple `/etc/tlsrelay/agence/pki` | par exemple `%ProgramData%\tlsrelay\agence\pki` |

```yaml
mode: server
instance: agence
credentials: { pki_root: /etc/tlsrelay/agence/pki }
whitelist: { file: /etc/tlsrelay/agence/whitelist.yaml }
destination: { address: 10.0.0.5, port: 8080 }
ports:
  mtls: { listen: "0.0.0.0:9003" }
```

Sans `logging.output`, le journal va dans le journal système (systemd) ou dans `%ProgramData%\tlsrelay\logs\agence.log` (Windows). Le canal d'administration est celui par défaut (ne pas définir `admin.endpoint` pour un service).

### 4.2 Liste blanche

```yaml
peers:
  - name: site-lyon
    ip: 192.0.2.10
    ports: [mtls]
    subject: "CN=site-lyon,O=Exemple"
```

### 4.3 PKI

Sur l'instance, créer la clé et la demande de certificat (la clé ne quitte pas la machine) :

```sh
sudo tlsrelay pki gen-csr -c /etc/tlsrelay/agence.yaml --subject "CN=relay.agence.exemple,O=Exemple" --san relay.agence.exemple
```

Sur le poste de l'AC (mini-AC créée une fois par `tlsrelay ca init --dir <ac>`), signer la demande puis rapporter le kit sur l'instance :

```sh
tlsrelay ca sign --dir <ac> --role server --csr request.csr --san relay.agence.exemple --out kit-agence
```

Sur l'instance :

```sh
sudo tlsrelay pki install -c /etc/tlsrelay/agence.yaml --from kit-agence
sudo tlsrelay pki activate -c /etc/tlsrelay/agence.yaml v1
```

### 4.4 Droits des fichiers

Le compte du service lit la configuration, la liste blanche et la PKI ; personne d'autre que lui et les administrateurs ne doit y accéder.

```sh
sudo chown -R root:tlsrelay /etc/tlsrelay/agence.yaml /etc/tlsrelay/agence
sudo chmod 0640 /etc/tlsrelay/agence.yaml
sudo find /etc/tlsrelay/agence -type d -exec chmod 0750 {} + -o -type f -exec chmod 0640 {} +
```

Sous Windows, après l'installation du service (section 4.5), qui crée le compte virtuel `NT SERVICE\tlsrelay-agence` :

```powershell
icacls "$env:ProgramData\tlsrelay\agence" /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "NT SERVICE\tlsrelay-agence:(OI)(CI)RX"
icacls "$env:ProgramData\tlsrelay\agence.yaml" /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" "NT SERVICE\tlsrelay-agence:R"
```

### 4.5 Service

```sh
sudo tlsrelay check-config -c /etc/tlsrelay/agence.yaml
sudo tlsrelay check-pki -c /etc/tlsrelay/agence.yaml
sudo tlsrelay service install --instance agence --boot      # démarrage avec le système
sudo tlsrelay start --instance agence
sudo tlsrelay status --instance agence
```

Sous Windows, mêmes commandes dans un PowerShell administrateur ; la configuration par défaut est `%ProgramData%\tlsrelay\agence.yaml` (`-c` pour un autre emplacement). Si le service ne démarre pas, la cause est dans `%ProgramData%\tlsrelay\logs\agence.log` (Windows) ou `journalctl -u tlsrelay@agence` (Linux).

### 4.6 Instance client

Même démarche avec `mode: client`, des ports qui déclarent `upstream` et `server_name`, et un certificat de rôle `client` (`tlsrelay ca sign --role client`). Le sujet du certificat client doit figurer dans la liste blanche du serveur, avec l'adresse IP d'où se connecte le client. Exemple : `client.yaml` des exemples.

## 5. Mise à jour

- **Linux** : `sudo apt install ./tlsrelay_<nouvelle version>_amd64.deb` ou `sudo dnf install ./tlsrelay-<nouvelle version>.rpm`. Les instances en service sont relancées avec le nouveau binaire (arrêt avec drain puis démarrage) ; configurations, listes blanches et PKI sont conservées.
- **Windows** : arrêter les instances (`tlsrelay stop --instance <nom>`), installer le nouveau MSI (il remplace l'ancienne version), puis les redémarrer (`tlsrelay start --instance <nom>`).

## 6. Désinstallation

- **Linux** : `sudo apt remove tlsrelay` (ou `sudo dnf remove tlsrelay`) arrête les instances (avec drain) et retire le binaire. `sudo apt purge tlsrelay` retire aussi les unités systemd des instances. `/etc/tlsrelay` (configurations, listes blanches, PKI) et le compte `tlsrelay` sont conservés : à supprimer à la main si nécessaire.
- **Windows** : désinstaller d'abord chaque instance (`tlsrelay service uninstall --instance <nom>`), puis le paquet (« Applications installées », ou `msiexec /x tlsrelay-0.1.0-win64.msi /qn`). `%ProgramData%\tlsrelay` est conservé.
