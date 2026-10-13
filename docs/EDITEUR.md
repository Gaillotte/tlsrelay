# tlsrelay-admin — guide de l'éditeur

`tlsrelay-admin` est l'éditeur graphique de tlsrelay (livraison 1.1), pour un poste d'administration Windows. Il édite les configurations et les listes blanches des instances, prépare leurs paquets de déploiement et gère la mini-AC. Il ne se connecte à aucune instance : il travaille sur des fichiers, que les instances lisent ensuite.

## 1. Installation

Fonctionnalité « tlsrelay-admin » du MSI (INSTALLATION §3) :

```powershell
msiexec /i tlsrelay-<version>-win64.msi /qn ADDLOCAL=ALL
```

L'éditeur est installé dans `C:\Program Files\tlsrelay\bin`, avec les bibliothèques Qt 6 (LGPLv3, voir `doc\THIRD-PARTY-NOTICES.txt` et `doc\LICENSES`), et un raccourci est ajouté au menu Démarrer. Il peut aussi être ouvert sur un fichier : `tlsrelay-admin.exe C:\chemin\agence.yaml`.

Contrôle d'un fichier sans fenêtre, avec les règles du service (code de sortie 0 : valide, 1 : invalide, 2 : illisible ; messages dans le fichier `--report`) :

```powershell
Start-Process -Wait -PassThru "C:\Program Files\tlsrelay\bin\tlsrelay-admin.exe" `
    -ArgumentList '--check', 'C:\chemin\agence.yaml', '--report', 'C:\chemin\controle.txt'
```

## 2. Configuration d'une instance

- **Fichier > Nouvelle configuration serveur / client**, ou **Ouvrir** une configuration existante. Un fichier invalide s'ouvre aussi : ses erreurs sont listées pour être corrigées. Les éléments que l'éditeur ne sait pas reprendre (clé inconnue, valeur d'un type inattendu) sont signalés : ils ne seront pas réécrits.
- L'onglet **Configuration** présente toutes les sections du fichier (SPEC §8). Un champ vide prend la valeur par défaut, indiquée en grisé. Les champs sans objet dans le mode choisi (par exemple `destination` pour un client) sont masqués, sauf s'ils contiennent une valeur.
- Chaque saisie est validée par le chargeur du service lui-même : les erreurs affichées en bas de la fenêtre sont exactement celles que signalerait `tlsrelay check-config`. Le champ en erreur est encadré en rouge, avec le message en infobulle ; un double-clic sur une erreur place le curseur dans le champ.
- En mode serveur, l'onglet **Liste blanche** édite le fichier désigné par `whitelist.file` (un chemin relatif est résolu depuis le répertoire de la configuration) : un pair par ligne (nom, adresse IP ou plage, ports, sujet du certificat). Sans case de port cochée, le pair a les ports par défaut (plain et tls, plus mtls si un sujet est donné). Les cellules en erreur sont surlignées.

## 3. Enregistrement

**Fichier > Enregistrer** (Ctrl+S) :

1. l'enregistrement est refusé tant qu'il reste des erreurs ;
2. un aperçu montre les différences de chaque fichier (configuration et, en mode serveur, liste blanche) ;
3. après confirmation, chaque fichier modifié est d'abord copié en `<fichier>.bak`, puis remplacé d'un seul coup (renommage) : une instance qui surveille le fichier ne lit jamais un fichier à moitié écrit.

Les fichiers sont réécrits sous une forme normalisée : sections dans l'ordre de la SPEC, valeurs par défaut omises, en-tête « Écrit par tlsrelay-admin ». **Les commentaires du fichier d'origine ne sont pas conservés** (ils restent dans le `.bak`).

Une liste blanche enregistrée est prise en compte par l'instance en 2 secondes (surveillance) ou avec `tlsrelay reload`. Une configuration modifiée demande un redémarrage de l'instance, sauf pour les niveaux de journalisation.

## 4. Paquet de déploiement

**Fichier > Exporter le paquet de déploiement** (Ctrl+E) crée, dans le répertoire choisi, un sous-répertoire au nom de l'instance, à copier sur sa machine :

| Fichier | Contenu |
|---|---|
| `<instance>.yaml` | configuration |
| `whitelist.yaml` | liste blanche (serveur) |
| `kit\` | kit PKI produit par une signature (facultatif) |
| `crl.pem` | CRL publiées par l'AC (facultatif) |
| `install.sh` ou `install.ps1` | installation des fichiers, contrôle de la configuration, kit et CRL |
| `LISEZMOI.txt` | étapes restantes, dans l'ordre : demande de certificat, activation, droits des fichiers, service |

La configuration est installée à l'emplacement par défaut de l'instance (`/etc/tlsrelay/<instance>.yaml`, `C:\ProgramData\tlsrelay\<instance>.yaml`), celui qu'utilisent `--instance` et `service install`. Le dialogue signale les points d'attention, par exemple un chemin relatif (le service le résoudrait depuis son répertoire de travail) ou un `admin.endpoint` défini pour un service.

## 5. PKI (autorité de certification)

L'onglet **PKI** gère une mini-AC, la même que `tlsrelay ca` : le répertoire peut être utilisé indifféremment par l'éditeur et par la ligne de commande.

- **Ouvrir une AC** (créée par `tlsrelay ca init` ou par l'éditeur) ou **Créer une AC** (racine P-384 de 15 ans, AC Serveurs et AC Clients de 5 ans). Le résumé indique les certificats d'AC (sujet, échéance, empreinte SHA-256), l'inventaire et l'état des CRL : périmées ou à republier dans les 7 jours, elles sont signalées.
- **Inventaire** : série, rôle, état, fin de validité, sujet, révocation ; filtres (en service, révoqués, expirant dans 30 jours, remplacés ou expirés). Les certificats révoqués sont en rouge, ceux qui expirent dans les 30 jours sur fond orange.
- **Signer une demande** : la demande (`request.csr`, produite sur l'instance par `tlsrelay pki gen-csr`) est examinée dès qu'elle est choisie : sujet, extensions demandées (ignorées : l'AC impose les siennes), conformité (clé P-256, preuve de possession). Pour un serveur, au moins un nom (SAN) est obligatoire. Le kit produit (`cert.pem`, `chain.pem`, `trust-roots.pem`, `trust-issuer.pem`) est à installer sur l'instance : `tlsrelay pki install -c <conf> --from <kit>`, puis `pki activate`.
- **Renouveler** : assistant de renouvellement du certificat sélectionné. La nouvelle demande, avec une nouvelle clé, est produite sur l'instance avec le même sujet ; l'éditeur signale un sujet différent. L'ancien certificat est marqué « remplacé ».
- **Révoquer** : choisir le certificat et le motif ; les CRL sont aussitôt publiées (et copiées si un fichier est indiqué). La révocation prend effet sur chaque instance quand les CRL y sont installées : `tlsrelay pki crl -c <conf> crl.pem` (SPEC §7.7).
- **Publier les CRL** : à refaire avant leur échéance (30 jours par défaut), puis à redéployer.
- **Journal d'audit** : toutes les opérations de l'AC (création, signatures, révocations, CRL, changement de racine), avec l'opérateur ; la chaîne d'empreintes est contrôlée à chaque affichage et une altération est signalée en rouge.
- **Changement de racine** : l'assistant crée la nouvelle AC (ou en reprend une), puis prépare les fichiers de confiance des étapes 1 et 2 pour chaque rôle et un `LISEZMOI.txt` avec les commandes des trois étapes (SPEC §7.5). Même résultat que `tlsrelay ca root-change`.

La phrase de passe de l'AC est demandée à chaque opération qui utilise une clé d'AC ; elle n'est jamais enregistrée. Le répertoire de l'AC et sa phrase de passe restent sur le poste d'administration et sont sauvegardés hors ligne (EXPLOITATION §4).

## 6. Bonnes pratiques

- Garder les configurations sous gestion de versions ou au moins les `.bak` ; l'aperçu des différences sert de relecture avant chaque enregistrement.
- Utiliser des chemins absolus pour `whitelist.file`, `credentials.pki_root` et `logging.output`.
- Ne pas définir `admin.endpoint` pour une instance installée en service.
- Publier les CRL à date fixe (par exemple chaque mois) et les déployer sur toutes les instances qui vérifient leurs pairs.
