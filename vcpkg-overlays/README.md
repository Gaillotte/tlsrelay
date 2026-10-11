# Ports vcpkg de surcharge

## openssl (3.5.x, branche à support long)

tlsrelay livre sous Windows la branche **OpenSSL 3.5 LTS** (support jusqu'en
avril 2030). Le catalogue vcpkg est passé à la branche 3.6 après la 3.5.4 ;
ce port reprend la recette officielle de vcpkg (`ports/openssl`, avec ses
correctifs inchangés) en la fixant sur la dernière version 3.5.

Différence avec la recette vcpkg : les sources viennent de l'**archive
officielle de la version** publiée par le projet OpenSSL
(`releases/download/openssl-X.Y.Z/openssl-X.Y.Z.tar.gz`), vérifiée par son
empreinte SHA-512, au lieu de l'archive générée par GitHub.

### Passer à une nouvelle version 3.5.x

1. Mettre à jour `version` dans `openssl/vcpkg.json`.
2. Télécharger `openssl-X.Y.Z.tar.gz` et `openssl-X.Y.Z.tar.gz.sha256` depuis
   la page de la version ; vérifier l'empreinte SHA-256 publiée.
3. Reporter la nouvelle empreinte SHA-512 (`sha512sum`) dans
   `openssl/portfile.cmake`.
4. Vérifier que les correctifs s'appliquent toujours (`git apply --check`).

La CI Windows échoue si la version embarquée n'est pas une 3.5.x.
