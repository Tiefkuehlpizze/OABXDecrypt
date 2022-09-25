# OABX Decrypt (NeoBackup Decrypt)
Un outil pour déchiffrer les sauvegardes créées avec [OAndbackupX/Neo Backup](https://github.com/NeoApplications/Neo-Backup).

## Usage
Déchiffre les sauvegardes créées avec «OAndbackupX» 6 et «Neo Backup» 7-8, la différence entre eux étant que chaque sauvegarde a son propre vecteur d'initialisation stocké dans le fichier de propriétés (voir première ligne de la [version 7.0.0](https://github.com/NeoApplications/Neo-Backup/releases/tag/7.0.0))

Minimum requis JRE 8.
Télécharger la [dernière version](https://github.com/NeoApplications/Neo-Backup/releases/latest).
Exécuter comme ceci:
```shell
# Inscrivez votre mot de passe dans une variable (il ne sera pas retourné). Vous n'avez besoin de le faire qu'une fois par session.
read -s NB_PASSWORD && export NB_PASSWORD
# pour déchiffrer les sauvegardes OABX 6
java -jar OABXDecrypt-1.1.jar -file "path/to/encrypted/backup.tar.gz.enc"
# pour déchiffrer les sauvegardes NeoBackup 7-8
java -jar OABXDecrypt-1.1.jar -file "path/to/encrypted/backup.tar.gz.env" -propfile "path/to/propfile.properties"

# D'autres options pour fournir le mot de passe
# Lire le mot de passe depuis un fichier (n'est peut-être pas sûr)
java -jar OABXDecrypt-1.1.jar -passfile "path/to/passfile" -file "path/to/encrypted/backup.tar.gz.env" -propfile "path/to/propfile.properties"
# ou indiquez votre mot de passe comme argument (n'est certainement pas sûr)
java -jar OABXDecrypt-1.1.jar -password "YourSecretPassword" -file "path/to/encrypted/backup.tar.gz.env" -propfile "path/to/propfile.properties"
```

L'outil va déchiffrer le contenu et l'écrire vers le même chemin sans le suffixe «.enc» qui est utilisé pour indiquer les fichiers chiffrés. Vous devriez pouvoir ouvrir le fichier avec votre logiciel d'archivage favori. S'il est indiqué que le fichier est corrompu, le mot de passe était probablement incorrect.


Faites attention à l'historique du terminal ou d'autres utilisateurs pouvant voir les processus avec leurs paramètres. Pendant que le logiciel est en cours d'exécution, votre mot de passe est visible dans la commande d'exécution (par exemple `/proc/$pid/cmdline`). Assurez-vous que votre machine est sûre et que vous êtes seul.

Note: Sels personnalisées non pris en charge !

## OAndbackup/Neo Backup
Veuillez noter que OAndbackupX utilise un fichier de propriétés pour sauver la méthode de chiffrement. Si vous souhaitez déchiffrer vos sauvegardes, vous devez aussi modifier le fichier `.properties` correspondant.

## Pourquoi ?
Les utilisateurs du canal Telegram OandbackupX ont continuellement demandé comment déchiffrer leurs sauvegardes. Puisque j'ai implémenté les logiques de chiffrement d'OABX et que le code est réutilisable, j'ai créé cette enveloppe.
Cela a évolué depuis en un petit outil qui, généralement fait la même chose que [CryptoUtils.kt](https://github.com/NeoApplications/Neo-Backup/blob/main/app/src/main/java/com/machiav3lli/backup/utils/CryptoUtils.kt) de NeoBackup - et toujours écrit en Java.
Cela fonctionnera tant qu'OABX/NeoBackup ne change pas la logique ou l'algorithme de chiffrement, ou bien implémente quelque chose de correct comme pgp. 
Vos sauvegardes sont en sûreté. AES est fort et le point de faiblesse est votre mot de passe.

## Instructions de compilation
* Mettez à jour le projet
* Exécutez `mvn package assembly:single` pour recevoir les fichiers jar empaquetés avec leurs dépendances inclus dans le répertoire `target`

## Autres implémentations
Car quelqu'un a essayé d'implémenter le déchiffrement de NeoBackup via Python et [a demandé de l'aide](https://github.com/NeoApplications/Neo-Backup/issues/527), j'ai créé une [référence d'implémentation](misc/decrypt.py) sur le déchiffrement de sauvegardes avec Python et [PyCryptodome](https://www.pycryptodome.org).
C'est une bonne lecture sur le fonctionnement du chiffrement de Neo Backup. Bien que ce n'est que du AES en mode GCM avec une clef générée par PBKDF2 utilisant une empreinte sha256.
Si vous souhaitez implémenter cela vous-même pour vous amuser ou apprendre : la structure de fichier OABX 6 et Neo Backup 7-8 est simple :
```
[encrypted data(total_filesize - 16 bytes))]
[authentication_tag(16 bytes)]
```
Pas d'entête ou données supplémentaires, uniquement des données à plat et un libellé d'authentification. La sortie a la même taille, réduit de 16 octets.
Exemple:
```
data.tar.gz.enc 752 bytes
data.tar.gz     736 bytes
```

## Derniers mots
Vous connaissez le refrain : Je ne suis pas responsable de ce que vous faites ou exécutez sur votre ordinateur. Cet outil est très basique. Si vous rencontrez des problèmes et pensez que cela est lié à l'outil, veuillez ouvrir un ticket et décrire votre problème.
Je ne peux pas récupérer vos mots de passe. En cas d'oubli, vos données sont perdues. Pas de portes dérobées :)
