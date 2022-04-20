# OABX Decrypt (NeoBackup Decrypt)
Your crappy tool to decrypt backups created [OandbackupX](https://github.com/machiav3lli/oandbackupx).

## Usage
Decrypts backups created with OAndbackupX 6.0 and OAndBackupX/Neo Backup 7.0. The difference between them is, that every backup has its own IV (initialization vector) stored in the properties file (see first line of [release 7.0.0](https://github.com/NeoApplications/Neo-Backup/releases/tag/7.0.0))

Minimum Requirement is JRE 8.
Download the [latest release](https://github.com/NeoApplications/Neo-Backup/releases/latest).
Run it like this:
```shell
# type your password into a variable (it won't be echoed) and you only have to do it once per shell session
read -s NB_PASSWORD
# to decrypt OABX 6 backups
java -jar OABXDecrypt-1.0.jar -file "path/to/encrypted/backup.tar.gz.enc"
# to decrypt NeoBackup 7 backups
java -jar OABXDecrypt-1.0.jar -file "path/to/encrypted/backup.tar.gz.env" -propfile "path/to/propfile.properties"

# Other options to provide the password
# Read the password from a file (maybe unsecure)
java -jar OABXDecrypt-1.0.jar -passfile "path/to/passfile" -file "path/to/encrypted/backup.tar.gz.env" -propfile "path/to/propfile.properties"
# or use your password as argument (unsecure)
java -jar OABXDecrypt-1.0.jar -password "YourSecretPassword" -file "path/to/encrypted/backup.tar.gz.env" -propfile "path/to/propfile.properties"
```

The tool will decrypt the contents and write them into the same path but without the `.enc` suffix which is used by OAndbackupX/Neo Backup to mark a file as encrypted.
You should be able to open the file with your favourite file archiver. If it says, the file is corrupted, the password might have been wrong.

Beware of the shell's history or other users who could see the process with its parameter. While the application is running, your password is visible in your command's cmdline (e.g. `/proc/$pid/cmdline`). So make sure, your computer is safe and you're alone. 

## OAndbackup/Neo Backup
Please note, that OAndbackupX uses a property file to save how the file has been encrypted. If you want to decrypt your backups, you also need to modify the corresponding `.properties` file.

## Why?
People in the OandbackupX Telegram channel kept asking, how to decrypt their backups. Since I implemented OABX's encryption and the logic is still the same and the code is completely reusable on a computer, I just created this wrapper.
It evolved a bit since it's a small tool, but generally does the same as the NeoBackup's [CryptoUtils.kt](https://github.com/NeoApplications/Neo-Backup/blob/main/app/src/main/java/com/machiav3lli/backup/utils/CryptoUtils.kt) - and it's still written in Java. 
It'll work as long as OBAX/Neo Backup does not change the encryption logic or algorithm or implements something proper like pgp.
Your backups are secure. AES is strong and the weakpoint is your password.

## Build Instructions
* Checkout the project
* run `mvn package assembly:single` to get the packaged jar with its dependencies included in `target` directory

## Last words
You know the drill: I'm not responsible for what you do and run on your computer. The tool is very basic. If you encounter some issue and you think it's related to my tool, please open an issue and describe your problem.
I'm not able to recover your password. If you forgot it, your data is lost. No backdoors :)
