# OABX Decrypt (NeoBackup Decrypt)
Your crappy tool to decrypt backups created [OandbackupX](https://github.com/machiav3lli/oandbackupx).

## Usage
Decrypts backups created with OAndbackupX 6.0. OAndBackupX/NeoBackup 7.0+ is not supported because every backup has its own IV (initialization vector) stored in the properties file (see first line of [release 7.0.0](https://github.com/NeoApplications/Neo-Backup/releases/tag/7.0.0)).

Minimum Requirement is JRE 8.
Download the [latest release](https://github.com/machiav3lli/oandbackupx/releases/latest).
Run it like this:
```shell
java -jar OABXDecrypt-1.0.jar "YourSecretPassword" "path/to/encrypted/backup.tar.gz.enc"
```

The tool will decrypt the contents and write them into the same path but without the `.enc` suffix which is used by OandbackupX to mark a file as encrypted.
You should be able to open the file with your favourite file archiver. If it says, the file is corrupted, the password might have been wrong.

Beware of the shell's history or other users who could see the process with it's parameter. While the application is running, your password is visible in your command's cmdline (e.g. `/proc/$pid/cmdline`). So make sure, your computer is safe and you're alone. 

## Oandbackup/NeoBackup
Please note, that OandbackupX uses a property file to save how the file has been encrypted. If you want to decrypt your backups, you also need to modify the corresponding `.properties` file.

## Why?
People in the OandbackupX Telegram channel kept asking, how to decrypt their backups. Since I implemented OABX's encryption and the logic is still the same and the code is completely reusable on a computer, I just created this wrapper.
It'll work as long as OBAX doesn't changes the encryption logic or algorithm or implements something proper like pgp.
Your backups are secure. AES is strong and the weakpoint is your password.

## Build Instructions
* Checkout the project
* run `mvn package assembly:single` to get the packaged jar with its dependencies included in `target` directory

## Last words
You know the drill: I'm not responsible for what you do and run on your computer. The tool is very basic. If you encounter some issue and you think it's related to my tool, please open an issue and describe your problem.
I'm not able to recover your password. If you forgot it, your data is lost. No backdoors :)
