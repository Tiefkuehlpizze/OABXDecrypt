package tkp;

import org.apache.commons.cli.*;
import org.tinylog.Logger;

import javax.crypto.AEADBadTagException;
import javax.crypto.CipherInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class App {
    public static final String ARG_NAME_INPUT_FILE = "file";
    public static final String ARG_NAME_PASSWORD = "password";
    public static final String ARG_NAME_PASSWORD_FILE = "passfile";
    public static final String ENV_VAR_NAME_PASSWORD = "NB_PASSWORD";
    public static final String ARG_NAME_PROPERTIES = "propfile";

    /**
     * Parses the command line arguments and handles the "help" command.
     *
     * @param args program arguments
     * @return parsed arguments
     * @throws ParseException on any issue occurring while parsing arguments
     */
    private static CommandLine parseArguments(String[] args) throws ParseException {
        Options options = new Options();
        options.addOption(
                Option.builder(App.ARG_NAME_INPUT_FILE)
                        .required()
                        .desc("[6/7] Encrypted input file to decrypt")
                        .hasArg()
                        .numberOfArgs(1)
                        .build()
        ).addOption(
                Option.builder(ARG_NAME_PROPERTIES)
                        .desc("[7] Properties file created by OAndBackupX 7 or NeoBackup 7 to retrieve the IV")
                        .hasArg()
                        .numberOfArgs(1)
                        .build()
        );
        OptionGroup decryptOgroup = new OptionGroup()
                .addOption(Option.builder(ARG_NAME_PASSWORD)
                        .desc("Password used to decrypt the file (use -help password for safer alternatives)")
                        .hasArg()
                        .numberOfArgs(1)
                        .build())
                .addOption(Option.builder(ARG_NAME_PASSWORD_FILE)
                        .desc("File containing the password used to decrypt the file (use -help password for safer alternatives)")
                        .hasArg()
                        .numberOfArgs(1)
                        .build()
                );
        options.addOptionGroup(decryptOgroup);
        options.addOption(Option.builder("help")
                .desc("Shows help for the application")
                .numberOfArgs(1)
                .optionalArg(true)
                .build());

        CommandLineParser parser = new DefaultParser();
        CommandLine arguments = parser.parse(options, args);
        if (arguments.hasOption("help")) {
            if ("password".equalsIgnoreCase(arguments.getOptionValue("help"))) {
                System.err.println("Passing the password as argument is insecure and can be seen in the process list and it could be stored in the shell's history");
                System.err.printf("You can use the following options:\n"
                                + "- Please use `read -s %s` to read your password into an environment variable and run this program. Be sure to end your shell session afterwards.\n"
                                + "- Create a file just containing your password with your favorite text editor and secure it with `chmod 600 your_file` "
                                + "and pass it to the application by using -%s parameter\n"
                                + "\tNote: The password is still readable by anyone who has direct access to the underlying storage system (such as root) "
                                + "Never decrypt your sensible data/backups on untrusted systems!\n"
                        , App.ENV_VAR_NAME_PASSWORD, App.ARG_NAME_PASSWORD_FILE);
            }
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("java -jar oabxdecrypt.jar", options);
            System.exit(1);
        }
        return arguments;
    }


    /**
     * Decrypts a backup file using OABX 6's default IV
     *
     * @param inputFilename path to the file to decrypt
     * @param password      password to use for decryption
     * @throws IOException                 on filesystem or read/write related issues
     * @throws Crypto.CryptoSetupException on issues initializing the wanted cipher suite
     */
    public static void decryptFile(final String inputFilename, final String password)
            throws IOException, Crypto.CryptoSetupException {
        App.decryptFile(inputFilename, password, Crypto.DEFAULT_IV);
    }

    /**
     * Decrypts a backup file using OABX/NeoBackup 7 strategy with per backup IVs.
     *
     * @param inputFilename      path to the file to decrypt
     * @param password           password to use for decryption
     * @param propertiesFilename path to the properties file for the backup
     * @throws IOException                 on filesystem or read/write related issues
     * @throws Crypto.CryptoSetupException on issues initializing the wanted cipher suite
     */
    public static void decryptFile(final String inputFilename, final String password, final String propertiesFilename)
            throws IOException, Crypto.CryptoSetupException {
        byte[] iv = new NeoBackupProperties(propertiesFilename).getIV();
        App.decryptFile(inputFilename, password, iv);
    }

    /**
     * Decrypts a backup file using the given IV
     *
     * @param inputFilename path to the file to decrypt
     * @param password      password to use for decryption
     * @param iv            initialization vector for the cipher suite
     * @throws IOException                 on filesystem or read/write related issues
     * @throws Crypto.CryptoSetupException on issues initializing the wanted cipher suite
     */
    public static void decryptFile(final String inputFilename, final String password, final byte[] iv)
            throws IOException, Crypto.CryptoSetupException {
        final String outputFilename = inputFilename.substring(0, inputFilename.lastIndexOf('.'));

        File inputFile = new File(inputFilename);
        FileOutputStream out = new FileOutputStream(outputFilename);
        FileInputStream inputStream = new FileInputStream(inputFile);

        CipherInputStream cipherInputStream = Crypto.decryptStream(inputStream, password, Crypto.FALLBACK_SALT, iv);

        final byte[] buffer = new byte[1 << 24];
        long writtenBytes = 0;
        int length;
        while ((length = cipherInputStream.read(buffer)) > 0) {
            out.write(buffer, 0, length);
            writtenBytes += length;
        }
        cipherInputStream.close();
        out.close();
        Logger.info("Done. Decrypted {} bytes.", writtenBytes);
    }

    /**
     * Tries to retrieve the password using the following sources (top first):
     * * CLI Argument "password" (highest priority)
     * * CLI Argument "passfile"
     * * Environment variable "NB_PASSWORD"
     *
     * @param args parsed command line arguments
     * @return the found password
     * @throws IOException on issues reading the password file
     */
    public static String retrievePassword(CommandLine args) throws IOException {
        if (args.hasOption(ARG_NAME_PASSWORD)) {
            Logger.debug("Password is set via command line arguments. Using it.");
            Logger.info("Passing the password as argument is insecure and can be seen in the process list and it could be stored in the shell's history");
            return args.getOptionValue(ARG_NAME_PASSWORD);
        }
        if (args.hasOption(App.ARG_NAME_PASSWORD_FILE)) {
            String passwordFilepath = args.getOptionValue(App.ARG_NAME_PASSWORD_FILE);
            Logger.debug("Reading file from password file: {}", passwordFilepath);
            final String fileContents = new String(Files.readAllBytes(Paths.get(passwordFilepath)), StandardCharsets.UTF_8);
            return fileContents.substring(0, fileContents.length() - 1);
        }
        Logger.debug("Trying to retrieve password from environment variable {}", App.ENV_VAR_NAME_PASSWORD);
        if (System.getenv().containsKey(App.ENV_VAR_NAME_PASSWORD)) {
            return System.getenv(App.ENV_VAR_NAME_PASSWORD);
        }
        throw new IllegalArgumentException("No password option set");
    }

    public static void main(String[] args) throws IOException, Crypto.CryptoSetupException {
        System.err.println("Crappy OABX/NeoBackup Decrypting Tool 2.0\n"
                + "This just decrypts your file with the given key. It does not verify, if anything is correct.\n"
                + "The file cannot be opened if the password was wrong or the encryption algorithm has changed.\n"
                + "This tool works with OABX 6-7 and NeoBackup 7\n"
                + "--------------------------");
        try {
            // Parsing and checking arguments
            CommandLine parsedArgs = App.parseArguments(args);
            final String password = App.retrievePassword(parsedArgs);
            if (password.isEmpty()) {
                throw new IllegalArgumentException("The password may not be empty.");
            }
            final String inputFilename = parsedArgs.getOptionValue(App.ARG_NAME_INPUT_FILE);
            if (inputFilename.isEmpty()) {
                throw new IllegalArgumentException("The input filename may not be empty.");
            }
            if (!inputFilename.endsWith(".enc")) {
                Logger.error("Input file \"{}\"does not end with .enc which is used by OABX to tag encrypted files. Wont' proceed.", inputFilename);
            }

            if (parsedArgs.hasOption(App.ARG_NAME_PROPERTIES)) {
                Logger.info("Assuming OABX/Neobackup 7 backup");
                App.decryptFile(inputFilename, password, parsedArgs.getOptionValue(App.ARG_NAME_PROPERTIES));
            } else {
                Logger.info("Assuming OABX 6 backup");
                App.decryptFile(inputFilename, password);
            }
        } catch (ParseException e) {
            Logger.error(e);
        } catch(IOException e){
            if(e.getCause() instanceof AEADBadTagException){
                Logger.error("{} Your password is probably wrong!", e.getCause());
            }else{
                throw e;
            }
        }
    }
}
