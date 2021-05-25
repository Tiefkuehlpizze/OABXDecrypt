package tkp;

import org.tinylog.Logger;

import javax.crypto.CipherInputStream;
import java.io.*;

public class App {
    public static void main(String[] args) throws IOException, Crypto.CryptoSetupException {
        Logger.info("Crappy OABX Decrypting Tool 1.0");
        Logger.info("This just decrypts your file with the given key. It does not verify, if anything is correct.");
        Logger.info("The file cannot be opened if the password was wrong or the encryption algorithm has changed.");
        Logger.info("This tool works wit OABX 6.0.0");

        if (args.length != 2) {
            Logger.error("Not enough arguments");
            Logger.info("Usage: java -jar OABXDecrypt.jar password filepath");
            System.exit(1);
        }
        final String password = args[0];
        final String inputFilename = args[1];
        final String outputFilename = inputFilename.substring(0, inputFilename.lastIndexOf('.'));
        final byte[] buffer = new byte[1 << 24];

        if (!inputFilename.endsWith(".enc")) {
            Logger.error("Input file \"{}\"does not end with .enc which is used by OABX to tag encrypted files. Wont' proceed.", inputFilename);
            System.exit(1);
        }

        File inputFile = new File(inputFilename);
        File outputFile = new File(outputFilename);

        if (outputFile.exists()) {
            Logger.warn("Output file {} already exists. Please confirm with return or abort with Ctrl+C", outputFilename);
            try {
                System.console().readLine();
            } catch (NullPointerException ex) {
                Logger.warn("No console detected. Please delete \"{}\" manually to continue", outputFilename);
                System.exit(1);
            }
        }

        FileOutputStream out = new FileOutputStream(outputFile);
        CipherInputStream cipherInputStream = Crypto.decryptStream(new FileInputStream(inputFile), password, Crypto.FALLBACK_SALT);
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
}
