/*
 * OAndBackupX: open-source apps backup and restore app.
 * Copyright (C) 2020  Antonios Hazim
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package tkp;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.tinylog.Logger;

/**
 * Crypto. The class to handle encryption and decryption of streams.
 * Call `encryptStream` or `decryptStream` with a password and a salt or a better a secret key
 * (for performance reasons) and the class will wrap the given stream in return.
 * <p>
 * Android Keystore API is not used on purpose, because the key material needs to be portable for
 * uses cases when the device has been wiped or when backups are restored on another device.
 * <p>
 * The IV is static as it may be public.
 */
public final class Crypto {
    /**
     * Default salt, if no user specified salt is available to improve security.
     * Better a constant salt for the app that using no salt.
     */
    public static final byte[] FALLBACK_SALT = "oandbackupx".getBytes(StandardCharsets.UTF_8);
    /**
     * Taken from here. Chosen because of API Level 24+ compatibility. Newer algorithms are available
     * with API Level 26+.
     * <a href="https://developer.android.com/guide/topics/security/cryptography#SupportedSecretKeyFactory">https://developer.android.com/guide/topics/security/cryptography#SupportedSecretKeyFactory</a>
     * <p>
     * The actual choice was inspired by this blog post:
     * <a href="https://www.raywenderlich.com/778533-encryption-tutorial-for-android-getting-started">https://www.raywenderlich.com/778533-encryption-tutorial-for-android-getting-started</a>
     */
    private static final String DEFAULT_SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2withHmacSHA256";
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int DEFAULT_IV_BLOCK_SIZE = 32;  // 256 bit
    public static final byte[] DEFAULT_IV;
    private static final int ITERATION_COUNT = 2020;
    private static final int KEY_LENGTH = 256;

    static {
        try {
            DEFAULT_IV = new byte[Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM).getBlockSize()];
            Arrays.fill(DEFAULT_IV, (byte) 0);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey generateKeyFromPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Crypto.generateKeyFromPassword(password, salt, Crypto.DEFAULT_SECRET_KEY_FACTORY_ALGORITHM, Crypto.DEFAULT_CIPHER_ALGORITHM);
    }

    public static SecretKey generateKeyFromPassword(String password, byte[] salt, String keyFactoryAlgorithm, String cipherAlgorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(keyFactoryAlgorithm);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, Crypto.ITERATION_COUNT, Crypto.KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, cipherAlgorithm.split("/")[0]);
    }

    public static CipherOutputStream encryptStream(OutputStream os, String password, byte[] salt) throws CryptoSetupException {
        try {
            SecretKey secret = Crypto.generateKeyFromPassword(password, salt);
            return Crypto.encryptStream(os, secret);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Logger.info("Could not setup encryption: " + e.getMessage());
            throw new CryptoSetupException("Could not setup encryption", e);
        }
    }

    public static CipherOutputStream encryptStream(OutputStream os, SecretKey secret) throws CryptoSetupException {
        return Crypto.encryptStream(os, secret, Crypto.DEFAULT_CIPHER_ALGORITHM);
    }

    public static CipherOutputStream encryptStream(OutputStream os, SecretKey secret, String cipherAlgorithm) throws CryptoSetupException {
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            final IvParameterSpec iv = new IvParameterSpec(Crypto.initIv(cipherAlgorithm));
            cipher.init(Cipher.ENCRYPT_MODE, secret, iv);
            return new CipherOutputStream(os, cipher);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException |
                 NoSuchPaddingException e) {
            Logger.error("Could not setup encryption: " + e.getMessage());
            throw new CryptoSetupException("Could not setup encryption", e);
        }
    }

    public static CipherInputStream decryptStream(InputStream in, String password, byte[] salt, byte[] iv) throws CryptoSetupException {
        try {
            SecretKey secret = Crypto.generateKeyFromPassword(password, salt);
            return Crypto.decryptStream(in, secret, iv, Crypto.DEFAULT_CIPHER_ALGORITHM);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Logger.error("Could not setup encryption: " + e.getMessage());
            throw new CryptoSetupException("Could not setup encryption", e);
        }
    }

    public static CipherInputStream decryptStream(InputStream in, SecretKey secret) throws CryptoSetupException {
        return Crypto.decryptStream(in, secret, Crypto.DEFAULT_IV, Crypto.DEFAULT_CIPHER_ALGORITHM);
    }

    public static CipherInputStream decryptStream(InputStream in, SecretKey secret, byte[] iv, String cipherAlgorithm) throws CryptoSetupException {
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            // I don't know, why NeoBackup can use IvParameterSpec here. It's not accepted in JDK 8 and 11 and causes
            // java.security.InvalidAlgorithmParameterException: Unsupported parameter: javax.crypto.spec.IvParameterSpec@108c4c35
            final GCMParameterSpec ivParams = new GCMParameterSpec(128, iv);
            //IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secret, ivParams);
            return new CipherInputStream(in, cipher);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                 InvalidKeyException e) {
            Logger.error("Could not setup encryption: " + e.getMessage());
            throw new CryptoSetupException("Could not setup encryption", e);
        }
    }

    public static int getCipherBlockSize(){
        try {
            return Cipher.getInstance(Crypto.DEFAULT_CIPHER_ALGORITHM).getBlockSize();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return Crypto.DEFAULT_IV_BLOCK_SIZE;
        }
    }

    private static byte[] initIv(String cipherAlgorithm) {
        int blockSize;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            blockSize = cipher.getBlockSize();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Fallback if the cipher has issues. Might lead to another exception later, but saves
            // the situation here. The use cipher might not match or will cause other exceptions
            // when used like this.
            blockSize = Crypto.DEFAULT_IV_BLOCK_SIZE;
        }
        // IV is nothing secret. Could also be constant, but why not spend a few cpu cycles to have
        // it dynamic, if the algorithm changes?
        byte[] iv = new byte[blockSize];
        for (int i = 0; i < blockSize; ++i) {
            iv[i] = 0;
        }
        return iv;
    }

    public static String getCipherAlgorithm() {
        return Crypto.DEFAULT_CIPHER_ALGORITHM;
    }

    public static class CryptoSetupException extends Exception {
        public CryptoSetupException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
