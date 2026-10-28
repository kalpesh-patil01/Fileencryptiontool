package com.fileencryption.service;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Password-based file encryption / decryption using AES-256-GCM.
 *
 * ENCRYPTED FILE FORMAT (version 1) - all numbers are big-endian:
 *
 *   offset  size  field
 *   ------  ----  --------------------------------------------------
 *   0       4     magic bytes "FENC" (identifies our file type)
 *   4       1     format version (currently 1)
 *   5       4     PBKDF2 iteration count used for this file
 *   9       16    random salt (for PBKDF2)
 *   25      12    random nonce / IV (for AES-GCM)
 *   37      ...   ciphertext followed by the 16-byte GCM authentication tag
 *
 * The 37-byte header is also given to GCM as "associated data" (AAD).
 * It is not secret, but if anybody edits it, authentication fails.
 */
public class FileEncryptionService {

    // ---- format constants ----
    private static final byte[] MAGIC = "FENC".getBytes(StandardCharsets.US_ASCII);
    private static final byte VERSION = 1;
    private static final int SALT_LENGTH = 16;       // 128-bit salt
    private static final int NONCE_LENGTH = 12;      // 96-bit nonce (the recommended size for GCM)
    private static final int TAG_LENGTH_BITS = 128;  // 128-bit authentication tag
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;
    private static final int KEY_LENGTH_BITS = 256;  // AES-256
    private static final int HEADER_LENGTH = MAGIC.length + 1 + 4 + SALT_LENGTH + NONCE_LENGTH; // 37

    /** PBKDF2 iterations used when encrypting (OWASP recommends 600,000 for PBKDF2-HMAC-SHA256). */
    public static final int PBKDF2_ITERATIONS = 600_000;

    // The iteration count is read from an uploaded file, so we limit it to a sane range.
    // Otherwise an attacker could upload a file claiming 2 billion iterations to freeze the server.
    private static final int MIN_ACCEPTED_ITERATIONS = 100_000;
    private static final int MAX_ACCEPTED_ITERATIONS = 2_000_000;

    private static final int BUFFER_SIZE = 8192;

    // SecureRandom = cryptographically secure random numbers (never use java.util.Random here)
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Reads plain data from "in", writes the encrypted file (header + ciphertext + tag) to "out".
     * The caller owns both streams and must close them.
     */
    public void encrypt(InputStream in, OutputStream out, char[] password)
            throws FileEncryptionException, IOException {

        // A NEW random salt and nonce for EVERY encryption.
        // Re-using a nonce with the same key would completely break GCM security.
        byte[] salt = new byte[SALT_LENGTH];
        byte[] nonce = new byte[NONCE_LENGTH];
        secureRandom.nextBytes(salt);
        secureRandom.nextBytes(nonce);

        byte[] header = buildHeader(PBKDF2_ITERATIONS, salt, nonce);
        SecretKey key = deriveKey(password, salt, PBKDF2_ITERATIONS);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(header); // the header is authenticated (tamper-proof) but not encrypted

            out.write(header);

            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] encryptedPart = cipher.update(buffer, 0, bytesRead);
                if (encryptedPart != null) {
                    out.write(encryptedPart);
                }
            }
            // doFinal() returns the last block and appends the 16-byte authentication tag
            out.write(cipher.doFinal());
        } catch (GeneralSecurityException e) {
            throw new FileEncryptionException("Encryption failed. Please try again.", e);
        }
    }

    /**
     * Reads an encrypted file from "in" and writes the original data to "out".
     *
     * SECURITY NOTE: with GCM the authentication tag is checked only at the very end.
     * Therefore the caller must NOT send "out" to the user until this method returns
     * normally. (DecryptionServlet writes to a temporary file first.)
     * If this method throws, whatever was already written to "out" must be discarded.
     */
    public void decrypt(InputStream in, OutputStream out, char[] password)
            throws FileEncryptionException, IOException {

        // 1) Read and validate the header BEFORE doing any expensive work
        byte[] header = new byte[HEADER_LENGTH];
        try {
            new DataInputStream(in).readFully(header);
        } catch (EOFException e) {
            throw new FileEncryptionException("This is not a valid encrypted file (file is too short).");
        }

        ByteBuffer buffer = ByteBuffer.wrap(header); // ByteBuffer is big-endian by default
        byte[] magic = new byte[MAGIC.length];
        buffer.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new FileEncryptionException(
                    "This file was not encrypted by this tool (unknown file format).");
        }
        byte version = buffer.get();
        if (version != VERSION) {
            throw new FileEncryptionException("Unsupported encrypted file version: " + (version & 0xFF) + ".");
        }
        int iterations = buffer.getInt();
        if (iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) {
            throw new FileEncryptionException("The encrypted file header is invalid or corrupted.");
        }
        byte[] salt = new byte[SALT_LENGTH];
        byte[] nonce = new byte[NONCE_LENGTH];
        buffer.get(salt);
        buffer.get(nonce);

        // 2) Derive the same key from the password + stored salt
        SecretKey key = deriveKey(password, salt, iterations);

        // 3) Decrypt
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(header);

            byte[] readBuffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = in.read(readBuffer)) != -1) {
                byte[] decryptedPart = cipher.update(readBuffer, 0, bytesRead);
                if (decryptedPart != null) {
                    out.write(decryptedPart);
                }
            }
            // doFinal() verifies the authentication tag.
            // If the password is wrong OR any byte was modified, it throws AEADBadTagException.
            out.write(cipher.doFinal());
        } catch (AEADBadTagException e) {
            throw new FileEncryptionException(
                    "Decryption failed: the password is wrong, or the file has been modified or corrupted.", e);
        } catch (GeneralSecurityException e) {
            throw new FileEncryptionException(
                    "Decryption failed: the password is wrong, or the file has been modified or corrupted.", e);
        }
    }

    /** Returns the size in bytes of the extra data added by encryption (header + tag). */
    public static int getOverheadBytes() {
        return HEADER_LENGTH + TAG_LENGTH_BYTES;
    }

    // ------------------------------------------------------------------ helpers

    /** Builds the 37-byte header described at the top of this class. */
    private byte[] buildHeader(int iterations, byte[] salt, byte[] nonce) {
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_LENGTH);
        buffer.put(MAGIC);
        buffer.put(VERSION);
        buffer.putInt(iterations);
        buffer.put(salt);
        buffer.put(nonce);
        return buffer.array();
    }

    /**
     * Turns a password into a 256-bit AES key using PBKDF2 with HMAC-SHA-256.
     * PBKDF2 repeats the hash many times (iterations) so guessing passwords is slow.
     * The password is NEVER used directly as the key.
     */
    private SecretKey deriveKey(char[] password, byte[] salt, int iterations)
            throws FileEncryptionException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            Arrays.fill(keyBytes, (byte) 0); // SecretKeySpec keeps its own copy
            return key;
        } catch (GeneralSecurityException e) {
            throw new FileEncryptionException("Could not derive the encryption key.", e);
        } finally {
            spec.clearPassword(); // wipe the password copy held by the spec
        }
    }
}
