package com.fileencryption.service;

/**
 * A checked exception whose message is SAFE to show to the user
 * (it never contains passwords, file paths or stack traces).
 */
public class FileEncryptionException extends Exception {

    private static final long serialVersionUID = 1L;

    public FileEncryptionException(String safeMessage) {
        super(safeMessage);
    }

    public FileEncryptionException(String safeMessage, Throwable cause) {
        super(safeMessage, cause);
    }
}
