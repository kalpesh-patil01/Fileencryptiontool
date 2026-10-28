package com.fileencryption.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Small helper methods shared by both servlets:
 * safe file names, sending a download, and showing an error page.
 */

public final class FileUtils {

    /** Largest ORIGINAL file the user may encrypt: 10 MB. */
    public static final long MAX_FILE_SIZE = 10L * 1024 * 1024;

    // Encryption adds 53 bytes (37 header + 16 tag). We allow 1 KB extra when uploading an
    // ".enc" file, so a file that was exactly 10 MB before encryption can still be decrypted.
    public static final long MAX_ENCRYPTED_FILE_SIZE = MAX_FILE_SIZE + 1024;

    // Extra room in the whole multipart request for the password fields and form boundaries.
    public static final long MAX_REQUEST_OVERHEAD = 64L * 1024;

    /** Files bigger than this are kept on disk by Tomcat while uploading, smaller ones in memory. */
    public static final int UPLOAD_MEMORY_THRESHOLD = 1024 * 1024;

    public static final String ENCRYPTED_EXTENSION = ".enc";

    private static final int MAX_NAME_LENGTH = 100;

    private FileUtils() {
        // utility class - no objects needed
    }

    /**
     * Makes a file name safe to use in a download header.
     * 1) The browser may send a full path such as "C:\Users\me\a.txt": keep only the last part.
     * 2) Keep only letters, digits, dot, dash and underscore. Everything else becomes "_".
     * 3) Remove leading dots (no hidden files, no "..") and limit the length.
     * We NEVER use this name to create a file on the server. It is only used for the download.
     */
    public static String sanitizeFileName(String submittedName) {
        if (submittedName == null) {
            return "file";
        }
        String name = submittedName;
        int lastSlash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        if (lastSlash >= 0) {
            name = name.substring(lastSlash + 1);
        }
        name = name.replaceAll("[^A-Za-z0-9._-]", "_");
        name = name.replaceAll("^\\.+", "");
        if (name.length() > MAX_NAME_LENGTH) {
            name = name.substring(0, MAX_NAME_LENGTH);
        }
        if (name.isEmpty() || name.replace("_", "").isEmpty()) {
            return "file";
        }
        return name;
    }

    /** "report.pdf" becomes "report.pdf.enc". */
    public static String buildEncryptedFileName(String submittedName) {
        return sanitizeFileName(submittedName) + ENCRYPTED_EXTENSION;
    }

    /** "report.pdf.enc" becomes "report.pdf". Other names get the prefix "decrypted_". */
    public static String buildDecryptedFileName(String submittedName) {
        String name = sanitizeFileName(submittedName);
        if (name.toLowerCase(Locale.ROOT).endsWith(ENCRYPTED_EXTENSION)
                && name.length() > ENCRYPTED_EXTENSION.length()) {
            return name.substring(0, name.length() - ENCRYPTED_EXTENSION.length());
        }
        return "decrypted_" + name;
    }

    /** Copies everything from "in" to "out" (simple loop, no memory problems for big files). */
    public static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            out.write(buffer, 0, bytesRead);
        }
    }

    /**
     * Sends a file on disk to the browser as a download.
     * "Content-Disposition: attachment" makes the browser save the file instead of opening it.
     * The file name was already sanitized, so it contains only safe ASCII characters.
     */
    public static void sendDownload(HttpServletResponse response, Path file, String downloadName)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/octet-stream");
        response.setContentLengthLong(Files.size(file));
        response.setHeader("Content-Disposition", "attachment; filename=\"" + downloadName + "\"");
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("X-Content-Type-Options", "nosniff");
        try (InputStream in = Files.newInputStream(file);
             OutputStream out = response.getOutputStream()) {
            copy(in, out);
        }
    }

    /**
     * Shows result.jsp with an error message. The message must be a fixed text written by us
     * (never user input), because result.jsp prints it as it is.
     */
    public static void showError(HttpServletRequest request, HttpServletResponse response,
                                 int httpStatus, String message) throws ServletException, IOException {
        response.setStatus(httpStatus);
        response.setHeader("Cache-Control", "no-store");
        request.setAttribute("success", Boolean.FALSE);
        request.setAttribute("title", "Something went wrong");
        request.setAttribute("message", message);
        request.getRequestDispatcher("/result.jsp").forward(request, response);
    }

    /** Deletes a temporary file and ignores the error if it is already gone. */
    public static void deleteQuietly(Path file) {
        if (file == null) {
            return;
        }
        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            // Nothing more we can do; the OS temp folder will be cleaned eventually.
        }
    }
}
