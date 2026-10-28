package com.fileencryption.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

import com.fileencryption.service.FileEncryptionException;
import com.fileencryption.service.FileEncryptionService;
import com.fileencryption.util.FileUtils;

/**
 * Handles POST /decrypt : receives an ".enc" file + password, returns the original file.
 *
 * IMPORTANT: GCM verifies its authentication tag only at the END of decryption.
 * So we decrypt into a temporary file first. The browser receives data only if the
 * tag was verified successfully. On failure the temp file is deleted and never sent.
 */

@WebServlet("/decrypt")
@MultipartConfig(
        fileSizeThreshold = FileUtils.UPLOAD_MEMORY_THRESHOLD,
        maxFileSize = FileUtils.MAX_ENCRYPTED_FILE_SIZE,
        maxRequestSize = FileUtils.MAX_ENCRYPTED_FILE_SIZE + FileUtils.MAX_REQUEST_OVERHEAD)
public class DecryptionServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendRedirect(request.getContextPath() + "/");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // The service holds no per-user data, so a new object per request is simple and thread-safe
        FileEncryptionService encryptionService = new FileEncryptionService();

        request.setCharacterEncoding("UTF-8");

        Part filePart = null;
        Path tempFile = null;
        try {
            // ---- 1. Validate the request ----
            String contentType = request.getContentType();
            if (contentType == null || !contentType.toLowerCase().startsWith("multipart/form-data")) {
                FileUtils.showError(request, response, HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid request. Please use the form on the home page.");
                return;
            }

            filePart = request.getPart("file");
            if (filePart == null || filePart.getSize() <= 0) {
                FileUtils.showError(request, response, HttpServletResponse.SC_BAD_REQUEST,
                        "Please choose an encrypted file. The file is missing or empty.");
                return;
            }
            if (filePart.getSize() > FileUtils.MAX_ENCRYPTED_FILE_SIZE) {
                FileUtils.showError(request, response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                        "The file is too large. The maximum size is 10 MB.");
                return;
            }

            String password = request.getParameter("password");
            if (password == null || password.isEmpty()) {
                FileUtils.showError(request, response, HttpServletResponse.SC_BAD_REQUEST,
                        "Please enter the password.");
                return;
            }

            String downloadName = FileUtils.buildDecryptedFileName(filePart.getSubmittedFileName());

            // ---- 2. Decrypt into a temporary file (NOT into the response) ----
            tempFile = Files.createTempFile("fenc-dec-", ".tmp");
            char[] passwordChars = password.toCharArray();
            try (InputStream in = filePart.getInputStream();
                 OutputStream out = Files.newOutputStream(tempFile)) {
                encryptionService.decrypt(in, out, passwordChars);
            } finally {
                java.util.Arrays.fill(passwordChars, '\0');
            }

            // ---- 3. Authentication succeeded: now (and only now) send the plaintext ----
            FileUtils.sendDownload(response, tempFile, downloadName);

        } catch (IllegalStateException e) {
            if (!response.isCommitted()) {
                FileUtils.showError(request, response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                        "The file is too large. The maximum size is 10 MB.");
            }
        } catch (FileEncryptionException e) {
            // Wrong password, modified file, or not one of our encrypted files.
            // The message is a fixed safe text; the temp file (with unverified data) is deleted below.
            if (!response.isCommitted()) {
                FileUtils.showError(request, response, HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
            }
        } catch (IOException | ServletException e) {
            log("Decryption request failed: " + e.getClass().getSimpleName());
            if (!response.isCommitted()) {
                FileUtils.showError(request, response, HttpServletResponse.SC_BAD_REQUEST,
                        "The upload could not be read. Please try again.");
            }
        } finally {
            FileUtils.deleteQuietly(tempFile); // success AND failure
            if (filePart != null) {
                try {
                    filePart.delete();
                } catch (IOException e) {
                    // ignore - Tomcat also removes upload files when the request ends
                }
            }
        }
    }
}
