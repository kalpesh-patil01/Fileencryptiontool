<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>File Encryption &amp; Decryption Tool</title>
    <link rel="stylesheet" href="${pageContext.request.contextPath}/css/style.css">
</head>
<body>
    <header class="site-header">
        <h1>File Encryption &amp; Decryption Tool</h1>
        <p>Protect a file with a password using AES-256-GCM. Encrypt a file, download it, and
           decrypt it later with the same password. Files up to 10&nbsp;MB are supported.</p>
    </header>

    <main class="container">

        <!-- ================= ENCRYPTION ================= -->
        <section class="card">
            <h2>1. Encrypt a file</h2>
            <!-- action must match @WebServlet("/encrypt"); enctype is required for file uploads -->
            <form id="encryptForm" action="${pageContext.request.contextPath}/encrypt"
                  method="post" enctype="multipart/form-data" accept-charset="UTF-8">

                <label for="encFile">Choose a file</label>
                <input type="file" id="encFile" name="file" required>

                <label for="encPassword">Password (at least 8 characters)</label>
                <input type="password" id="encPassword" name="password" minlength="8"
                       autocomplete="new-password" required>

                <label for="encConfirm">Confirm password</label>
                <input type="password" id="encConfirm" name="confirmPassword" minlength="8"
                       autocomplete="new-password" required>

                <p class="warning">If you lose the password, the file <strong>cannot be recovered</strong>.</p>

                <div class="buttons">
                    <button type="submit" class="btn btn-primary">Encrypt</button>
                    <button type="reset" class="btn btn-secondary">Clear</button>
                </div>
            </form>
        </section>

        <!-- ================= DECRYPTION ================= -->
        <section class="card">
            <h2>2. Decrypt a file</h2>
            <!-- action must match @WebServlet("/decrypt") -->
            <form id="decryptForm" action="${pageContext.request.contextPath}/decrypt"
                  method="post" enctype="multipart/form-data" accept-charset="UTF-8">

                <label for="decFile">Choose an encrypted file (.enc)</label>
                <input type="file" id="decFile" name="file" accept=".enc" required>

                <label for="decPassword">Password</label>
                <input type="password" id="decPassword" name="password"
                       autocomplete="current-password" required>

                <div class="buttons">
                    <button type="submit" class="btn btn-primary">Decrypt</button>
                    <button type="reset" class="btn btn-secondary">Clear</button>
                </div>
            </form>
        </section>
    </main>

    <footer class="site-footer">
        <p>Your files are processed in memory and in temporary files that are deleted right away.
           Nothing is stored on the server.</p>
    </footer>

    <!-- Small convenience checks only. The server repeats every check. -->
    <script>
        var MAX_BYTES = 10 * 1024 * 1024;

        document.getElementById('encryptForm').addEventListener('submit', function (event) {
            var file = document.getElementById('encFile').files[0];
            if (file && file.size > MAX_BYTES) {
                alert('The file is larger than 10 MB.');
                event.preventDefault();
                return;
            }
            if (document.getElementById('encPassword').value !== document.getElementById('encConfirm').value) {
                alert('The password and the confirmation do not match.');
                event.preventDefault();
            }
        });

        document.getElementById('decryptForm').addEventListener('submit', function (event) {
            var file = document.getElementById('decFile').files[0];
            if (file && file.size > MAX_BYTES + 1024) {
                alert('The file is larger than 10 MB.');
                event.preventDefault();
            }
        });
    </script>
</body>
</html>
