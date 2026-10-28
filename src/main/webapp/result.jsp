<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Result - File Encryption &amp; Decryption Tool</title>
    <link rel="stylesheet" href="${pageContext.request.contextPath}/css/style.css">
</head>
<body>
    <header class="site-header">
        <h1>File Encryption &amp; Decryption Tool</h1>
    </header>

    <main class="container single">
        <section class="card">
            <%-- "title" and "message" are set by FileUtils.showError().
                 They are fixed texts written in our Java code, never text typed by the user,
                 so printing them directly is safe. If this page is opened by the error-page
                 rules in web.xml (404 / 500), no message exists and a generic one is shown. --%>
            <h2>${empty title ? 'Oops!' : title}</h2>
            <p class="error-message">
                ${empty message ? 'The page was not found or an unexpected error occurred. Please try again.' : message}
            </p>
            <div class="buttons">
                <a class="btn btn-primary" href="${pageContext.request.contextPath}/">Back to home</a>
            </div>
        </section>
    </main>
</body>
</html>
