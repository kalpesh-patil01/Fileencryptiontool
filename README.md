# File Encryption & Decryption Tool

A beginner-friendly Java web application (Servlets + JSP) that encrypts a file with a password
and decrypts it again later. It runs locally on **Apache Tomcat 9** and uses **AES-256-GCM**
with a key derived by **PBKDF2-HMAC-SHA-256**.

> ⚠️ **If you lose the password, the encrypted file can NEVER be recovered.**
> There is no reset option, no backdoor and no stored key. Keep your password safe.

---

## 1. Project description

You upload a file in the browser, type a password, and the server returns an encrypted file
(`yourfile.txt.enc`). Later you upload the `.enc` file with the same password and get your
original file back. The original file on your computer is never changed or deleted.
The server stores nothing permanently and uses no database.

## 2. Features

- Encrypt any file up to 10 MB and download `<name>.enc`
- Decrypt `.enc` files made by this tool and download the original file
- Password-based: AES-256-GCM, PBKDF2 key derivation, new random salt and nonce for every file
- Detects wrong passwords and modified/corrupted files (and never sends unverified data)
- Upload validation (missing file, empty file, empty password, too large, wrong format)
- Safe download file names (path traversal and header-injection characters removed)
- Friendly error page without Java stack traces or server paths
- Responsive HTML/CSS page, only a tiny bit of JavaScript for convenience checks

## 3. Technology stack

| Part | Technology |
|------|-----------|
| Language | Java 11 or later |
| Web layer | Java Servlets (`javax.servlet`, Servlet 4.0) |
| Frontend | JSP, HTML5, CSS3 (small inline JavaScript for convenience checks) |
| Server | Apache Tomcat 9 |
| Cryptography | Java Cryptography Architecture (`javax.crypto`) |
| Build | Maven, WAR packaging |

No Spring, Hibernate, database or external UI framework is used.

## 4. Project structure

```
FileEncryptionTool/
├── pom.xml                         Maven build file (WAR, Servlet API 4.0.1 "provided")
├── README.md
└── src/main/
    ├── java/com/fileencryption/
    │   ├── servlet/
    │   │   ├── EncryptionServlet.java        POST /encrypt
    │   │   └── DecryptionServlet.java        POST /decrypt
    │   ├── service/
    │   │   ├── FileEncryptionService.java    AES-GCM + PBKDF2 logic (no servlet code)
    │   │   └── FileEncryptionException.java  error whose message is safe to show
    │   └── util/
    │       └── FileUtils.java                file names, downloads, error page, size limits
    └── webapp/
        ├── index.jsp                         home page with both forms
        ├── result.jsp                        error page
        ├── css/style.css
        └── WEB-INF/web.xml                   welcome page + generic error pages
```

## 5. Servlets and JSP used in this project

A **servlet** is a Java class that runs inside Tomcat and answers HTTP requests. The idea is
similar to a Django view, but you read the request and write the response yourself.

| Concept | Where it is used |
|---------|------------------|
| `@WebServlet("/encrypt")` | Maps a URL to a servlet class (like `path()` in Django `urls.py`). |
| `doPost(request, response)` | Runs for POST requests (form submit). `doGet` redirects to the home page. |
| `@MultipartConfig` | Allows reading `multipart/form-data` (file upload) and sets the size limits. |
| `request.getPart("file")` | Gets the uploaded file. `Part.getInputStream()` reads its bytes. |
| `request.getParameter("password")` | Reads a normal form field (works in multipart requests because of `@MultipartConfig`). |
| `Content-Disposition: attachment` | Response header that makes the browser download the data as a file. |
| `getRequestDispatcher("/result.jsp").forward(...)` | Shows the error page (like `render()` in Django). |
| `web.xml` | Deployment descriptor: welcome page and generic error pages. |

A **JSP** is an HTML page that Tomcat converts into a servlet. The JSPs here contain only HTML
and EL expressions such as `${pageContext.request.contextPath}`. There are **no scriptlets**
(`<% ... %>`) and no business logic in JSP files.

The form `action` URLs (`/encrypt`, `/decrypt`) match the `@WebServlet` values.

## 6. AES-GCM and PBKDF2 explained

**AES** is a block cipher: it turns data into unreadable bytes using a secret key.
**GCM** (Galois/Counter Mode) is a mode of AES that gives you:

1. **Confidentiality** – nobody can read the data without the key.
2. **Integrity / authenticity** – a 128-bit *authentication tag* is added at the end. If the
   password is wrong, or even **one bit** of the file changed, the tag check fails and
   decryption is refused.

GCM needs a **nonce** (a 12-byte number that must never repeat for the same key). A new random
nonce is created for every encryption.

**PBKDF2** (Password-Based Key Derivation Function 2) turns a human password into a strong
256-bit AES key. It mixes the password with a random **salt** and repeats HMAC-SHA-256 many
times (**600,000 iterations**, the current OWASP recommendation for PBKDF2-HMAC-SHA256).
The repetition makes every password guess slow for an attacker. The salt makes sure the same
password gives a different key for every file. The password is **never** used directly as a key.

The iteration count is defined in `FileEncryptionService.PBKDF2_ITERATIONS`. It is stored inside
each encrypted file, so you can raise it later and old files can still be decrypted.

## 7. How encryption works

1. The browser sends the file and password to `POST /encrypt`.
2. `EncryptionServlet` checks: multipart request, file present and not empty, size ≤ 10 MB,
   password present, at least 8 characters, and password = confirmation.
3. `FileEncryptionService.encrypt()`:
   1. creates a random 16-byte salt and a random 12-byte nonce with `SecureRandom`
   2. derives a 256-bit key with PBKDF2-HMAC-SHA-256
   3. writes the header, then encrypts the data in 8 KB pieces with AES-GCM
   4. appends the 16-byte authentication tag
4. The result is written to a **temporary file**, sent to the browser with
   `Content-Disposition: attachment; filename="<safe name>.enc"`, and then deleted.

### Encrypted file format (version 1)

| Offset | Size | Content |
|-------:|-----:|---------|
| 0 | 4 | Magic bytes `FENC` |
| 4 | 1 | Format version (`1`) |
| 5 | 4 | PBKDF2 iteration count |
| 9 | 16 | Salt |
| 25 | 12 | Nonce |
| 37 | … | Ciphertext + 16-byte GCM tag |

The 37-byte header is passed to GCM as *additional authenticated data*, so changing the salt,
nonce or iteration count also makes authentication fail. The overhead is 53 bytes per file.

## 8. How decryption works

1. The browser sends the `.enc` file and password to `POST /decrypt`.
2. `DecryptionServlet` validates the upload. Then `FileEncryptionService.decrypt()` checks the
   header: magic bytes, version, and an iteration count inside a sane range (so a fake file
   cannot make the server calculate for hours).
3. It derives the key from the password and the stored salt and decrypts.
4. **The decrypted data goes into a temporary file, not to the browser.** GCM verifies the tag
   only at the very end, so anything written earlier is *unverified*.
5. Only when verification succeeds is the temporary file sent as a download.
   If it fails, the user sees *"the password is wrong, or the file has been modified or
   corrupted"* and the temporary file is deleted. Nothing is sent.

`name.txt.enc` is downloaded as `name.txt`.

## 9. Prerequisites

- **JDK 11 or later** (a JDK, not only a JRE). Check with `java -version` and `javac -version`.
- **Apache Maven 3.6 or later**. Check with `mvn -version`.
- **Apache Tomcat 9.x**. Do NOT use Tomcat 10 or 11: they use `jakarta.servlet` and would not run this app.
- The `JAVA_HOME` environment variable pointing to your JDK (Tomcat needs it).

## 10. Build the WAR with Maven

Extract `FileEncryptionTool.zip` (right-click → *Extract All…*), or use Command Prompt:

```bat
mkdir C:\Projects
cd /d C:\Projects
tar -xf "%USERPROFILE%\Downloads\FileEncryptionTool.zip"
```

Then build:

```bat
cd /d C:\Projects\FileEncryptionTool
mvn clean package
```

Success ends with `BUILD SUCCESS` and creates `target\FileEncryptionTool.war`.
The first build downloads Maven plugins, so it needs an internet connection.

## 11. Deploy to Tomcat 9

Tomcat is assumed to be installed in `C:\apache-tomcat-9.0.117`.
**If yours is somewhere else**, change the path in the first line below. Everything after it
uses the variable.

```bat
set CATALINA_HOME=C:\apache-tomcat-9.0.117
copy /Y target\FileEncryptionTool.war "%CATALINA_HOME%\webapps\"
```

Start Tomcat:

```bat
"%CATALINA_HOME%\bin\startup.bat"
```

A new window opens with the Tomcat log. Wait for a line like `Server startup in [...] milliseconds`.
Tomcat unpacks the WAR automatically into `webapps\FileEncryptionTool\`.

Stop Tomcat:

```bat
"%CATALINA_HOME%\bin\shutdown.bat"
```

**Re-deploying after a code change:** stop Tomcat, run `mvn clean package`, delete the old
deployment, then copy the new WAR:

```bat
rmdir /S /Q "%CATALINA_HOME%\webapps\FileEncryptionTool"
del "%CATALINA_HOME%\webapps\FileEncryptionTool.war"
copy /Y target\FileEncryptionTool.war "%CATALINA_HOME%\webapps\"
```

## 12. Find or change the Tomcat port

Do not assume 8080. Look at the HTTP connector in `conf\server.xml`:

```bat
findstr /N /C:"<Connector port" "%CATALINA_HOME%\conf\server.xml"
```

Or open it with `notepad "%CATALINA_HOME%\conf\server.xml"` and find the connector that has
`protocol="HTTP/1.1"`:

```xml
<Connector port="8080" protocol="HTTP/1.1"
           connectionTimeout="20000"
           redirectPort="8443" />
```

To use another port (for example 9090), change `port="8080"` to `port="9090"`, save the file,
and restart Tomcat (`shutdown.bat`, then `startup.bat`).

To see which program is using a port (for example 8080):

```bat
netstat -ano | findstr :8080
```

## 13. Open the application

```
http://localhost:<PORT>/FileEncryptionTool/
```

Replace `<PORT>` with the number from `server.xml` (for example
`http://localhost:8080/FileEncryptionTool/`). `FileEncryptionTool` is the WAR file name,
so renaming the WAR changes the URL.

**Quick manual test:**

1. Encrypt a small `.txt` file and download the `.enc` file.
2. Decrypt it with the same password and compare it with the original.
3. Try a wrong password. You must see an error and no download.
4. Change one byte of the `.enc` file in a hex editor and try again. It must fail.
5. Try submitting the form without choosing a file.

## 14. Common errors and solutions

| Problem | Cause / Solution |
|---------|------------------|
| `'mvn' is not recognized` | Maven is not installed or not in `PATH`. Add Maven's `bin` folder to `PATH` and open a **new** Command Prompt. |
| `release version 11 not supported` / `invalid target release` | You are using JDK 8. Install JDK 11+ and point `JAVA_HOME` to it. |
| `Neither the JAVA_HOME nor the JRE_HOME environment variable is defined` | Run `set JAVA_HOME=C:\Path\To\Your\JDK` (or set it permanently in *System Properties → Environment Variables*). |
| Tomcat window opens and closes immediately | Usually `JAVA_HOME` is missing or the port is in use. Run `"%CATALINA_HOME%\bin\catalina.bat" run` to see the error in the same window. |
| `Address already in use` / port 8080 in use | Another program uses the port. Stop it or change the port (section 12). |
| Browser shows **404** for `/FileEncryptionTool/` | The WAR is not deployed or failed to start. Check that `webapps\FileEncryptionTool\` exists and read `logs\catalina.<date>.log`. Check the port and the exact URL. |
| 404 and the log mentions `javax/servlet` or `jakarta` | You are using Tomcat 10/11. Install **Tomcat 9**. |
| `javax.servlet cannot be resolved` in your IDE | Reload the Maven project. The Servlet API is only needed at compile time (scope `provided`). |
| "The file is too large" | The limit is 10 MB for the original file. To change it, edit `FileUtils.MAX_FILE_SIZE`, rebuild and redeploy. |
| "the password is wrong, or the file has been modified or corrupted" | Wrong password, or the `.enc` file was changed or damaged (for example by a text editor or an incomplete download). The tool cannot tell which, on purpose. |
| "not encrypted by this tool" | The selected file does not start with the `FENC` header. |
| Downloaded file has a slightly different name | Names are cleaned for safety: only letters, digits, `.`, `-`, `_` are kept. Spaces and non-English letters become `_`. |
| Old version still shows after redeploy | Delete the old `webapps\FileEncryptionTool` folder before copying the new WAR (section 11) and refresh the browser cache. |

## 15. Security limitations and warnings

- **Password loss = data loss.** Nothing can recover a file without its password.
- **Use HTTPS if the server is not your own computer.** On `http://localhost` your password never
  leaves your machine. Over a network, plain HTTP would expose the password and the file.
  Configure TLS in Tomcat before any real use.
- **A strong password is required.** PBKDF2 slows guessing down but cannot save a weak password
  like `password123`. Use a long passphrase.
- **Temporary files:** data is briefly written to the operating system's temporary folder
  (`java.io.tmpdir`) and deleted right after the response. While a decryption is being checked,
  the *plaintext* exists unencrypted on the server disk. Run this on a machine you trust.
- **The password arrives as a Java `String`,** which cannot be wiped from memory. The application
  wipes the `char[]` copy and the key bytes where it can.
- **Single-message GCM and a 10 MB limit.** The whole file is one GCM message and Java buffers the
  data during GCM decryption, which is why the limit exists. Huge files would need a "chunked" format.
- **File size and type are not hidden.** The `.enc` file reveals the approximate original size.
  The original file name is not stored inside the encrypted file.
- **No user accounts, rate limiting or audit log.** Anybody who can reach the page can use it.
- This is a learning project. It has **not** been audited by a security professional.
