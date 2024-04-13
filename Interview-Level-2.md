
# Web Application

### SQL injection and its type:

**1. In-band SQL Injection:**
a) **Union-based SQLi:** Utilizes the SQL UNION operator to combine the results of two or more
    SELECT queries into a single result set.

```
' UNION SELECT null--comment
' UNION SELECT null,nul l--comment
' UNION SELECT null,null,null--comment
' UNION SELECT null,null,null,null--comment
1 UNION SELECT username, password FROM users
```
```
b) Error-based SQLi : Injects SQL code that triggers database errors, revealing information
about the database structure or contents.
AND 1=1—
SELECT 1/0 –
AND 1=0--
AND 1=1#
AND 1=0#
OR 1=
OR 1=
OR x=x
OR x=y
```
**2. Out-of-band SQL Injection:**
Instead of retrieving data directly through the application, use alternative communication
methods (such as DNS or HTTP queries) to access the database.
**3. Blind SQL Injection:**
a) **Boolean-based Blind SQLi:** Sends SQL queries that result in a true or false response, using
    conditional statements to extract data.
    ' OR '
    ' OR 1 -- -
    " OR "" = "
    " OR 1 = 1 -- -
    ' OR '' = '
    ' OR 1=1 --
    ' OR 1=1 AND 'a'='a

```
b) Time-based Blind SQLi : Introduces time delays in SQL queries to infer information from the
database based on the application's response time.
sleep(5)#
```

```
" or sleep(5)#
' or sleep(5)#
" or sleep(5)="
' or sleep(5)='
; WAITFOR DELAY '0:0:10'—
waitfor delay '00:00:05'
```
**4. Second-order SQL Injection:** Second-order SQL injection, also known as stored or persistent SQL injection,
    is a type of SQL injection attack where the malicious payload is stored within the application's database, and the
    execution of the payload occurs at a later time when certain conditions are met.

### OWASP TOP 10

```
Top 10 Web Application Security Risks 2021 Mobile Top 10 2024: Final Release Updates
A01:2021-Broken Access Control M1: Improper Credential Usage
A02:2021-Cryptographic Failures M2: Inadequate Supply Chain Security
A03:2021-Injection M3: Insecure Authentication/Authorization
A04:2021-Insecure Design M4: Insufficient Input/Output Validation
A05:2021-Security Misconfiguration M5: Insecure Communication
A06:2021-Vulnerable and Outdated Components M6: Inadequate Privacy Controls
A07:2021-Identification and Authentication Failures M7: Insufficient Binary Protections
A08:2021-Software and Data Integrity Failures M8: Security Misconfiguration
A09:2021-Security Logging and Monitoring Failures* M9: Insecure Data Storage
A10:2021-Server-Side Request Forgery (SSRF)* M10: Insufficient Cryptography
```
```
OWASP Top 10 API Security Risks – 2023 OWASP Desktop App Security Top 10
API1:2023 Broken Object Level Authorization DA1 - Injections
API2:2023 Broken Authentication DA2 - Broken Authentication & Session Management
API3:2023 Broken Object Property Level Authorization DA3 - Sensitive Data Exposure
API4:2023 Unrestricted Resource Consumption DA4 - Improper Cryptography Usage
API5:2023 Broken Function Level Authorization DA5 - Improper Authorization
API6:2023 Unrestricted Access to Sensitive Business Flows DA6 - Security Misconfiguration
API7:2023 Server Side Request Forgery DA7 - Insecure Communication
API8:2023 Security Misconfiguration DA8 - Poor Code Quality
API9:2023 Improper Inventory Management DA9 - Using Components with Known Vulnerabilities
API10:2023 Unsafe Consumption of APIs DA10 - Insufficient Logging & Monitoring
```
```
Common Ports and services Common Ports and services
20 - FTP (File Transfer Protocol) - Data 143 - IMAP (Internet Message Access Protocol)
21 - FTP (File Transfer Protocol) - Control 161 - SNMP (Simple Network Management Protocol)
22 - SSH (Secure Shell) 179 - BGP (Border Gateway Protocol)
23 - Telnet 443 - HTTPS (Hypertext Transfer Protocol Secure)
25 - SMTP (Simple Mail Transfer Protocol) 514 - Syslog
53 - DNS (Domain Name System) 587 - SMTP (Submission)
67 - DHCP (Dynamic Host Configuration Protocol) -
Server
```
```
5900 - VNC (Virtual Network Computing)
```
```
68 - DHCP (Dynamic Host Configuration Protocol) -
Client
```
```
3389 - RDP (Remote Desktop Protocol)
```
```
80 - HTTP (Hypertext Transfer Protocol) 27017 - MongoDB - Default port for MongoDB database
```

110 - POP3 (Post Office Protocol version 3) 3306 - MySQL Database - Database server
115 - SFTP (Simple File Transfer Protocol) 5432 - PostgreSQL Database - Database server
119 - NNTP (Network News Transfer Protocol) 143 - IMAP (Internet Message Access Protocol)
123 - NTP (Network Time Protocol) 161 - SNMP (Simple Network Management Protocol)

### Common Missing Security Headers

```
Content-Security-Policy
```
```
In simple terms, the purpose of the "Content Security Policy" (CSP) header is to help
protect website from malicious attacks, particularly Cross-Site Scripting (XSS).
```
```
It works by specifying which sources of content are approved, like scripts, stylesheets,
or images. By allowing only trusted sources, CSP prevents unauthorized content from
being loaded onto your site, making it more secure against cyber threats.
```
```
'none' - blocks the use of this type of resource.
'self' - matches the current origin (but not subdomains).
'unsafe-inline' - allows the use of inline JS and CSS.
'unsafe-eval' - allows the use of mechanisms like eval().
Vul vs Fix
```
```
o Content-Security-Policy: script-src 'self' 'unsafe-
inline' 'unsafe-eval';
```
- Content-Security-Policy: default-src 'self'; script-
    src 'self' https://apis.google.com ;

```
o Content-Security-Policy: default-src 'self'
https://example.com;
```
- Content-Security-Policy: default-src 'self'; script-
    src 'self' https://example.com;

(^)
**X-Frame-Options**
X-Frame-Options : Tell the browser whether you want to allow your site to be framed
or not. By preventing a browser from framing your site you can defend against attacks
like clickjacking.
"X-Frame-Options: SAMEORIGIN"
**X-Content-Type-Options**
X-Content-Type-Options stops a browser from trying to MIME-sniff the content type
and force it to stick with the declared content-type.
"X-Content-Type-Options: no sniff".
**Referrer-Policy**
In simpler terms, the purpose of the "Referrer Policy" header is to control how much
information the browser shares when you click on a link and leave a webpage. It
determines what details, such as the website you're coming from, are sent to the new
page you're visiting. This helps protect your privacy and sensitive information from
being unnecessarily shared with other websites.

- **Purpose:** Controls how much information the browser includes with navigations
    away from a document.
- **Vulnerable Example:** Referrer-Policy: unsafe-url
    - This setting allows the full URL (including path and query parameters) to


```
be sent in the Referer header, potentially exposing sensitive information.
```
- **Fix Example:** Referrer-Policy: strict-origin
    - This setting instructs the browser to include only the origin (scheme, host,
       and port) of the referring URL in the Referer header, enhancing user
       privacy and security.

(^)
**Permissions-Policy**

- **Purpose:** Controls which browser features and APIs can be used.
- **Vulnerable Example:** Permissions-Policy:accelerometer=*
    - This setting allows any origin to access the device's
       accelerometer API, potentially leading to unauthorized access
       or misuse of sensitive device capabilities.
- **Fix Example:** Permissions-Policy: accelerometer=()
    - This setting restricts access to the accelerometer API to the
       same origin only, preventing unauthorized access and reducing
       the risk of exploitation.
- Permissions-Policy: camera=*, geolocation=*, microphone=*
    ▪ This policy allows any origin to access the camera, geolocation, and
       microphone APIs, potentially leading to unauthorized access or misuse of
       sensitive device capabilities:
- Permissions-Policy: camera=(), geolocation=(), microphone=()

```
▪ This policy restricts access to the camera, geolocation, and microphone APIs
to the same origin only, preventing unauthorized access and reducing the risk
of exploitation.
```
### Common Cookies and It’s values

**1. Secure:**
    - **_Value_** : Secure
    - **_Mitigate_** : Man In the middle Attack.
    - **_Explanation_** : By setting the secure attribute, the cookie will only be sent over HTTPS
       connect 8 ions, reducing the risk of interception by attackers.
**2. HttpOnly:**
    - **_Value_** : HttpOnly
    - **_Mitigate_** : XSS
    - **_Explanation_** : When a cookie has the HttpOnly attribute set, JavaScript cannot access
       it, which helps mitigate certain types of XSS attacks.
**3. SameSite:**
    **_Values_** : Strict, Lax, or None
    **_Explanation_** : The SameSite attribute defines when cookies should be sent along with
    cross-site requests.


```
a) Strict : The cookie will only be sent in a first-party context, which
provides a high level of protection against CSRF attacks.
b) Lax : The cookie will be sent in a first-party context and in cross-origin
POST requests initiated by top-level navigations.
c) None : The cookie will be sent in all contexts, including cross-origin
requests. However, this requires the Secure attribute to be set as well.
```
```
Let's say you have a website https://example.com and you want to set a
cookie named session_id for user authentication. You want to ensure that
the cookie is sent securely and protect against CSRF attacks.
```
1. **Strict** :
    **Example** : **Set-Cookie: session_id=abc123; SameSite=Strict; Secure**
    **Explanation** : With SameSite=Strict, the **session_id** cookie will only be sent in first-
    party contexts. This means it will only be included in requests initiated by
    **example.com** , such as when the user navigates directly to pages on **example.com**. It
    won't be sent in cross-origin requests, even if they're initiated by **example.com**.
    Adding **Secure** ensures that the cookie is only sent over HTTPS connections.
2. **Lax** :
    - **Example** : **Set-Cookie: session_id=abc123; SameSite=Lax; Secure**
    - **Explanation** : With SameSite=Lax, the **session_id** cookie will be sent in first-
       party contexts as well as in cross-origin POST requests initiated by top-level
       navigations. For example, if a form on **example.com** submits data to another
       origin via POST, the **session_id** cookie will be included. Again, **Secure** ensures
       that the cookie is only sent over HTTPS connections.
3. **None** :
    - **Example** : **Set-Cookie: session_id=abc123; SameSite=None; Secure**
    - **Explanation** : SameSite=None allows the **session_id** cookie to be sent in all
       contexts, including cross-origin requests. However, it requires the **Secure**
       attribute to be set, meaning the cookie will only be sent over HTTPS connections.
       This is commonly used for scenarios like Single Sign-On (SSO), where the cookie
       needs to be included in cross-origin requests, such as when accessing resources
       on different domains.

### JWT Tokens

A JWT, which stands for JSON Web Token, is like a small, safe package for sending information
between two parties over the internet. It's often used to show that a user is logged in and to share
details about them securely.

- **Header** : Contains metadata about the token, such as the algorithm used for signing.
    _Example_ : {"alg": "HS256", "typ": "JWT"}
- **Payload** : Contains claims, which are statements about an entity (e.g., user information) and
    additional data.
    _Example_ : {"sub": "john.doe@example.com", "name": "John Doe", "exp": 1678303200}
- **Signature** : Created by encoding the header and payload, then signing them with a secret
    key. It verifies the sender's identity and ensures the integrity of the message.
    _Example_ : gDlQmk8bg3JgrAytXn_FfRy6zSrLJQk-VvENiUcGG2Y


### CORS vs SOAP

**SOAP** : The SOP policy helps protect users from malicious scripts that could access their sensitive
data or perform **unauthorized actions on their behalf.**

For example, if **business.com** tries to make an HTTP request to **metrics.com** , the browser, by
default, will block the request because it comes from a different domain.

**CORS** is a security feature created to selectively relax the SOP restrictions and enable controlled
access to resources from different domains. CORS rules allow domains to specify which domains can
request information from them by adding specific HTTP headers in the response

```
Access-Control-Allow-Origin: This header specifies the allowed domains to read the
response contents. The value can be either a wildcard character (*) , which indicates all
domains are allowed, or a comma-separated list of domains.
```
```
Access-Control-Allow-Credentials: This header determines whether the domain
allows for passing credentials — such as cookies or authorization headers in the cross-origin
requests.
```
```
The value of the header is either True or False. If the header is set to “true,” the domain
allows sending credentials. If it is set to “false,” or not included in the response, then it is not
allowed.
```
### CORS Misconfiguration

**1. Reflected Origins:** Domains get reflected in the response header.
    a. **Impact High – Access-Control-Allow-Credentials = True**
    b. **Impact Low - Access-Control-Allow-Credentials = False**
    c. **Exploitable** : Yes
**2. Modified Origins** : If no checks are in place CORS Policy can be bypassed. For example,
    adding a prefix or suffix to the **abc.com** domain would be something like
    **attackerabc.com** or **abc.com.attack.com**.
       a. **Impact High – Access-Control-Allow-Credentials = True**
       b. **Impact Low - Access-Control-Allow-Credentials = False**
       c. **Exploitable:** Yes
**3. Trusted subdomains with Insecure Protocol.** Set the Origin header to an existing subdomain
    and see if it accepts it. If it does, it means the domain trusts all its subdomains. This is not a
    good idea because if one of the subdomains has a Cross-Site Scripting (XSS) vulnerability, it
    will allow the attacker to inject a malicious JS payload and perform unauthorized actions.
       a. **Impact High** : If domain accepts subdomains with an insecure protocol like http
       b. **Impact Low:** Otherwise, it will not be exploitable and would be only a poor CORS
          implementation.


**4. Null Origin:** Set the Origin header to the null value — **Origin: null** , and see if the
    application sets **the Access-Control-Allow-Origin** header to null. If it does, it means
    that null origins are whitelisted.
       a. **Impact High:** if the domain allows for authenticated requests with the **Access-**
          **Control-Allow-Credentials** header set to **true.**
       b. **Impact Low and not exploitable:** If the case is not above then low impact and not
          exploitable.
**5.** Unexplainable Case **: Wild Card (*) –** but its misconfiguration and not exploitable.

### Intruder attack Type:

**1. Sniper:**
    - Work on single payload set.
    - If 3 positions are selected then one by one position are set with payload to run. It
       work set payload in first position and rest two values will as it is. Now same goes of
       rest two positions.
    - It means sniper handles single position at time.
**2. Battering RAM**
    - Work on single payload set.
    - Payload set at all position simultaneously.
**3. Pitchfork**
    - Work on multiple set of payload.


- Work on the minimum number of payloads.
- If two payloads contain number like 6 and 4, then will generate 4 payloads only.
- To run this at all position one payload is needed.
**4. Cluster Bomb**
- Work on multiple set of payload.
- All the permutation and combination of payloads generates.
- Suppose if the payload set is 2 and position also two then works as shown in image.


- billion laugh attack
- SSRF and bypass
- Deserialization Vulnerability,
- xml attack,
- SSL key Pinning bypass
- login page - scenario (authentication bypass by SQL injection, host header injection, url
    redirection, username enumeration, rate limiting or brute force,
- directory traversal,
- LFI and RFI
- How to connect proxy with mobile
- By SSRF exploit LFI, RFI, or command injection
- SQL injection and it's type

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


# Android Application

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

**Pictorial representation of android architecture with several main components and their sub
components –**


**Applications –**

Applications are the top layer of android architecture. The pre-installed applications like home,
contacts, camera, gallery etc. and third-party applications downloaded from the play store like chat
applications, games etc. will be installed on this layer only.

It runs within the Android run time with the help of the classes and services provided by the
application framework.

**Application framework –**

Application Framework provides several important classes which are used to create an Android
application. It provides a generic abstraction for hardware access and also helps in managing the
user interface with application resources. Generally, it provides the services with the help of which
we can create a particular class and make that class helpful for the Applications creation.

It includes different types of services activity manager, notification manager, view system, package
manager etc. which are helpful for the development of our application according to the prerequisite.

**Application runtime –**

Android Runtime environment is one of the most important parts of Android. It contains
components like core libraries and the Dalvik virtual machine (DVM). Mainly, it provides the base for
the application framework and powers our application with the help of the core libraries.

Like Java Virtual Machine (JVM),

**Dalvik Virtual Machine (DVM)**

DVM is a register-based virtual machine and specially designed and optimized for android to ensure
that a device can run multiple instances efficiently. It depends on the layer Linux kernel for threading
and low-level memory management. The core libraries enable us to implement android applications
using the standard JAVA or Katlin programming languages.

**Platform libraries –**

The Platform Libraries includes various C/C++ core libraries and Java based libraries such as Media,
Graphics, Surface Manager, OpenGL etc. to provide a support for android development.

- **Media** library provides support to play and record audio and video formats.
- **Surface manager** responsible for managing access to the display subsystem.
- **SGL** and **OpenGL** both cross-language, cross-platform application program interface (API) are
    used for 2D and 3D computer graphics.
- **SQLite** provides database support and **Free Type** provides font support.
- **Web-Kit** This open source web browser engine provides all the functionality to display web
    content and to simplify page loading.
- **SSL (Secure Sockets Layer)** is security technology to establish an encrypted link between a
    web server and a web browser.


### Linux Kernel –

Linux Kernel is heart of the android architecture. It manages all the available drivers such as display
drivers, camera drivers, Bluetooth drivers, audio drivers, memory drivers, etc. which are required
during the runtime.

The Linux Kernel will provide an abstraction layer between the device hardware and the other
components of android architecture. It is responsible for management of memory, power, devices
etc.

**The features of Linux kernel are:**

- **Security:** The Linux kernel handles the security between the application and the system.
- **Memory Management:** It efficiently handles the memory management thereby providing
    the freedom to develop our apps.
- **Process Management:** It manages the process well, allocates resources to processes
    whenever they need them.
- **Network Stack:** It effectively handles the network communication.
- **Driver Model:** It ensures that the application works properly on the device and hardware
    manufacturers responsible for building their drivers into the Linux build.

### Common Components –

1. **Activity** :

```
o Represents a single screen with a user interface in an Android application.
o Entry point for user interaction.
o Potential security issues: insecure data storage, input validation, authentication
flaws.
```
- **Broadcast Receiver** :
    o Listens for system-wide broadcast messages or intents.
    o Responds to system events.
    o Potential security issues: insecure broadcast handling, privilege escalation.
- **Intent** :
    o Messaging object used to communicate between components.
    o Starts Activities, Services, delivers broadcasts, or passes data between components.
    o Potential security issues: intent spoofing, intent injection, insecure data passing.

```
➢ Explicit Intents :
o Used to start a specific component within the same application.
o Requires specifying the target component's class or package name.
o Example: Starting a new Activity within the app.
➢ Implicit Intents :
o Used to trigger actions based on an action string.
o Does not specify the target component's name but defines an action to
be performed.
o Android system resolves the intent based on available components
capable of handling the action.
```

```
o Example: Opening a web page or sending an email.
```
- **Service** :
    o Background component that performs long-running operations.
    o Runs tasks asynchronously without a user interface.
    o Potential security issues: insufficient authentication, denial of service (DoS), data
       leakage.
- **Content Provider** :
    o Manages shared application data accessible by other applications or components.
    o Provides a standardized interface for accessing and manipulating data.
    o Potential security issues: insecure data exposure, insufficient access controls.
- **Manifest File (AndroidManifest.xml)** :
    o Configuration file containing essential information about the application.
    o Declares components, permissions, and hardware requirements.
    o Potential security issues: excessive permissions, missing security controls.
- **WebView** :
    o Embeds web content within an application.
    o Can execute JavaScript, load remote URLs, and interact with the DOM.
    o Potential security issues: JavaScript injection, XSS attacks, insecure communication.
- **Activity Manager**
    o Manages the lifecycle of application activities.
    o Controls the creation, starting, pausing, and stopping of activities.
    o Handles activity stacking and navigation within the application.

### Common Tool for Static Analysis–

- **Tool** :
    o **Automation** : MobSF, BuprSuite, Frida, Drozer ...
    o **Manual** : Burpsuite, apktool , jadx-gui, dex2jar, Ghidra

**dex2jar** is a command-line tool for converting Android DEX files (Dalvik Executable) to JAR files,
which can then be decompiled using Java decompiles like JD-GUI

**Ghidra** is powerful reverse engineering framework. It provides features for disassembly,
decompilation, scripting, and collaborative reverse engineering, making it suitable for static analysis

### APK Folder Components –

The Android Package (APK) file is a compressed archive file that contains all the files needed to run
an Android application on an Android device. The APK file is essentially a ZIP file that contains
several components, including:

#### 1. AndroidManifest.xml: This file contains information about the application, including its

```
package name, version number, required permissions, and components such as activities,
services, and broadcast receivers.
```
#### 2. Classes.dex: This file contains the compiled Java bytecode for the application’s classes,

```
which are executed by the Android Runtime (ART).
```

#### 3. Resources.arsc: This file contains compiled resources such as strings, images, and layouts

```
that are used by the application.
```
#### 4. lib/: This folder contains compiled native code libraries for specific device architectures,

```
such as ARM or x86.
```
#### 5. META-INF/: This folder contains the manifest file, the certificate of the APK signature, and a

```
list of all the files in the APK, along with their checksums.
```
#### 6. assets/: This folder contains additional application data files, such as sound and video files,

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

```
o Look for use of encryption algorithms and verify implementation correctness.
o Check for hardcoded keys, weak encryption methods, or use of insecure cryptographic
algorithms.
```
- Code Obfuscation:
    o Check for obfuscation techniques used to hide code.
    o Verify that obfuscation does not hide malicious code.
- API Usage:
    o Verify absence of insecure or vulnerable APIs.
    o Look for APIs allowing unauthorized access or data leakage.
- Hardcoded Sensitive Information:

#### o Look for insecure storage of sensitive data.

```
o Check for hardcoded database queries, passwords, keys, or URLs.
```
- External Libraries:
    o Verify absence of insecure or vulnerable third-party libraries.


- Integrity Checks:
    o Look for integrity checks to prevent tampering with code.
- Native Code:
    o If present, verify secure compilation of native code.
- Web View Related Checks:

#### o setJavaScriptEnabled(): Ensure proper validation of input data to prevent

#### injection of malicious JavaScript code.

#### o setAllowFileAccess(): Validate input data to prevent unauthorized

#### access/modification of local files.

#### o addJavascriptInterface(): Validate input data to prevent execution of

#### arbitrary Java code.

#### o runtime.exec(): Prevent injection of malicious input data to avoid execution of

#### arbitrary shell commands.

- Root Detection Implementation Details:
    o Verify implementation details of root detection mechanisms.
- SSL Pinning Implementation Details:
    o Review implementation details of SSL pinning to ensure secure communication.


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
    o Export burpsuite certificate
    o Configured port and interface in burpsuite.
    o Setup manual proxy in android device and enter the ip and port of burp config.
    o Send Burpsuite certificate in android and install.
    o Burp configuration done.
- **Setup Frida with BuprSuite:**
    o Check android architecture and download accordingly **Frida-server**
       adb shell getprop ro.product.cpu.abi // Check architecture
    o Download the burp certificate and renamed it as cert-der.crt


```
o Now send the Frida-server and burp certificate in android location /data/local/tmp
o Done!
```
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
```
# Frida command explain
```
- f: Specifies the target application package name ('com.userapp.test') to attach to.
- l: Specifies the Frida script file (`fridascript.js`) to load and execute.
- U: Specifies that the target device is connected over USB.
- **SSL Unpinning using Exposed-Module**

```
# SSL Unpinning Bypass using Expose Module
git clone https://github.com/ac-pm/SSLUnpinning_Xposed.git
cd /SSLUnpinning_Xposed
```

```
adb install mobi.acpm.sslunpinning_latest.apk
Open in android and check for SSL unpinning
```
- **Root Detection Bypass Using Frida**

```
# Bypass anti-root detection mechanisms
frida - U --codeshare dzonerzy/fridantiroot - f in.<package
company>.<package name
```

## Source Code Analysis

### Vulnerable code Challenge in Python and flask:

- The SQL Injection vulnerability is fixed by using parameterized queries.
- The SSRF vulnerability is fixed by validating the URL with filter_var() function.
- The XSS vulnerability is fixed by using htmlspecialchars() to escape user input.
- The CSRF vulnerability is addressed by including a CSRF token in the form.
- The OS Command Injection vulnerability is mitigated by using escapeshellarg() to escape user input.
- The LFI vulnerability is addressed by checking if the file exists before reading its content.
- The RFI vulnerability is mitigated by validating the URL and handling HTTP errors properly.

# SQL Injection (SQLi)
# Vulnerable Code: Direct concatenation of user input into SQL query.
# Fix: Use parameterized queries to separate data from commands.
import sqlite

def get_user(username):
conn = sqlite3.connect('database.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE username = '" + username +
"'") # Vulnerable
return cursor.fetchone()

# Fixed Code
def get_user(username):
conn = sqlite3.connect('database.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE username = ?", (username,)) #
Fixed
return cursor.fetchone()

# Server-Side Request Forgery (SSRF)
# Vulnerable Code: Direct use of user-controlled input in HTTP requests.
# Fix: Validate and restrict user-supplied URLs to prevent SSRF.
import requests

def fetch_url(url):
response = requests.get(url) # Vulnerable
return response.text

# Fixed Code
def fetch_url(url):


if not url.startswith('http://') and not url.startswith('https://'):
raise ValueError('Invalid URL')
response = requests.get(url)
return response.text

# Cross-Site Scripting (XSS)
# Vulnerable Code: Rendering user input without proper escaping.
# Fix: Use escaping functions to prevent injection of malicious scripts.
from flask import Flask, request, render_template_string, escape

app = Flask(__name__)

@app.route('/')
def index():
name = request.args.get('name', 'Guest')
return render_template_string('<h1>Hello, {{ name }}</h1>', name=name) #
Vulnerable

# Fixed Code
@app.route('/')
def index():
name = request.args.get('name', 'Guest')
return render_template_string('<h1>Hello, {{ name | safe }}</h1>',
name=escape(name)) # Fixed

# Cross-Site Request Forgery (CSRF)
# Vulnerable Code: Lack of CSRF token protection in forms.
# Fix: Include CSRF tokens in<form action="/transfer" method="post">
# <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
# <input type="hidden" name="amount" value="1000">
# <input type="submit" value="Transfer Money">
# </form> forms and AJAX requests.
# Fixed Code
<form action="/transfer" method="post">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
<input type="hidden" name="amount" value="1000">
<input type="submit" value="Transfer Money">
</form>

# OS Command Injection


# Vulnerable Code: Direct use of user input in system commands without
validation.
# Fix: Use subprocess module with proper input validation and sanitization.
import subprocess

def execute_command(command):
result = subprocess.check_output(command, shell=True,
stderr=subprocess.STDOUT) # Vulnerable
return result.decode("utf-8")

# Fixed Code
def execute_command(command):
try:
result = subprocess.check_output(command, shell=True,
stderr=subprocess.STDOUT)
return result.decode("utf-8")
except subprocess.CalledProcessError as e:
return f"Error: {e}"

# Local File Inclusion (LFI)
# Vulnerable Code: Directly opens a file without proper validation.
# Fix: Check if the file exists before reading its content.

# Vulnerable LFI Code
def read_file(file_path):
with open(file_path, 'r') as file:
content = file.read()
return content

# Fixed LFI Code
def read_file_fixed(file_path):
if not os.path.isfile(file_path):
return "File not found"
with open(file_path, 'r') as file:
content = file.read()
return content

# Remote File Inclusion (RFI)
# Vulnerable Code: Makes an HTTP request to a user-supplied URL without proper
validation.
# Fix: Check if the URL starts with 'http://' or 'https://' and handle HTTP
errors properly.

# Vulnerable RFI Code
def fetch_remote_file(url):
response = requests.get(url)


return response.text

# Fixed RFI Code
def fetch_remote_file_fixed(url):
if not url.startswith(('http://', 'https://')):
return "Invalid URL"
response = requests.get(url)
if response.status_code != 200 :
return "Failed to fetch remote file"
return response.text

### Vulnerable code Challenge in PHP:

<?php
// SQL Injection (SQLi)
// Vulnerable Code: Direct concatenation of user input into SQL query.
// Fix: Use parameterized queries to separate data from commands.
function get_user($username) {
$conn = new SQLite3('database.db');
$stmt = $conn->prepare('SELECT * FROM users WHERE username = :username');
$stmt->bindValue(':username', $username, SQLITE3_TEXT);
$result = $stmt->execute();
return $result->fetchArray(SQLITE3_ASSOC);
}

// Server-Side Request Forgery (SSRF)
// Vulnerable Code: Direct use of user-controlled input in HTTP requests.
// Fix: Validate and restrict user-supplied URLs to prevent SSRF.
function fetch_url($url) {
if (!filter_var($url, FILTER_VALIDATE_URL)) {
throw new Exception('Invalid URL');
}
return file_get_contents($url);
}

// Cross-Site Scripting (XSS)
// Vulnerable Code: Rendering user input without proper escaping.
// Fix: Use escaping functions to prevent injection of malicious scripts.
$name = isset($_GET['name'])? $_GET['name'] : 'Guest';
echo "<h1>Hello, ". htmlspecialchars($name). "</h1>";

// Cross-Site Request Forgery (CSRF)
// Vulnerable Code: Lack of CSRF token protection in forms.
// Fix: Include CSRF tokens in forms and AJAX requests.
?>
<form action="/transfer" method="post">


<input type="hidden" name="csrf_token" value="<?php echo
$_SESSION['csrf_token']; ?>">
<input type="hidden" name="amount" value="1000">
<input type="submit" value="Transfer Money">
</form>

<?php
// OS Command Injection
// Vulnerable Code: Direct use of user input in system commands without
validation.
// Fix: Use escapeshellarg() function to properly escape user input.
function execute_command($command) {
return shell_exec('ls '. escapeshellarg($command));
}

// Local File Inclusion (LFI)
// Vulnerable Code: Directly opens a file without proper validation.
// Fix: Check if the file exists before reading its content.
function read_file($file_path) {
if (!file_exists($file_path)) {
return "File not found";
}
return file_get_contents($file_path);
}

// Remote File Inclusion (RFI)
// Vulnerable Code: Makes an HTTP request to a user-supplied URL without
proper validation.
// Fix: Check if the URL starts with 'http://' or 'https://' and handle HTTP
errors properly.
function fetch_remote_file($url) {
if (!filter_var($url, FILTER_VALIDATE_URL)) {
throw new Exception('Invalid URL');
}
return file_get_contents($url);
}
?>

// Parameter Pollution
// Vulnerable Code: Assumes a single value for a parameter, leading to
ambiguity or unexpected behavior.
// Fix: Validate and sanitize input, ensure consistent parameter usage
throughout the application.

// Vulnerable Function


function process_input($param) {
// Assuming $param is a single value
// Vulnerable code may misinterpret or overwrite $param due to parameter
pollution
return $param;
}

// Fixed Function
function process_input_fixed($param) {
// Assuming $param is properly validated and sanitized
// Fixed code ensures consistent and safe usage of $param throughout the
application
return $param;
}


