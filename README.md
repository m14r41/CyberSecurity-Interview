**Disclaimer:**
The content presented here does not belong to me in any way. It is a compilation sourced from various domains, and due credit and respect are given to the original creators. I do not endorse or support any unethical activities, and this content is intended solely for educational purposes.

**Note:**
Based on my personal experience, the following list comprises some commonly encountered interview questions. However, I cannot guarantee that interview questions will be 100% derived from this repository.

---
**This is based my personal experiance:**

| S.N | Profile | Level  | Description | Link |
|-----|---------|--------|-------------|------|
| 1   | VAPT    | Level 1| **-** Owasp, Port and services, IP and Mac, Encription, Hashing, Common vulnerability <br> **-** For freshers and experiance | [Click Here](https://github.com/m14r41/CyberSecurity-Interview/tree/main) |
| 2   | VAPT    | Level 2| **-** Dedicated for Experiance Pentester <br> **-** Web, Mobile, API, Thick Client, SAST etc | [Click Here](https://github.com/m14r41/CyberSecurity-Interview/blob/main/Interview-Level-2.md) |




---
# **Level 1:** 
### Awesome Interview Links: For (freshers)

| S.N | Link                                                                                         | By    |
|-----|----------------------------------------------------------------------------------------------|-------------|
| 1   | [Cyber Security Interview Questions - Part 1](https://shifacyclewala.medium.com/cyber-security-interview-questions-part-1-ae00b96c5610) | [Shifa cyclewala](#) |
| 2   | [Cyber Security Interview Questions - Part 2](https://shifacyclewala.medium.com/cyber-security-interview-questions-part-2-13fbb38b9b46) | [Shifa cyclewala](#) |
| 3   | [Cyber Security Interview Questions - Part 3](https://shifacyclewala.medium.com/cyber-security-interview-questions-part-3-2238f36cbe76) | [Shifa yclewala](#) |
| 4   | [Cyber Security Interview Questions - Part 4](https://shifacyclewala.medium.com/cyber-security-interview-questions-part-4-a28f8829d541) | [Shifa cyclewala](#) |
| 5   | [Cyber Security Interview Questions - Part 5](https://shifacyclewala.medium.com/cyber-security-interview-questions-part-5-5be559408234) | [Shifa cyclewala](#) |

### Top 100 Web application Vulnerability and Mitigation: ( Experianced)

| S.N | Link                                                                                         | By    |
|-----|----------------------------------------------------------------------------------------------|-------------|
| 1   | [Top 100 Web Application Vulnerability and Mitigation](https://github.com/m14r41/Interview-CyberSecurity/blob/main/VAPT/Top%20100%20-%20Web%20Vulnerability%20and%20Mitigation.pdf) | [Unknown](#) |

## Dedicated for Freshers, also asked with experianced condidates some questions.
  **Top 20 from list are strongly recommended.**

### 1. Information Security

> Information security is the process employed to safeguard information in any form (physical or electronic) from unauthorized access, disclosure, and destruction.

> According to NIST, it involves protecting information systems from unauthorized activities to ensure confidentiality, integrity, and availability.

### 2. Cyber Security VS Information Security

### Cyber Security

> Cybersecurity focuses on safeguarding electronic data, preventing unauthorized access, disclosure, alteration, and destruction.

> Its primary goal is to protect digital data and systems from unauthorized access, damage, or disruption.

### Information Security

> Information security is a broader discipline encompassing the protection of all types of assets, whether in hard copy or digital form.

> The main objective of information security is to reduce the risk of cyber-attacks and protect against unauthorized exploitation of systems, networks, and technologies.


### 3. What is CIA Triad ?

>CIA Triad an information security model meant to guide an organization’s security procedures and policies.

>Confidentiality, Integrity, and Availability. These are the three core components of the CIA triad


- ```Confidentiality```
  
  >Confidentiality ensures  access to resources or data must be restricted to only authorized subjects or entities. Data encryption is a common method of ensuring confidentiality.
  
  
- ```Integrity```
  
  Integrity involves maintaining the consistency and accuracy of data over its entire life cycle. 
  
  Data must not be changed in transit, for example, when it is sent over the Internet or using a local area network
  
 

- ```availability```

  A vulnerability is a flaw, loophole, oversight, or error that can be exploited to violate the system security policy.
  
    For example, software or an application that has code vulnerable to a buffer or flow exploit.
  
### 3. Explain **Vulnerabilty**, **Threats**, **Exploit** and **Risk**.
- ```Vulnerabilty```
  
  >A vulnerability is a flaw, loophole, oversight, or error that can be exploited to violate system security policy. 
  
  >For example, a software or an application that has code vulnerable to a buffer or flow exploit.
  
  
- **```Threats```**
  
  >A threat is an event, natural or man-made, able to cause a negative impact on an organization.


- **```Exploit```**
  
  
  >An exploit is a defined way to breach the security of an IT system through a vulnerability.
  
  
- **```Risk```**
    ```
    It is an situation involving exposure to dange.
    ```
### 4. Define **Indentification**, **Authentication**, and **Authorization**?
- **```Indentification```**
  
  >Identification is the process in which the ability to identify uniquely a user of a system or an application that is running in the system.
  
- **```Authentication```**
  
  >Process of verifying the identity of the user who claims to be.
  
- **```Authorization```**
  
  >What level of access someone have ,i.e process of granting access and defining the specific resources for a user's needs.
  

### 5. What is 3 way handshake?

>A three-way handshake is a method used in a TCP/IP network to create a connection between a local host/client and server.

- **```Step 1 (SYN):```**

    
    >In the first step, the client wants to establish a connection with a server, so it sends a segment with SYN(Synchronize Sequence Number) which informs the server that the client is likely to start communication and with what sequence number it starts segments with
    

- **```Step 2 (SYN + ACK):```**
    
    >The Server responds to the client request with SYN-ACK signal bits set. Acknowledgement(ACK) signifies the response of the segment it received and SYN signifies with what sequence number it is likely to start the segments with
    

- **```Step 3 (ACK):```**
    
    >In the final part client acknowledges the response of the server and they both establish a reliable connection with which they will start the actual data transfer
    
  
  
 ### 6. What is SSL/TLS handshake? 
 
 >In nutshell, SSL is obsolete and TLS is new name of older SSL protocol as modern encryption standard using by everybody. Technically, TLS is more accurate, but everyone knows SSL.
 

```SSL```    | ````TLS````
-------- | ------------
SSL stands for “Secure Socket Layer.” |	TLS stands for “Transport Layer Security.”
Netscape developed the first version of SSL in 1995. |	The first version of TLS was developed by the Internet Engineering Taskforce (IETF) in 1999.
SSL is a cryptographic protocol that uses explicit connections to establish secure communication between web server and client. | TLS is also a cryptographic protocol that  provides secure communication between web server and client via implicit connections. It’s the successor of SSL protocol.
Three versions of SSL have been released: SSL 1.0, 2.0, and 3.0. |	Four versions of TLS have been released: TLS 1.0, 1.1, 1.2, and 1.3.
All versions of SSL have been found vulnerable, and they all have been deprecated. |	TLS 1.0 and 1.1 have been “broken” and are deprecated as of March 2020. TLS 1.2 is the most widely deployed protocol version.

### 7. Accounting V/S Auditing.
- **```Accounting```**
    ```
    The Process of tracking and recording system activities and resource access.
    ```
-    **```Auditing```**
        ```
     The portion of accounting requires security professionals to examine logs of what was recorded.
        ```


### 8. Give the name of few tools used in penetration testing.

- **```BurpSuite```**
    
    Burp or Burp Suite is a set of tools used for penetration testing of web applications. It is developed by the company named Portswigger, 
    
  -   **Proxy:**
        
        >proxy lets the user see and modify the contents of requests and responses while they are in transit.
        -------------------------------------------
        >It also allow to send the  request/response under monitoring to another relevant tool in BurpSuite, that avoids copy paste.
        -------------------------------------------
        >Also allow to configure the proxy.
        
     - **Intruder:**
        
        >Burp Intruder is a tool for automating customized attacks against web applications
        -------------------------------------------
        >Brute-force attacks on password forms, pin forms, and other such forms.
        -------------------------------------------
        >The dictionary attack on password forms, fields that are suspected of being vulnerable to XSS or SQL injection.
        -------------------------------------------
        >Testing and attacking rate limiting on the web-app.
        
     - **Intruder:**
        
        >Burp Repeater is a simple tool for manually manipulating and reissuing individual HTTP requests, and analyzing the application's responses.
        -------------------------------------------
       >Allow send a request to Repeater from anywhere within Burp, modify the request and issue it over and over again.
        
    - **Decoder**
        
        >Decoder lists the common encoding methods like URL, HTML, Base64, Hex, etc. This tool comes handy when looking for chunks of data in values of parameters or headers.
        -----------------------------------------------
        >Decoder lists the common encoding methods like URL, HTML, Base64, Hex, etc.
        
- **```Nessus```**
    
    >The Nessus vulnerability scanner is a remote security scanner from Tenable, Inc. 
    

    >Nessus scans a computer and then generates alerts if vulnerabilities are discovered.  Nessus runs over 1,000+ checks to see if vulnerabilities exist.
    

- **```Nikto```**
    
    >Nikto is an Open Source software written in Perl language that is used to scan a web-server for the vulnerability that can be exploited and can compromise the server. 
    

    >It can also check for outdated version details of 1200 server and can detect problems with specific version details of over 200 servers.
    
    
    Example : **nikto -host www.example.com
    
- **```Nmap```**
    
    >Nmap is a free and open-source network scanner tool. Nmap is used to discover hosts and services on a computer network by sending packets and analyzing the  responses.
    
    >Nmap provides a number of features for provding computer networks, including host discovery and service and operating dedection.
    

   - **Ping Scan** Nmap discover host by using a ping scan without sending packets.
      
      ```
      nmap -sp 192.100.1.1/24
      ```
      
   - **Host Scan** responds to this packet with another ARP packet containing its status and MAC address.
      ```
      nmap -sp <target IP range>
      ```
   - **OS Scanning** sends TCP and UDP packets to a particular ports and compares this response to a database of 2600 O/S
   
      ```
      nmap -O <target IP>
      ```
   - **Most Popular Ports** 
      ```
      nmap --top-ports 20 192.168.1.106
      ```
   - **Output to a File**
      ```
      -oN output.txt
      ```
      ```
      -oX output.xml
      ```
       

### **9. Encription VS encoding Vs Hashing** 


- **```Hashing:```**
    
    >A string of numbers generated to confirm the integrity of data through hashing algorithms.
    
    
    >Hashing is a form of cryptographic security which differs from encryption. Whereas encryption is a two step process used to first encrypt and then decrypt a message, hashing condenses a message into an irreversible fixed-length value, or hash.
    
- **```Encryption:```**
    
    >A technique used to maintain the confidentiality of data by converting the data into an undecipherable format.
    
- **```Encoding:```**
    
     >A conversion of data from one format to another format.
     
  

 > ### Encription vs Hashing

 |```Encryption``` |	```Hashing``` |
|----------- | ---------|
|A two-way function that takes in plaintext data, and turns it into undecipherable ciphertext.| A one-way method of hiding sensitive data. Using a hashing algorithm, hashing turns a plaintext into a unique hash digest that cannot be reverted to the original plaintext, without considerable effort.|
It is reversible | It is irreversible
Variable Length | 	Fixed Length  
Types :	Asymmetric and Symmetric |	Hashing
Common Algorithms :	AES, RC4, DES, RSA, ECDSA |	SHA-1, SHA-2, MD5, CRC32, WHIRLPOOL


 > ## Encription vs Encoding
 
```symmetric Key Encryption```  | ```Asymmetric Key Encryption```
---------------- | -------------
It only requires a single key for both encryption and decryption.l  |It requires two key one to encrypt and the other one to decrypt.
The encryption process is very fast.  | The encryption process is slow.
It is used when a large amount of data is required to transfer. | It is used to transfer small amount of data.
It only provides confidentiality | It provides confidentiality, authenticity and non-repudiation.
Examples: 3DES, AES, DES and RC4 | Examples: Diffie-Hellman, ECC, El Gamal, DSA and RSA 

### 10. TCP vs UDP

|```TCP``` | ```UDP``` |
|---- | ------|
TCP:Transmission Control Protocol | UDP : User Datagram Protocol
It is a Connection Oriented protocol | It is a Connection less protocol
Acknowledgement is received | Acknowledgment is not received
TCP is comparatively slower than UDP. | UDP is faster, simpler, and more efficient than TCP.
TCP is used by HTTP, HTTPs, FTP, SMTP and Telnet. | UDP is used by DNS, DHCP, TFTP, SNMP, RIP, and VoIP.
UDP is used by DNS, DHCP, TFTP, SNMP, RIP, and VoIP. | There is no retransmission of lost packets in the User Datagram Protocol (UDP)
Retransmission of lost packets is possible in TCP, but not in UDP. | There is no retransmission of lost packets in the User Datagram Protocol (UDP)

### 11. What is OSI Model? 

>OSI stands for Open System Interconnection is a reference model that describes how information from a software application in one computer moves through a physical medium to the software application in another computer.
----------------------------------------
>OSI model consists of seven layers, and each layer performs a particular network function.

>Upper layer of the OSI model mainly deals with the application related issues, and they are implemented only in the software

>He lower layer of the OSI model deals with the data transport issues. The data link layer and the physical layer are implemented in hardware and software. 

| S.N | OSI Layer          | Function                                                                  | Protocols                                 |
|-----|--------------------|---------------------------------------------------------------------------|-------------------------------------------|
| 1   | Application Layer  | Application layer interface directly interacts with the application and provides common web application services                            | HTTP, FTP, SMTP, POP, SNMP, DHCP        |
| 2   | Presentation Layer | Translate, encrypt, and compress data                                    | SSL, TLS, ASCII, JPEG, MPEG              |
| 3   | Session Layer      | To establish, manage, and terminate sessions                             | NetBios, PPTP, RPC, SIP, SSH             |
| 4   | Transport Layer    | Provide Reliable end to end communication solution <br>**-** Form **Semgments**  | TCP, UDP, SCTP, DCCP, SPX               |
| 5   | Network Layer      | <br>**-** Move packet from source to destination <br> **-** Internetworking, Addressing  <br> - Form **Packets**                                            | IP, ICMP, ARP, OSPF, BGP, RIP            |
| 6   | Data Link Layer    | - Framing, error detection and correction, acknowledgment, flow control, ensuring well-defined reliable service interface to the network layer, encapsulating packets from network layer to frames, etc <br> **-** Form **Frames** | Bridge, Switch, Ethernet, PPP, HDLC     |
| 7   | Physical Layer     | **-** Controls the way unstructured, raw, bit-stream data is sent and received over a physical medium. <br> **-** Composed of the electrical, optical, and physical components of the network. <br> **-** Form **Bits** | Coax, Fiber, Wireless, RJ45, Bluetooth  |

<img src="https://github.com/m14r41/CyberSecurity-Interview/assets/95265573/a219dfa7-a885-4064-a584-b3df253cffa5" alt="OSI model" width="600"/>


    

### 12. TCP/IP Model

>TCP/IP model, it was designed and developed by Department of Defense (DoD) in 1960s and is based on standard protocols. It stands for Transmission Control Protocol/Internet Protocol. The TCP/IP model is a concise version of the OSI model. It contains four layers, unlike seven layers in the OSI model. The layers

- >**1. Process/Application Layer** [Application + Presentation + Session Layer](#) 
- >**2. Host-to-Host/Transport Layer** - [transport layer](#)
- >**3.Internet Layer** - [Network layer](#)
- >**4.Network Access/Link Layer** - [Data Link Layer + Physical Layer](#)

### 13. What is OWASP ?

>OWASP Top 10 is an online document on OWASP’s website that provides ranking of and remediation guidance for the top 10 most critical web application security risks


>"Open Web Application Security Proect" is list of most common web application vulnerabilty. It was first updated in 2013 and now it's latest release is 2021.

- >**A01:2021-Broken Access Control**
- >**A02:2021-Cryptographic Failures**
- >**A03:2021-Injection**
- >**A04:2021-Insecure Design**
- >**A05:2021-Security Misconfiguration**
- >**A06:2021-Vulnerable and Outdated Components**
- >**A07:2021-Identification and Authentication Failures**
- >**A08:2021-Software and Data Integrity Failures**
- >**A09:2021-Security Logging and Monitoring Failures**
- >**A10:2021-Server-Side Request Forgery**

### 14. What is pentesting and types of pentesting


>Penetration testing is also known as pen testing or ethical hacking. It describes the intentional launching of simulated cyberattacks that seek out exploitable vulnerabilities in computer systems, networks, websites, and applications.


>The type of penetration testing normally depends on the scope and the organizational wants and requirements. This can classfied in to 3 types


- **Black Box Penetration Testing**
    
    ```In black box penetration testing, tester has no idea about the systems that he is going to test. He is interested to gather information about the target network or system.```<br><br>

-  **White Box Penetration Testing**
    
    ```It is normally considered as a simulation of an attack by an internal source. It is also known as structural, glass box, clear box, and open box testing.``` <br><br>

    ```White box penetration testing examines the code coverage and does data flow testing, path testing, loop testing, etc```. <br><br>

- **Grey Box Penetration Testing**
   ```In this type of testing, a tester usually provides partial or limited information about the internal details of the program of a system.```
    

### 15. What is ports and  most common network ports and services.

>Protocol is a set of rule by definition in computer networking, Protocol is a standard way for computers to exchange information each protocol has a port number assigned to it

>There are 65,535 ports in total

### 16. What is functions of ports
- >**FTP — Port Number : 20,21 :**
    ```
    FTP : File Transfer Protocol
    Use : The purpose of FTP is to transfer files Upload and Download
    ```
- >**SSH — Port 22 :**
    ```
    SSH Secure Shell
    Use : The SSH protocol uses encryption to secure the connection between a client and a server
    It is used for remote login
    ```
- >**Telnet — Port 23 :**
    ```
    Use : Its main function is to establish a connection between a server and a remote computer.
    It is used for remote login
    NOTE: The key difference between Telnet and SSH is that SSH uses encryption,
    which means that all data transmitted over a network is secure , from eavesdropping
    ```
- >**RDP — 3389 :**
    ```
    Remote Desktop Protocol
    This port has been developed by Microsoft. It enables you to establish a connection with a remote computer
    But this time we need a windows device at the other end.
    ```
- >**DNS — 53 :**
    ```
    Domain Name System
    URL to IP Mapping.
    SMTP — 25 :
    Simple mail transfer protocol
    Sending Emails.
    ```
- >**POP3 — 110 :**
    ```
    Post office protocol v3
    Receiving emails.
    ```
- >**IMAP4 — 143:**
    ```
    Internet message access protocol v4
    Receiving emails(new version).
    ```
- >**HTTP — 80 :**
    ```
    hypertext transfer protocol
    Connect to the web pages on the internet
    This is an application layer protocol
    ```
- >**HTTPS — 443 :**

    ```
    Hypertext transfer protocol secure.
    HTTPS is a secure protocol which uses TLS/SSL certificate to ensure the authentication.
    ```
- >**ARP**
    ```
    ARP is a protocol used by the Internet Protocol (IP) [RFC826], to map IP network addresses to the hardware addresses used by a data link protocol

    ARP is used to keep track of all devices that are directly connected IP subnets of the switch

    The switch maintains an ARP table which is made of mapped IP addresses and MAC addresses. 
    
    When a packet needs to be routed to a certain device, the switch looks up the IP address of the device in its ARP table to obtain the MAC address of the destination device. The ARP table includes both static and dynamic addresses.
    ```

### 17. Common Ports and services

| ```Ports``` | `Services`|
| ---- | ----|
|20 |File Transfer Protocol (FTP) Data Transfer
21  | File Transfer Protocol (FTP) Command Control
22  | Secure Shell (SSH)
23  |Telnet - Remote login service, unencrypted text messages
25  |Simple Mail Transfer Protocol (SMTP) E-mail Routing
53 |Domain Name System (DNS) service
80 | Hypertext Transfer Protocol (HTTP) used in World Wide Web
110 |Post Office Protocol (POP3) used by e-mail clients to retrieve e-mail from a server
119 |Network News Transfer Protocol (NNTP)
123 |Network Time Protocol (NTP)
143 |Internet Message Access Protocol (IMAP) Management of Digital Mail
161 |Simple Network Management Protocol (SNMP)
194 |Internet Relay Chat (IRC)
443 |HTTP Secure (HTTPS) HTTP over TLS/SSL

### 14. **What is Bruteforce and how to prevent from it.**

A brute force attack (also known as brute force cracking), is a popular cracking method relies on guessing possible combinations of a targeted password until the correct password is discovered. The longer the password, the more combinations that will need to be tested. 

>### **How to prevent from this.**
- Limit the number of failed login attempts.
- By altering the sshd_config file, you can make the root user unreachable via SSH.
- Instead of using the default port, change it in your sshd config file.
- Make use of Captcha.
- Limit logins to a certain IP address or range of IP addresses.
- Authentication using two factors
- URLs for logging in that are unique
- Keep an eye on the server logs.

### 18. DNS working

1. When searching for a www.example.com,
   
        >we are actually searching for www.example.com. 
        The Browser and OS looks within the computer if the related IP address stored in the cache.


2. If no record found then the Operating system queries the "Resolving Name Server" for the records.
   
        >The Resolving Name Server is configured within the computer automatically or manually.

        >If no enteries in the cache, then the RNS will ask the ROOT Name Servers.


3. The ROOT Name Servers tells where to find the COM name servers or TLD Name Servers.
   
        >The RNS takes all this information, puts it in its cache and then goes to TLD Name Servers. 


4. When the RNS queries COM TLD nameservers for www.example.com., TLS ns then tells the address
   
		>for example.com. Name Servers which are also called Authoriative Name Servers. The RNS puts all
		this information in its cache and goes to example.com. Authoriative NS.


5. The example.com. Authoriative Name Servers will tell the RNS the related IP address of www.example.com.
   
		>This entry is made in the memory of RNS and RNS goes back to the OS. OS then passes this
		information to the browser.



### **19. SSH handshake**
- >**It happens in two steps-**
    ```
	1. Server's identity is authenticated by the client 
   

	2. Client's identity is authenticated by the server
    ```

## 20. **SSL versus TLS**


>SSL Versions 			TLS Versions

- SSLv1					-TLS1.0
- SSLv2					-TLS1.1
- SSLv3(POODLE)			-TLS1.2
- SSLv3.1				-TLS1.3  
    


>SSL 1.0 never publically release because of serious security flaws in the protocol. (Wikipedia - https://en.wikipedia.org/wiki/Transport_Layer_Security#SSL_1.0,_2.0,_and_3.0 )

>Both SSL 2.0, 3.0, TLS 1.0, and 1.1 have been deprecated

 
>SSL is the predecessor to TLS - TLS is the new name for SSL


>HTTPS is HTTP-within-SSL/TLS.


### 21. Some Basic Vulnerabilty and terms.

- >`Application Vulnerabilities`
    
    >Software system flaws or weaknesses in an application that could be exploited to compromise the security of the application.
    >Software system flaws or weaknesses in an application that could be exploited to compromise the security of the application.
    

- >`Buffer Overflow`
    
    >Buffer Overflows occur when there is more data in a buffer than it can handle, causing data to overflow into adjacent storage.
    

- >`Credentials Management`

    >A credentials management attack attempts to breach username/password pairs and take control of user accounts.
    


- >`CRLF Injection`

    >CRLF Injection attacks refer to the special character elements "Carriage Return" and "Line Feed." Exploits occur when an attacker is able to inject a CRLF sequence into an HTTP stream. 
    

- >`Cross-Site Request Forgery`
    
    >Cross-Site Request Forgery (CSRF) is a malicious attack that tricks the user’s web browser to perform undesired actions so that they appear as if an authorized user is performing those actions.
    

- >`Cross-Site Scripting`
    
    >XSS vulnerabilities target scripts embedded in a page that are executed on the client-side (in the user’s web browser) rather than on the server-side. 
    
- >`Directory Traversal`
    
    >Directory traversal is a type of HTTP exploit that is used by attackers to gain unauthorized access to restricted directories and files.
    

- >`Encapsulation`
    
    >Encapsulation refers to a programming approach that revolves around data and functions contained, or encapsulated, within a set of operating instructions.
    

- >`Error Handling`
    
    >Error Handling vulnerabilities occur when a system reveals detailed error messages or codes generated from stack traces, database dumps, and a wide variety of other problems, including out of memory, null pointer exceptions, and network timeout errors.
    
- >`Failure to Restrict URL Access`

    >One of the common vulnerabilities listed on the Open Web Application Security Project’s (OWASP) Top 10. The OWASP Top 10 details the most critical vulnerabilities in web applications. 
    

- >`Insecure Cryptographic Storage`
    
    >Insecure Cryptographic Storage is a common vulnerability that occurs when sensitive data is not stored securely from internal users. 
    

- >`Insufficient Transport Layer Protection`
    
    >Insufficient transport layer protection is a security weakness caused by applications not taking any measures to protect network traffic. 
    
- >`LDAP Injection`
    
    >LDAP injection is the technique of exploiting web applications that use client-supplied data in LDAP statements without first stripping potentially harmful characters from the request. 
    
- >`Malicious Code`
    
    >Analysis tools are designed to uncover any code in any part of a software system or script that is intended to cause undesired effects, security breaches or damage to a system.
    

- >`OS Command Injection`
    
    >Command injection refers to a class of critical application vulnerabilities involving dynamically generated content. Attackers execute arbitrary commands on a host operating system using a vulnerable application.
    

- >`Race Condition`
    
    >A race condition attack happens when a computing system that’s designed to handle tasks in a specific sequence is forced to perform two or more operations simultaneously.
    
- >`SQL Injection`
    
    >SQL injection is a type of web application security vulnerability in which an attacker is able to submit a database SQL command, which is executed by a web application, exposing the back-end database.
    
- >`Null Byte Injection`
    
    >The null character is a control character with the value zero. 

    >It is also possible to pass the null character in the URL, which creates a vulnerability known as Null Byte Injection and can lead to security exploits.
    
    >In the URL it is represented by %00.
     
    
    >Ex- Image with the name hello.gif and can be changed to hello.phpA.gif. Try replacing the hex value of A (\x60) with null byte which is (\x00)
    

- >`Port Knocking :`

    >In computer networking, port knocking is a method of externally opening ports on a firewall by generating a connection attempt on a set of prespecified closed ports.
    
- >`Command Injection`

	>Command injection is an attack in which the goal is execution of arbitrary commands on the host operating 

    >system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell.
    
- >'`ShellShock Vulnerability`
    
	>Shellshock is a security bug causing Bash to execute commands from environment variables unintentionally.

	>Since the environment variables are not sanitized properly by Bash before being executed, the attacker
	>can send commands to the server through HTTP requests and get them executed by the web server operating system. 

	>An attacker can potentially use CGI to send a malformed environment variable to a vulnerable Web server. Because the server uses Bash to interpret the variable, it will also run any malicious command tacked-on to it.
    
---

## Additional Tips
![image](https://github.com/m14r41/CyberSecurity-Interview/assets/95265573/7095e6eb-f95f-4a94-939a-f503d7ef3631)
