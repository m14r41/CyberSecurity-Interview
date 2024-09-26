
# Active Directory (AD) - Basics Understanding

#### Common Terms:
- **Domain**: A logical group of network objects (users, computers, devices) that share a common directory database.
- **Forest**: A collection of one or more domains that share a common schema and configuration.
- **Tree**: A hierarchy of one or more domains that are connected in a contiguous namespace.
- **Organizational Unit (OU)**: A container within a domain used to organize users, groups, and computers. OUs can be nested.
- **Group Policy**: A feature that allows administrators to implement specific configurations for users and computers within the domain.
- **Schema**: Defines the objects and attributes that the directory service can contain.
- **Global Catalog**: A distributed data repository that contains a searchable, partial representation of every object in every domain in a forest.

#### Key Components:
- **Active Directory Domain Services (AD DS)**: The core service that provides the directory and authentication services.
- **Active Directory Lightweight Directory Services (AD LDS)**: A lighter version of AD DS, used for directory-enabled applications.
- **Active Directory Federation Services (AD FS)**: Provides single sign-on and identity federation for users accessing applications across different organizations.

----

# Domain Controller (DC)

#### Common Terms:
- **Primary Domain Controller (PDC)**: The main domain controller responsible for processing authentication requests and managing changes in a domain.
- **Backup Domain Controller (BDC)**: An older term (from NT4 days) for a domain controller that provides backup and redundancy for the PDC.
- **Replication**: The process of copying changes made on one domain controller to others to ensure consistency.
- **Trust Relationship**: A connection between two domains that allows users from one domain to access resources in another.

#### Key Components:
- **Active Directory Database**: The database file (NTDS.dit) that stores the directory data and objects.
- **DNS Integration**: Active Directory relies on DNS for domain controller location and service discovery.
- **Authentication Protocols**: Protocols like Kerberos and NTLM that handle authentication requests.

### Summary
- **Active Directory** is the service that organizes and manages network resources.
- **Domain Controllers** are servers that implement AD services, handling user authentication and managing directory data. 


---

## Summarize the key concepts and components of Active Directory (AD) and Domain Controllers (DC):

| **Concept**               | **Active Directory (AD)**                                   | **Domain Controller (DC)**                      |
|---------------------------|------------------------------------------------------------|------------------------------------------------|
| **Definition**            | Directory service for managing network resources           | Server that runs AD Domain Services             |
| **Main Functionality**    | Manages permissions and access across the network          | Authenticates users and computers               |
| **Components**            | - AD DS (Domain Services)                                 | - Hosts the AD DS database (NTDS.dit)          |
|                           | - AD LDS (Lightweight Directory Services)                  | - Processes authentication requests             |
|                           | - AD FS (Federation Services)                              | - Handles replication between DCs               |
| **Common Terms**          | - Domain                                                  | - Primary Domain Controller (PDC)              |
|                           | - Forest                                                  | - Backup Domain Controller (BDC)                |
|                           | - Tree                                                    | - Trust Relationship                            |
|                           | - Organizational Unit (OU)                                | - Replication                                   |
|                           | - Group Policy                                            | - Authentication Protocols (Kerberos, NTLM)    |
|                           | - Schema                                                  |                                                |
|                           | - Global Catalog                                          |                                                |

- **Active Directory** is the framework for managing network resources.
- **Domain Controllers** are the servers that implement the AD services, facilitating user authentication and data management.

