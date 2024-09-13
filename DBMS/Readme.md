# Database Management System (DBMS): Top 20 Interview Questions

1. **What is a Database Management System (DBMS)?**

   **Answer:** A DBMS is software that facilitates the creation, management, and manipulation of databases. It provides a systematic way to store, retrieve, and manage data, ensuring data integrity, security, and efficient access.

2. **What are the main types of DBMS?**

   **Answer:** The main types include:
   - **Relational DBMS (RDBMS):** Uses tables to store data (e.g., MySQL, PostgreSQL, Oracle).
   - **NoSQL DBMS:** Non-relational databases designed for specific use cases (e.g., MongoDB, Cassandra).
   - **Hierarchical DBMS:** Uses a tree-like structure (e.g., IBM's Information Management System (IMS)).
   - **Network DBMS:** Uses a network structure to represent relationships (e.g., Integrated Data Store (IDS)).

3. **Explain the concept of normalization.**

   **Answer:** Normalization is the process of organizing data within a database to reduce redundancy and improve data integrity. It involves dividing large tables into smaller ones and defining relationships between them. Common normal forms include 1NF, 2NF, 3NF, and BCNF.

4. **What is the difference between SQL and NoSQL databases?**

   **Answer:** SQL databases are relational and use structured query language (SQL) for defining and manipulating data. They are suited for applications with complex queries and transactions. NoSQL databases are non-relational and are designed for unstructured or semi-structured data, offering scalability and flexibility for large-scale applications.

5. **What is a primary key, and why is it important?**

   **Answer:** A primary key is a unique identifier for each record in a table. It ensures that each record can be uniquely identified, maintains data integrity, and enforces the entity integrity constraint by preventing duplicate records.

6. **What is an index, and how does it improve database performance?**

   **Answer:** An index is a data structure that improves the speed of data retrieval operations on a database table. By creating an index on one or more columns, the database can quickly locate rows based on the indexed columns, reducing query execution time.

   **Tool/Command:**
   - For creating an index in SQL: `CREATE INDEX index_name ON table_name(column_name);`

7. **Explain the concept of ACID properties in databases.**

   **Answer:** ACID properties ensure reliable transaction processing:
   - **Atomicity:** Ensures that a transaction is all-or-nothing.
   - **Consistency:** Ensures that a transaction brings the database from one valid state to another.
   - **Isolation:** Ensures that transactions occur independently of one another.
   - **Durability:** Ensures that once a transaction is committed, it remains permanent.

8. **What is a foreign key, and how does it enforce referential integrity?**

   **Answer:** A foreign key is a column or a set of columns in one table that refers to the primary key in another table. It enforces referential integrity by ensuring that the value in the foreign key column matches a value in the referenced primary key column, thus maintaining valid relationships between tables.

9. **What is a database schema, and what are its components?**

   **Answer:** A database schema defines the structure of a database, including the tables, columns, data types, constraints, and relationships. Components include:
   - **Tables:** Structures that store data.
   - **Columns:** Attributes of the tables.
   - **Constraints:** Rules applied to data (e.g., primary key, foreign key).
   - **Relationships:** Links between tables.

10. **How do you perform a database backup and restore?**

    **Answer:** Database backup involves creating a copy of the database to prevent data loss. Restore is the process of recovering data from a backup. 

    **Tool/Command:**
    - For MySQL: 
      - Backup: `mysqldump -u username -p database_name > backup.sql`
      - Restore: `mysql -u username -p database_name < backup.sql`
    - For PostgreSQL: 
      - Backup: `pg_dump database_name > backup.sql`
      - Restore: `psql database_name < backup.sql`

11. **What is SQL injection, and how can you prevent it?**

    **Answer:** SQL injection is a type of attack where malicious SQL code is inserted into a query, potentially compromising the database. Prevent it by:
    - **Using Parameterized Queries:** Ensure queries are built with parameters rather than direct user input.
    - **Input Validation:** Validate and sanitize user inputs.
    - **Stored Procedures:** Use stored procedures to encapsulate SQL code.

12. **What is a transaction, and how is it managed in a database?**

    **Answer:** A transaction is a sequence of operations performed as a single unit of work. Transactions are managed using:
    - **Begin Transaction:** Starts the transaction.
    - **Commit:** Saves changes made during the transaction.
    - **Rollback:** Reverts changes if an error occurs.

    **Tool/Command:**
    - For SQL: 
      - Begin Transaction: `BEGIN;`
      - Commit: `COMMIT;`
      - Rollback: `ROLLBACK;`

13. **What are stored procedures, and how do they differ from functions?**

    **Answer:** Stored procedures are precompiled collections of SQL statements that perform a specific task. Functions are similar but are designed to return a single value and can be used within SQL statements. Stored procedures can perform operations without returning values, whereas functions return values and can be used in queries.

14. **How do you handle data replication and synchronization in a database?**

    **Answer:** Data replication involves copying data from one database to another. Synchronization ensures that changes are reflected across all replicas. Methods include:
    - **Master-Slave Replication:** One master node sends data to one or more slave nodes.
    - **Master-Master Replication:** Multiple nodes can act as masters and replicate data to each other.

    **Tool/Command:**
    - For MySQL: `CHANGE MASTER TO MASTER_LOG_FILE='mysql-bin.000001', MASTER_LOG_POS=4;`

15. **What are database constraints, and what types are commonly used?**

    **Answer:** Database constraints enforce rules on data to maintain integrity. Common types include:
    - **Primary Key:** Ensures uniqueness of records.
    - **Foreign Key:** Enforces referential integrity.
    - **Unique:** Ensures all values in a column are unique.
    - **Check:** Validates data against a specified condition.
    - **Not Null:** Ensures that a column cannot have NULL values.

16. **What is denormalization, and why might it be used?**

    **Answer:** Denormalization is the process of introducing redundancy into a database by merging tables or adding redundant data to improve read performance. It is used to optimize query performance and reduce the complexity of complex queries.

17. **How do you optimize database performance?**

    **Answer:** Optimize database performance by:
    - **Indexing:** Creating indexes to speed up queries.
    - **Query Optimization:** Writing efficient SQL queries.
    - **Database Design:** Normalizing or denormalizing tables appropriately.
    - **Caching:** Using caching mechanisms to reduce database load.
    - **Monitoring:** Regularly monitoring and tuning database performance.

18. **What is a database view, and how is it used?**

    **Answer:** A database view is a virtual table created by a query on one or more tables. It does not store data itself but provides a way to simplify complex queries and present data in a specific format.

    **Tool/Command:**
    - For SQL: `CREATE VIEW view_name AS SELECT column1, column2 FROM table_name WHERE condition;`

19. **What are the differences between OLTP and OLAP databases?**

    **Answer:**
    - **OLTP (Online Transaction Processing):** Optimized for transaction-oriented tasks, such as order processing and real-time data entry. Focuses on fast query processing and data integrity.
    - **OLAP (Online Analytical Processing):** Optimized for complex queries and data analysis, often used for reporting and data mining. Focuses on read-heavy operations and aggregate data processing.

20. **How do you ensure data security in a database?**

    **Answer:** Ensure data security by:
    - **Access Control:** Implementing role-based access controls and permissions.
    - **Encryption:** Encrypting data at rest and in transit.
    - **Auditing:** Monitoring and logging database activities.
    - **Backup and Recovery:** Regularly backing up data and testing recovery procedures.
    - **Patching:** Keeping database software up to date with security patches.

    **Tool/Command:**
    - For MySQL Encryption: `ALTER TABLE table_name MODIFY column_name VARBINARY(255) ENCRYPTED;`

