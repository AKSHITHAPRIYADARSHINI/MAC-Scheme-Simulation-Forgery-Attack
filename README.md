**Cryptographic MAC Implementation & Forgery Attack Simulation**

This project demonstrates a vulnerable Message Authentication Code (MAC) construction and shows how an attacker can exploit structural weaknesses to perform chosen-message forgery attacks. The system includes a Flask backend, a simple HTML/JS interface, and an attacker script that interacts with a MAC oracle to perform extension and cut-and-paste attacks.

The goal of this project is to visually and practically illustrate why insecure MAC constructions fail, especially when they do not provide proper message integrity or collision resistance.

📂 Project Structure
/mac_server.py           → Flask backend implementing weak MAC scheme
/mac_attacker.py         → Attacker model performing forgery using MAC oracle
/mac_implementation.html → Frontend UI for interacting with the MAC system

🧩 Overview

The system uses a deliberately weak MAC design to demonstrate how real-world vulnerabilities emerge. The MAC takes the form:

MAC(msg) = H( key || msg )


This simple structure is not secure because hash functions support extension attacks. Using only the MAC of one message, an attacker can generate a valid MAC for a modified message without knowing the key.

Your project simulates this insecurity by allowing:

MAC generation from the server

Attackers to query a MAC oracle

Forged messages to be created and submitted

A visualization of how servers mistakenly accept forged MACs

🏗️ System Architecture
+-------------------+        +------------------+         +----------------------+
|  HTML/JS Frontend | ---->  |     Flask App    | ---->   |    Weak MAC Scheme   |
|   UI for MAC I/O  |        |   /mac-generate  |         |  (key || message)    |
+-------------------+        +------------------+         +----------------------+
         |                               |                           |
         |                               v                           |
         |                 +--------------------------+               |
         |                 |       MAC Oracle         | <-------------+
         |                 | (Attacker queries MACs)  |
         |                 +--------------------------+
         |
         v
+---------------------------+
|     Attacker Script       |
|  Performs Forgery Attack  |
+---------------------------+

🗡️ Chosen-Message Forgery Attack
1️⃣ Attacker queries MAC oracle
Attacker → msg1, msg2, msg3 → Oracle
Oracle → MAC(msg1), MAC(msg2), MAC(msg3)

2️⃣ Attacker uses structure of weak hash-based MAC
original_msg = M
extension     = E

forged_msg = M || padding || E
forged_mac = H(key || M || padding || E)

3️⃣ Server accepts forged message

Because the MAC does not bind message length or prevent hash extension.

🧨 Cut-and-Paste Forgery Visualization
Original: |--A--|--B--|--C--|
MAC:      H(K || A || B || C)

Attacker cuts/pastes:
Forged:   |--A--|--X--|--C--|

Server recomputes:
H(K || A || X || C)

→ Valid under weak MAC design

🚀 How to Run
1. Install Dependencies
pip install flask

2. Start the MAC Server
python mac_server.py

3. Open UI

Open mac_implementation.html in your browser.

4. Run Attacker Script
python mac_attacker.py

🎯 Learning Objectives

Understand why H(key || msg) is insecure

See how chosen-message attacks work in practice

Demonstrate length extension and message forgery techniques

Visualize weaknesses in naive MAC designs

📜 Disclaimer

This project is for educational and academic purposes only and should not be used as a model for real-world MAC implementation.
