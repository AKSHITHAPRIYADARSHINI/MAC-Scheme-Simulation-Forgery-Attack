# **Cryptographic MAC Implementation & Forgery Attack Simulation**

This project demonstrates a vulnerable Message Authentication Code (MAC) construction and shows how attackers can exploit structural weaknesses to perform chosen-message forgery attacks. It includes:

* A Flask backend implementing a weak MAC scheme
* A simple HTML/JS interface
* An attacker script simulating MAC oracle abuse and forgery

The purpose of this project is to **visually and practically illustrate why insecure MAC constructions fail**, especially when they do not enforce proper message integrity or collision resistance.

---

## **📂 Project Structure**

```
mac_server.py           → Flask backend implementing weak MAC scheme
mac_attacker.py         → Attacker script performing forgery using MAC oracle
mac_implementation.html → Frontend UI for interacting with the MAC system
```

---

## **🧩 Overview**

The system uses a **deliberately weak MAC** of the form:

```
MAC(msg) = H(key || msg)
```

This construction is insecure because many hash functions support **length-extension attacks**. An attacker can generate a valid MAC for an altered message **without knowing the secret key**, using only the MAC of the original message.

This project simulates the attack by enabling:

* MAC generation through the server
* Attacker MAC oracle queries
* Forged message creation and testing
* Visualization of insecure MAC acceptance

---

## **🏗️ System Architecture**

```
+-------------------+      +------------------+      +----------------------+
| HTML/JS Frontend  | ---> |   Flask App      | ---> |   Weak MAC Scheme    |
| UI for MAC I/O    |      |  /mac-generate   |      |   (key || message)   |
+-------------------+      +------------------+      +----------------------+
           |                        |                        |
           v                        |                        |
+--------------------------+        |                        |
|        MAC Oracle        | <------+                        |
| (Attacker queries MACs) |                                 |
+--------------------------+                                 |
           v                                                  |
+---------------------------+                                 |
|     Attacker Script      |                                 |
|  Performs Forgery Attack | --------------------------------+
+---------------------------+   
```

---

## **🗡️ Chosen-Message Forgery Attack**

### **1️⃣ Attacker queries the MAC oracle**

```
Attacker → msg1, msg2, msg3 → Oracle
Oracle   → MAC(msg1), MAC(msg2), MAC(msg3)
```

### **2️⃣ Attacker performs length‑extension**

```
original_msg = M
extension    = E

forged_msg = M || padding || E
forged_mac = H(key || M || padding || E)
```

### **3️⃣ Server accepts the forged message**

because the MAC does not:

* Bind message length
* Prevent hash extension
* Protect message structure

---

## **🧨 Cut‑and‑Paste Forgery Visualization**

**Original message:**

```
|--A--|--B--|--C--|
MAC = H(K || A || B || C)
```

**Attacker creates:**

```
|--A--|--X--|--C--|
```

**Server recomputes:**

```
H(K || A || X || C)
```

✔️ Still valid under the weak MAC scheme.

---

## **🚀 How to Run**

### **1. Install Dependencies**

```
pip install flask
```

### **2. Start MAC Server**

```
python mac_server.py
```

### **3. Open Frontend UI**

Open the file:

```
mac_implementation.html
```

### **4. Run Attacker Script**

```
python mac_attacker.py
```

---

## **🎯 Learning Objectives**

* Understand why **H(key || msg)** is insecure
* Observe how **chosen‑message attacks** work
* Demonstrate **length‑extension** and **cut‑and‑paste forgery**
* Visualize the weaknesses in naive MAC designs

---

## **📜 Disclaimer**

This project is intended for **educational and academic purposes only**.
It should **not** be used as a real‑world MAC implementation model.
