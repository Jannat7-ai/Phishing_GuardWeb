# 🛡️ Phishing Guard Pro

A web-based cybersecurity threat intelligence platform that analyzes URLs and detects phishing websites using multiple layered security mechanisms.

---

## 🎯 Features
- **VirusTotal Integration:** Scans URLs using 70+ threat intelligence engines.
- **SSL Certificate Inspection:** Checks the validity, issuer, and expiration state of SSL certificates.
- **WHOIS Domain Age Analysis:** Evaluates domain registration tracking to flag freshly created malicious links.
- **Typosquatting Detection:** Uses the Levenshtein distance algorithm to identify domains spoofing or pretending to be famous tech giants (like Google, PayPal, Facebook).
- **Heuristic Content Check:** Scans URL structures for dangerous semantic keywords (e.g., login, verify, secure).
- **Interactive Multi-Step UI:** Clean dashboard featuring live scanning steps, a dynamic risk gauge, a print report option, and raw JSON data export.

---

## ⚙️ How It Works
1. The user inputs a suspicious target URL.
2. The asynchronous Flask backend processes live verification checks.
3. Points are calculated through algorithmic weights configured inside the risk scoring function.
4. A dynamic verdict banner categorizes threat levels into: **SAFE**, **CAUTION**, **WARNING**, or **CRITICAL**.

---

## 📸 Screenshots

### 🏠 Home Page
![Home Screen](./screenshots/Home.png.jpeg)

---

### ⚡ Scan Page
![Scan](./screenshots/Scan.png.jpeg)

---

### 📊 Result Page
![Scan Result](./screenshots/Result.png.jpeg)

---

## 🛠️ Tech Stack
- **Backend:** Python (Flask, Flask-CORS)
- **Frontend:** Vanilla HTML5, CSS3 (Modern Dark Dashboard layout), JavaScript (Fetch API)
- **Third-Party APIs & Libraries:** VirusTotal v3 API, `python-whois`, `Levenshtein` distance algorithm, `requests`, `ssl`, `socket`

---

## 💻 How to Run This Project

Follow these exact steps to set up and run the threat intelligence application locally:

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/Phishing_GuardWeb.git](https://github.com/YOUR_USERNAME/Phishing_GuardWeb.git)
cd Phishing_GuardWeb


2. Install Required Python Libraries
You need to install the specialized packages that handle network validation and string manipulation. Run this command in your terminal:
Bash
pip install flask flask-cors requests python-whois Levenshtein

3. Start the Flask Server
Execute the local server script from your project directory:

Bash
python App.py
Once the server starts, you will see the confirmation message: Open: http://localhost:5000

4. Open the Web Application
Open your web browser and navigate to:

http://localhost:5000
(Note: The interface includes built-in demo links to easily test safe, medium risk, or critical phishing URL simulations).

📌 Disclaimer
This project is built for educational, research, and cybersecurity awareness evaluation purposes only.

👨‍💻 Developer
Jannat Khatoon