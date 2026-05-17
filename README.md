# 🛡️ PhishGuard

An AI-powered phishing URL detection platform that combines Machine Learning, Cyber Threat Intelligence, and Browser Protection to identify malicious URLs in real time.Phishing attacks remain one of the most common cybersecurity threats.  
PhishGuard aims to provide a lightweight, intelligent, and real-time detection system that combines ML prediction with live threat intelligence.

## 🚀 Features

- Real-time phishing detection
- ML-based URL classification
- Chrome extension support
- Threat intelligence integration
- WHOIS & DNS analysis
- Interactive React dashboard
- IOC report generation

## 🧠 Tech Stack

Frontend: React, Vite, TailwindCSS  
Backend: FastAPI, SQLAlchemy  
ML: XGBoost, Scikit-learn  
Database: PostgreSQL  
Extension: Chrome Extensions API

## 🚀 How to Run PhishGuard

- Clone or download the repository and open the project folder in VS Code.
- Open a new terminal in VS Code and run:

```bash
npm install
Start the frontend using:
```bash
npm run dev
Open the generated localhost link (usually http://localhost:5173/) in the browser.
Build the Chrome Extension using:
```bash
npm run build:ext
This will generate a dist-extension/ folder containing the extension files.
Open Google Chrome and go to:
```bash
chrome://extensions/
Enable Developer Mode from the top-right corner.
Click Load unpacked.
Select the generated dist-extension/ folder (NOT the main project folder).
The PhishGuard extension is now installed and ready to use.
Open any website and click the extension icon to scan URLs for phishing detection.
Whenever changes are made to the extension/frontend code, rerun:
```bash
npm run build:ext
Then refresh the extension from the Chrome Extensions page to apply updates.
