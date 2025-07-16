# 🛡️ MalwareShield Pro

**Deployed at:** 🔗 [https://malwareshieldpro.streamlit.app/](https://malwareshieldpro.streamlit.app/)

---

## 📌 About

**MalwareShield Pro** is a cybersecurity project developed by **[vishux777](https://github.com/vishux777)** as part of the CipherSchools Cybersecurity course.
It is a **Streamlit-powered malware analysis and reporting tool** that scans uploaded files, optionally integrates with **VirusTotal**, and generates reports in both PDF and JSON formats.

---

## 🚀 Features

* 🧪 **Local and VirusTotal Malware Scanning**
* 📄 **Detailed PDF + JSON Report Generation**
* 🎴 **Card-based UI** for clean, modern interaction (Desktop & Mobile friendly)
* ⏱️ **Fast & Efficient** Scanning Pipeline
* 🧰 Built using **Streamlit**, **Python**, **WeasyPrint**, and optional **VirusTotal API**

---

## 📦 Tech Stack

* **Frontend:** Streamlit
* **Backend:** Python
* **PDF Generation:** WeasyPrint
* **API Integration:** VirusTotal (optional)
* **UI/UX:** Responsive card layout using Streamlit's component system

---

## 🔧 Setup Instructions

1. Clone this repository:

   ```bash
   git clone https://github.com/vishux777/CipherSchools_Project.git
   cd CipherSchools_Project
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) Add your VirusTotal API key in the code:

   ```python
   VIRUSTOTAL_API_KEY = "your_api_key_here"
   ```

4. Run the app:

   ```bash
   streamlit run main.py
   ```

---

## 🐞 Known Issues

* VirusTotal scans may take time or rate-limit with free keys.
* PDF report generation may occasionally fail on some systems; ensure WeasyPrint is correctly installed.
* UI optimizations are ongoing for better mobile performance.

---

## 📜 License

This project is open-source under the [MIT License](LICENSE).

---

## ✍️ Author

Made with 💗 by **[@vishux777](https://github.com/vishux777)** for **CipherSchools Cybersecurity Course**. 
