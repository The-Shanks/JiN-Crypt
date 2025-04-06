# 🔐 JiN Vault



**JiN** (*Just in Notes*) is a lightweight, offline password and document keeper built for privacy-conscious users. It securely stores sensitive information in a local file with custom encryption using a unique passkey file.
![Screenshot at 2024-12-22 21-12-04](https://github.com/user-attachments/assets/0bb18ee3-8d33-4a49-8c82-ffa16fc72a77)
---

## 🚀 Features

- 🔑 Secure storage for passwords & notes
- 🧊 `passkey.jiren` file for authentication & encryption
- 📂 No internet or cloud — fully offline
- 🖥️ CLI-based interface
- ⚡ Lightweight and fast

---

## 🔐 What is `passkey.jiren`?

`passkey.jiren` is your **master key file**. It:
- Stores your encryption key (in hashed/encrypted form)
- Is **required** to decrypt any saved content
- Is **unique** to each instance of JiN

> 🛑 **Important:** If you delete or lose the `passkey.jiren` file, you will **not** be able to access your saved passwords or notes. Make a secure backup if needed.

---

## 🧠 How It Works

1. **First Run:** JiN generates a `passkey.jiren` file to encrypt future entries.
2. **Add Entry:** Securely store a password or note using the passkey.
3. **View Entries:** Decrypts and displays your stored entries (only if the passkey is valid).
4. **Delete Entry:** Remove stored data securely.
5. **Exit:** All data stays local in encrypted `.txt` format.

---

## 📦 Getting Started

1. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/JiN-Crypt.git
   cd JiN-Crypt
   python3 jin.py

