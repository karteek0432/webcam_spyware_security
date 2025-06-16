## 🛡️ Webcam Spyware Security System

A powerful and user-friendly Python GUI application that protects your webcam from unauthorized access and spyware using **Face Recognition**, **Email OTP Authentication**, **System Registry Control**, and **Scheduled Privacy Mode**.

![Python](https://img.shields.io/badge/Python-3.10-blue)
![CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter-orange)

---

## 📸 Screenshots

![Screenshot (1143)](https://github.com/user-attachments/assets/2bc45915-1a45-4e2f-9e3c-ddfb74b6baec)
![Screenshot (1144)](https://github.com/user-attachments/assets/309c8139-6bbe-4700-b08d-8ac0d820d048)
![Screenshot (1145)](https://github.com/user-attachments/assets/660ac4cd-7d99-459d-bdc9-bb39d2b2ddf0)
![Screenshot (1148)](https://github.com/user-attachments/assets/ee4babac-fd56-4de0-8767-f32c458edbfa)
![Screenshot (1149)](https://github.com/user-attachments/assets/804cd1dd-477c-4a6a-ae46-f067505c8ebb)
![Screenshot (1150)](https://github.com/user-attachments/assets/6d7a6bbb-8090-4f66-bac4-306f6ae05596)
![Screenshot (1151)](https://github.com/user-attachments/assets/e61ffc6b-f817-4d3a-9685-f16ef7df8c62)
![Screenshot (1152)](https://github.com/user-attachments/assets/deca862b-ce9c-408a-aeb8-755a60cfec53)
![Screenshot (1154)](https://github.com/user-attachments/assets/ae814186-be49-4a2f-8545-b134994b269d)
![Screenshot (1156)](https://github.com/user-attachments/assets/ec3edc98-4559-461c-8f2f-19ee322c60bb)




---

## 📌 Features

- ✅ **Enable/Disable Webcam** at the system level using the Windows Registry
- 🔐 **Dual Authentication** to control webcam access:
  - Password sent via Email
  - Face Recognition (if available)
- 🧠 **Intruder Detection**: Automatically records 10-second video and sends email if unauthorized access is detected
- 📅 **Scheduled Privacy Mode**: Automatically disables/enables the camera based on user-defined time slots
- 📜 **Base64-Encoded Logs** of all actions and intrusions
- 📷 **Face Registration** with OTP verification and multi-sample recognition
- 📁 Project Info Viewer with developer and company details

---

## 🎓 Internship Information

This project was developed as part of a **Cybersecurity Internship** at **Supraja Technologies**  
**Internship Duration**: 29-May-2025 to 10-June-2025  
It demonstrates implementation of physical-level protection to **secure webcams against spyware and hacking** using AI and system registry control.

---

## ⚙️ System Requirements

- ✅ **Tested and works best on Python 3.10**
- 💻 Windows 10/11 required (due to registry access for webcam control)
- 📦 Required Python libraries:
  ```bash
  pip install customtkinter pillow face_recognition opencv-python numpy schedule
  ```

---

## 🚀 How to Run

**⚙️ Setup for Email OTP and Alerts**

To enable email-based OTP verification and intruder alerts, you must edit the Python file with your own Gmail and App Password.

**📌 Follow these steps:**

Open the file webcam_spyware_security.py

**Find and replace the following lines with your credentials:**
<br>
SENDER_EMAIL = "your_email@gmail.com"<br>
APP_PASSWORD = "your_app_password"<br>
RECEIVER_EMAIL = "receiver_email@gmail.com"

**⚠️ Important:**
<br>
-Use a Gmail address with 2-Step Verification enabled<br>
-Generate a 16-character App Password from your Google Account<br>
-Do not share this file publicly after editing
### Run using Python:

```bash
pip install -r requirements.txt
```
```bash
python webcam_spyware_security.py
```
---

## ⚠️ Important Notes

> 🛑 **You must run the program with administrative privileges** to allow registry-level changes to the webcam settings.

- For `.py` file: Open command prompt as **Administrator**
- If you face any errors running the Python script, you can convert it into a .exe file using the following command:
```bash
python -m PyInstaller --onefile --windowed --icon=camera.ico ^
  --add-data "camera.png;." ^
  --add-data "suprajatechnologieslogo.jpeg;." ^
  --add-data "face_recognition_models;face_recognition_models" ^
  --hidden-import=cv2 ^
  --hidden-import=numpy ^
  --hidden-import=dlib ^
  --hidden-import=face_recognition.api ^
  --hidden-import=face_recognition.face_recognition_cli ^
  --hidden-import=PIL.JpegImagePlugin ^
  --hidden-import=PIL.PngImagePlugin ^
  --hidden-import=PIL._tkinter_finder ^
  webcam_spyware_security.py
```
- After building, go to the dist/ folder and Right-click → Run the EXE as Administrator

---

## 🧠 Security Highlights

| Feature                  | Description |
|--------------------------|-------------|
| **Face Recognition**     | Verifies the authorized user via camera |
| **Email Password**       | Sends verification code to email for actions |
| **OTP for Face Register**| OTP verification before storing face data |
| **Intruder Recording**   | 10-sec video + Email alert for failed attempts |
| **Logs**                 | Base64 encoded security logs with timestamps |

---

