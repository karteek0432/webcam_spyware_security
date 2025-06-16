import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import subprocess
import random
import smtplib
import cv2
import os
import time
import threading
import webbrowser
from email.message import EmailMessage
import winreg
from datetime import datetime, time as dt_time
import string
import secrets
import sys
import json
import schedule
import tempfile
import base64
import ctypes
import numpy as np
import face_recognition
from customtkinter import ThemeManager

# Helper function to center any window
def center_window(window, width, height):
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")

# Face recognition availability
try:
    import face_recognition
    import numpy as np
    FACE_RECOGNITION_AVAILABLE = True
except ImportError as e:
    FACE_RECOGNITION_AVAILABLE = False

# Configuration Constants
SENDER_EMAIL=your_email@gmail.com
APP_PASSWORD=your_gmail_app_password
RECEIVER_EMAIL=your_email@gmail.com
WEBCAM_REG_KEY = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam"
LOG_FILE = "security_logs.txt"
SCHEDULE_FILE = "privacy_schedules.json"
CONFIG_FILE = "security_config.json"

def resource_path(relative_path):
    """Ensures resource files work both in script and .exe."""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert") if hasattr(self.widget, "bbox") else (0, 0, 0, 0)
        x = x + self.widget.winfo_rootx() + 40
        y = y + self.widget.winfo_rooty() + 20
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify="left",
                         background="#333", foreground="white",
                         relief="solid", borderwidth=1,
                         font=("tahoma", "10", "normal"))
        label.pack(ipadx=6, ipady=2)

    def hide_tip(self, event=None):
        tw = self.tip_window
        self.tip_window = None
        if tw:
            tw.destroy()

def generate_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_otp(length=6):
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def log_action(action):
    log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {action}"
    encoded_entry = base64.b64encode(log_entry.encode('utf-8')).decode('utf-8')
    with open(LOG_FILE, "a") as f:
        f.write(encoded_entry + "\n")

def send_mail(subject, content, attachment_path=None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg.set_content(content)
    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="video", subtype="mp4", filename=os.path.basename(attachment_path))
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        log_action(f"Mail error: {str(e)}")
        return False

def set_camera_permission(enable):
    access = "Allow" if enable else "Deny"
    try:
        keys = [
            r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam",
            r"SOFTWARE\\Policies\\Microsoft\\Windows\\Camera"
        ]
        for key_path in keys:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "Value", 0, winreg.REG_SZ, access)
            except FileNotFoundError:
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    winreg.SetValueEx(key, "Value", 0, winreg.REG_SZ, access)
        try:
            subprocess.run(['gpupdate', '/force'], capture_output=True, timeout=5)
        except:
            pass
        log_action(f"Camera {'enabled' if enable else 'disabled'} system-wide")
        return True
    except PermissionError:
        messagebox.showerror("Permission Denied", "Run as Administrator to change camera settings.")
        return False
    except Exception as e:
        log_action(f"Registry error: {str(e)}")
        return False

def record_intruder():
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter("intruder.mp4", fourcc, 20.0, (640, 480))
        start_time = time.time()
        while time.time() - start_time < 10:
            ret, frame = cap.read()
            if ret:
                out.write(frame)
        cap.release()
        out.release()
        send_mail("INTRUDER ALERT!", "Unauthorized access detected!", "intruder.mp4")
    except Exception as e:
        log_action(f"Recording error: {str(e)}")

class WebcamSecurityCore:
    def __init__(self):
        self.running = True
        self.monitoring_active = False
        self.privacy_mode = False
        self.scheduled_privacy_active = False
        self.schedules = []
        self.face_users = []  # List of lists: [[face_encodings], ...]
        self.authentication_required = True
        self.load_schedules()
        self.load_face_data()
        self.start_background_threads()
        log_action("Security system initialized - authentication REQUIRED")

    def load_face_data(self):
        face_file = resource_path("authorized_faces.npy")
        if os.path.exists(face_file) and FACE_RECOGNITION_AVAILABLE:
            try:
                self.face_users = np.load(face_file, allow_pickle=True).tolist()
                log_action(f"Loaded {len(self.face_users)} authorized users")
            except Exception as e:
                log_action(f"Error loading face data: {e}")
                self.face_users = []

    def save_face_data(self):
        if self.face_users and FACE_RECOGNITION_AVAILABLE:
            try:
                face_file = resource_path("authorized_faces.npy")
                np.save(face_file, np.array(self.face_users, dtype=object))
                log_action("Face data saved successfully")
            except Exception as e:
                log_action(f"Error saving face data: {e}")

    def start_background_threads(self):
        threading.Thread(target=self.privacy_scheduler_loop, daemon=True).start()

    def privacy_scheduler_loop(self):
        while self.running:
            try:
                current_time = datetime.now().strftime("%H:%M")
                should_be_private = self.check_privacy_schedule(current_time)
                if should_be_private and not self.scheduled_privacy_active:
                    self.activate_scheduled_privacy()
                elif not should_be_private and self.scheduled_privacy_active:
                    self.deactivate_scheduled_privacy()
            except Exception as e:
                log_action(f"Privacy scheduler error: {e}")
            time.sleep(30)

    def check_privacy_schedule(self, current_time):
        for start_time, end_time in self.schedules:
            if self.time_in_range(start_time, end_time, current_time):
                return True
        return False

    def time_in_range(self, start, end, current):
        try:
            start_dt = datetime.strptime(start, "%H:%M")
            end_dt = datetime.strptime(end, "%H:%M")
            current_dt = datetime.strptime(current, "%H:%M")
            start_min = start_dt.hour * 60 + start_dt.minute
            end_min = end_dt.hour * 60 + end_dt.minute
            current_min = current_dt.hour * 60 + current_dt.minute
            if start_min <= end_min:
                return start_min <= current_min <= end_min
            else:
                return current_min >= start_min or current_min <= end_min
        except Exception as e:
            log_action(f"Time comparison error: {e}")
            return False

    def activate_scheduled_privacy(self):
        self.scheduled_privacy_active = True
        self.privacy_mode = True
        set_camera_permission(False)
        log_action("Privacy mode activated by schedule - system-wide block")

    def deactivate_scheduled_privacy(self):
        if not self.check_privacy_schedule(datetime.now().strftime("%H:%M")):
            self.scheduled_privacy_active = False
            set_camera_permission(True)
            log_action("Privacy mode deactivated by schedule")

    def init_webcam(self):
        try:
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                log_action("Failed to initialize webcam")
                return False
            cap.release()
            return True
        except Exception as e:
            log_action(f"Webcam initialization error: {e}")
            return False

    def register_new_face(self):
        if not FACE_RECOGNITION_AVAILABLE:
            return False, "Face recognition not available"
        try:
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                return False, "Cannot access camera"
            messagebox.showinfo("Face Registration", "Look at the camera. Capturing in 3 seconds...")
            time.sleep(3)
            face_encodings = []
            for i in range(5):
                ret, frame = cap.read()
                if ret:
                    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    face_locations = face_recognition.face_locations(rgb_frame)
                    if len(face_locations) != 1:
                        cap.release()
                        return False, f"Require one face in frame (found {len(face_locations)})"
                    encoding = face_recognition.face_encodings(rgb_frame, face_locations)[0]
                    face_encodings.append(encoding)
                else:
                    cap.release()
                    return False, f"Failed to capture frame {i+1}"
                time.sleep(0.5)
            cap.release()
            if face_encodings:
                self.face_users.append(face_encodings)
                self.save_face_data()
                log_action(f"Registered new user with {len(face_encodings)} samples")
                return True, "Face registered successfully"
            else:
                return False, "Failed to capture face data"
        except Exception as e:
            return False, f"Registration error: {str(e)}"

    def verify_face_authentication(self):
        if not FACE_RECOGNITION_AVAILABLE or not self.face_users:
            return False, "Face recognition not available or no faces registered"
        try:
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                return False, "Cannot access camera"
            start_time = time.time()
            authenticated = False
            while time.time() - start_time < 10:
                ret, frame = cap.read()
                if ret:
                    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    face_locations = face_recognition.face_locations(rgb_frame)
                    if face_locations:
                        face_encoding = face_recognition.face_encodings(rgb_frame, face_locations)[0]
                        for user_encodings in self.face_users:
                            matches = face_recognition.compare_faces(user_encodings, face_encoding, tolerance=0.6)
                            if any(matches):
                                authenticated = True
                                break
                    if authenticated:
                        break
            cap.release()
            if authenticated:
                log_action("Face authentication successful")
                return True, "Face verified successfully"
            else:
                log_action("Face authentication failed")
                threading.Thread(target=record_intruder, daemon=True).start()
                return False, "Face not recognized"
        except Exception as e:
            return False, f"Authentication error: {str(e)}"

    def load_schedules(self):
        if os.path.exists(SCHEDULE_FILE):
            try:
                with open(SCHEDULE_FILE, "r") as f:
                    self.schedules = json.load(f)
                log_action(f"Loaded {len(self.schedules)} privacy schedules")
            except Exception as e:
                self.schedules = []
                log_action(f"Error loading schedules: {e}")
        else:
            self.schedules = []

    def save_schedules(self):
        try:
            with open(SCHEDULE_FILE, "w") as f:
                json.dump(self.schedules, f)
            log_action("Privacy schedules saved")
            threading.Thread(target=self.force_schedule_check, daemon=True).start()
        except Exception as e:
            log_action(f"Error saving schedules: {e}")

    def force_schedule_check(self):
        time.sleep(0.1)
        current_time = datetime.now().strftime("%H:%M")
        should_be_private = self.check_privacy_schedule(current_time)
        if should_be_private and not self.scheduled_privacy_active:
            self.activate_scheduled_privacy()
        elif not should_be_private and self.scheduled_privacy_active:
            self.deactivate_scheduled_privacy()

    def add_schedule(self, start_time, end_time):
        self.schedules.append((start_time, end_time))
        self.save_schedules()
        log_action(f"Added schedule: {start_time}-{end_time}")

    def stop(self):
        self.running = False
        self.monitoring_active = False

class SecurityDashboard(ctk.CTk):
    def __init__(self, security_system):
        super().__init__()
        self.security = security_system
        self.title("Webcam Spyware Security - Supraja Technologies")
        self.geometry("1200x800")
        self.configure_styles()
        self.create_widgets()
        self.after(1000, self.update_status)

    def configure_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('default')
        bg_color = ThemeManager.theme["CTkFrame"]["fg_color"][1]
        text_color = ThemeManager.theme["CTkLabel"]["text_color"][1]
        self.style.configure("Treeview", background=bg_color, foreground=text_color, fieldbackground=bg_color)

    def create_widgets(self):
        # Project Info Button
        project_info_btn = ctk.CTkButton(
            self, text="Project Info", command=self.show_project_info, fg_color="#393E46"
        )
        project_info_btn.pack(pady=(10, 5), anchor="nw")
        ToolTip(project_info_btn, "Show project details and credits")

        header_frame = ctk.CTkFrame(self)
        header_frame.pack(fill="x", pady=10)

        try:
            img_path = resource_path("camera.png")
            if os.path.exists(img_path):
                img = Image.open(img_path).resize((100, 100))
                self.logo_img = ImageTk.PhotoImage(img)
                ctk.CTkLabel(header_frame, image=self.logo_img, text="").pack(side="left", padx=10)
        except Exception:
            pass

        header_text = "Webcam Spyware Security System"
       

        ctk.CTkLabel(header_frame, text=header_text, font=ctk.CTkFont(size=18, weight="bold")).pack(side="left", padx=10)

        status_frame = ctk.CTkFrame(self)
        status_frame.pack(fill="x", pady=5)
        self.camera_status_label = ctk.CTkLabel(status_frame, text="Webcam Status: Disable", text_color="red", font=ctk.CTkFont(size=14, weight="bold"))
        self.camera_status_label.pack(side="left", padx=10)
        ToolTip(self.camera_status_label, "Displays real-time webcam status")

        control_frame = ctk.CTkFrame(self)
        control_frame.pack(fill="x", pady=10)
        buttons = [
            ("Enable Camera", "green", self.enable_camera),
            ("Disable Camera", "red", self.disable_camera),
            ("Register Face", "#4B0082", self.register_face),
            ("View Logs", "#1E90FF", self.view_logs)
        ]
        for text, color, command in buttons:
            btn = ctk.CTkButton(control_frame, text=text, fg_color=color, command=command)
            btn.pack(side="left", padx=5)
            ToolTip(btn, {
                "Enable Camera": "Enable webcam at the system level (requires authentication)",
                "Disable Camera": "Disable webcam at the system level (requires authentication)",
                "Register Face": "Register your face for authentication (requires OTP)",
                "View Logs": "View security and access logs"
            }[text])

        schedule_frame = ctk.CTkFrame(self)
        schedule_frame.pack(fill="both", expand=True, pady=10)
        ctk.CTkLabel(schedule_frame, text="Privacy Schedules (Auto-blocks webcam during specified times)", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        schedule_tree_frame = tk.Frame(schedule_frame)
        schedule_tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.schedule_tree = ttk.Treeview(schedule_tree_frame, columns=("Start", "End", "Status"), show="headings", height=6)
        self.schedule_tree.heading("Start", text="Start Time")
        self.schedule_tree.heading("End", text="End Time")
        self.schedule_tree.heading("Status", text="Status")
        self.schedule_tree.pack(side="left", fill="both", expand=True)
        schedule_scrollbar = ttk.Scrollbar(schedule_tree_frame, orient="vertical", command=self.schedule_tree.yview)
        schedule_scrollbar.pack(side="right", fill="y")
        self.schedule_tree.configure(yscrollcommand=schedule_scrollbar.set)
        self.schedule_tree.bind('<ButtonRelease-1>', self.on_schedule_click)
        self.schedule_tree.bind('<<TreeviewSelect>>', self.on_schedule_select)

        btn_frame = ctk.CTkFrame(schedule_frame)
        btn_frame.pack(fill="x", padx=5, pady=5)
        ctk.CTkButton(btn_frame, text="Add Schedule", command=self.add_schedule_dialog, fg_color="green").pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Edit Selected", command=self.edit_selected_schedule, fg_color="orange").pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Delete Selected", command=self.delete_selected_schedule, fg_color="red").pack(side="left", padx=5)

        self.update_schedule_list()

    def on_schedule_click(self, event):
        item = self.schedule_tree.identify_row(event.y)
        if item:
            self.schedule_tree.selection_set(item)
            self.schedule_tree.focus(item)

    def on_schedule_select(self, event):
        pass

    def update_status(self):
        self.camera_status_label.configure(
            text="Webcam Status: Enable" if self.security.monitoring_active else "Webcam Status: Disable",
            text_color="green" if self.security.monitoring_active else "red"
        )
        self.after(1000, self.update_status)

    def authenticate(self, action):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Authentication Required")
        dialog.geometry("350x200")
        center_window(dialog, 350, 200)
        dialog.lift()
        dialog.focus_force()
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="🔐 Authentication Required", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        ctk.CTkLabel(dialog, text="Choose authentication method:").pack(pady=10)
        ctk.CTkButton(dialog, text="✉️ Email/Password", command=lambda: [dialog.destroy(), self.password_authentication(action)], width=200).pack(pady=5)
        if FACE_RECOGNITION_AVAILABLE and self.security.face_users:
            ctk.CTkButton(dialog, text="👤 Face Recognition", command=lambda: [dialog.destroy(), self.face_authentication(action)], width=200).pack(pady=5)

    def password_authentication(self, action):
        temp_password = generate_password()
        if send_mail("Security Password", f"Your verification code: {temp_password}"):
            dialog = ctk.CTkToplevel(self)
            dialog.geometry("350x180")
            dialog.title("Enter Password")
            center_window(dialog, 350, 180)
            dialog.lift()
            dialog.focus_force()
            dialog.grab_set()
            ctk.CTkLabel(dialog, text="Check your email for password:", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
            entry = ctk.CTkEntry(dialog, show="*", width=250)
            entry.pack(pady=10)
            def verify():
                if entry.get() == temp_password:
                    dialog.destroy()
                    self.handle_camera_action(action)
                else:
                    messagebox.showwarning("Invalid Password", "Recording intruder activity...")
                    threading.Thread(target=record_intruder).start()
                    dialog.destroy()
            ctk.CTkButton(dialog, text="Verify", command=verify, width=120).pack(pady=10)

    def face_authentication(self, action):
        success, message = self.security.verify_face_authentication()
        if success:
            self.handle_camera_action(action)
        else:
            messagebox.showwarning("Authentication Failed", message)

    def handle_camera_action(self, action):
        if action == "enable":
            if set_camera_permission(True):
                self.security.monitoring_active = True
                self.security.init_webcam()
                messagebox.showinfo("Success", "Camera enabled")
                self.update_status()
        else:
            if set_camera_permission(False):
                self.security.monitoring_active = False
                messagebox.showinfo("Success", "Camera disabled")
                self.update_status()

    def register_face(self):
        if not FACE_RECOGNITION_AVAILABLE:
            messagebox.showerror("Feature Unavailable", "Face recognition is not available in this build")
            return
        otp = generate_otp()
        if not send_mail("Face Registration OTP", f"Your OTP for face registration is: {otp}"):
            messagebox.showerror("Error", "Failed to send OTP email")
            return
        dialog = ctk.CTkToplevel(self)
        dialog.title("OTP Verification")
        dialog.geometry("400x200")
        center_window(dialog, 400, 200)
        dialog.lift()
        dialog.focus_force()
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="🔐 Face Registration OTP", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=15)
        ctk.CTkLabel(dialog, text="Enter OTP sent to your email:").pack(pady=10)
        otp_entry = ctk.CTkEntry(dialog, placeholder_text="Enter 6-digit OTP", width=200)
        otp_entry.pack(pady=10)
        def verify():
            if otp_entry.get() == otp:
                dialog.destroy()
                messagebox.showinfo("Ready", "See the camera in 3 seconds...")
                threading.Thread(target=self.capture_face_frames, daemon=True).start()
            else:
                messagebox.showerror("Invalid OTP", "Incorrect OTP. Recording intruder activity...")
                threading.Thread(target=record_intruder).start()
                dialog.destroy()
        ctk.CTkButton(dialog, text="Verify OTP", command=verify, fg_color="#4B0082", width=200, height=40).pack(pady=15)

    def capture_face_frames(self):
        try:
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                messagebox.showerror("Webcam Error", "Webcam could not be accessed.")
                return
            face_frames = []
            countdown = 3
            start_time = time.time()
            window_name = "Face Registration Preview"
            cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
            app_x = self.winfo_x()
            app_y = self.winfo_y()
            app_w = self.winfo_width()
            app_h = self.winfo_height()
            win_w, win_h = 320, 240
            x_pos = app_x + (app_w // 2) - (win_w // 2)
            y_pos = app_y + (app_h // 2) - (win_h // 2)
            cv2.moveWindow(window_name, x_pos, y_pos)
            while len(face_frames) < 5:
                ret, frame = cap.read()
                if not ret:
                    continue
                current_time = time.time()
                elapsed = current_time - start_time
                if elapsed < countdown:
                    cv2.putText(frame, f"{countdown - int(elapsed)}", (250, 240), cv2.FONT_HERSHEY_SIMPLEX, 3, (0, 255, 0), 5)
                else:
                    face_frames.append(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
                    time.sleep(0.5)
                resized_frame = cv2.resize(frame, (320, 240))
                cv2.imshow(window_name, resized_frame)
                if cv2.waitKey(1) == 27:
                    break
            cap.release()
            cv2.destroyAllWindows()
            if face_frames:
                encodings = []
                for img in face_frames:
                    locations = face_recognition.face_locations(img)
                    if len(locations) == 1:
                        encodings.append(face_recognition.face_encodings(img, locations)[0])
                if encodings:
                    self.security.face_users.append(encodings)
                    self.security.save_face_data()
                    messagebox.showinfo("Success", f"Registered new user with {len(encodings)} samples")
                    self.update_status()
                else:
                    messagebox.showwarning("No Faces Detected", "No valid face found in captured images.")
            else:
                messagebox.showwarning("No Frames Captured", "Face registration failed")
        except Exception as e:
            messagebox.showerror("Error", f"Face capture failed: {str(e)}")

    def view_logs(self):
        if not os.path.exists(LOG_FILE):
            messagebox.showinfo("Logs", "No logs available yet")
            return
        log_window = ctk.CTkToplevel(self)
        log_window.title("Security Logs (Base64 Decoded)")
        log_window.geometry("800x600")
        center_window(log_window, 800, 600)
        log_window.lift()
        log_window.focus_force()
        log_window.grab_set()
        textbox = ctk.CTkTextbox(log_window, wrap="word")
        textbox.pack(fill="both", expand=True, padx=10, pady=10)
        with open(LOG_FILE, "r") as f:
            for line_num, line in enumerate(f, 1):
                try:
                    decoded_line = base64.b64decode(line.strip()).decode('utf-8', 'ignore')
                    textbox.insert("end", f"{line_num:3}: {decoded_line}\n")
                except:
                    textbox.insert("end", f"{line_num:3}: [Invalid log entry]\n")
        textbox.configure(state="disabled")
        btn_frame = ctk.CTkFrame(log_window)
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Refresh Logs", command=lambda: [log_window.destroy(), self.view_logs()]).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Clear Logs", command=self.clear_logs).pack(side="left", padx=5)

    def clear_logs(self):
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear all logs?"):
            with open(LOG_FILE, "w"):
                pass
            messagebox.showinfo("Success", "Logs cleared successfully")

    def add_schedule_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Add Privacy Schedule")
        dialog.geometry("400x300")
        center_window(dialog, 400, 300)
        dialog.lift()
        dialog.focus_force()
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="Add Privacy Schedule", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=15)
        ctk.CTkLabel(dialog, text="Start Time (HH:MM):").pack(pady=5)
        start_entry = ctk.CTkEntry(dialog, width=200)
        start_entry.pack(pady=5)
        ctk.CTkLabel(dialog, text="End Time (HH:MM):").pack(pady=5)
        end_entry = ctk.CTkEntry(dialog, width=200)
        end_entry.pack(pady=5)
        ctk.CTkLabel(dialog, text="Example: 22:00 to 07:00", font=ctk.CTkFont(size=10), text_color="gray").pack(pady=5)
        def save_schedule():
            start = start_entry.get().strip()
            end = end_entry.get().strip()
            try:
                datetime.strptime(start, "%H:%M")
                datetime.strptime(end, "%H:%M")
                self.security.add_schedule(start, end)
                self.update_schedule_list()
                dialog.destroy()
                messagebox.showinfo("Success", f"Schedule added: {start} - {end}")
            except ValueError:
                messagebox.showerror("Error", "Invalid time format. Use HH:MM")
        ctk.CTkButton(dialog, text="Save Schedule", command=save_schedule, fg_color="green", width=150).pack(pady=15)

    def edit_selected_schedule(self):
        selected = self.schedule_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please click on a schedule row to select it first")
            return
        try:
            item = selected[0]
            values = self.schedule_tree.item(item, "values")
            if not values or len(values) < 2:
                raise ValueError("Invalid schedule data")
            dialog = ctk.CTkToplevel(self)
            dialog.title("Edit Schedule")
            dialog.geometry("400x300")
            center_window(dialog, 400, 300)
            dialog.lift()
            dialog.focus_force()
            dialog.grab_set()
            ctk.CTkLabel(dialog, text="Edit Privacy Schedule", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=15)
            ctk.CTkLabel(dialog, text="Start Time (HH:MM):").pack(pady=5)
            start_entry = ctk.CTkEntry(dialog, width=200)
            start_entry.insert(0, values[0])
            start_entry.pack(pady=5)
            ctk.CTkLabel(dialog, text="End Time (HH:MM):").pack(pady=5)
            end_entry = ctk.CTkEntry(dialog, width=200)
            end_entry.insert(0, values[1])
            end_entry.pack(pady=5)
            def save_edit():
                new_start = start_entry.get().strip()
                new_end = end_entry.get().strip()
                try:
                    datetime.strptime(new_start, "%H:%M")
                    datetime.strptime(new_end, "%H:%M")
                    old_start, old_end = values[0], values[1]
                    for i, (start, end) in enumerate(self.security.schedules):
                        if start == old_start and end == old_end:
                            self.security.schedules[i] = (new_start, new_end)
                            break
                    self.security.save_schedules()
                    self.update_schedule_list()
                    dialog.destroy()
                    messagebox.showinfo("Success", "Schedule updated successfully")
                except ValueError:
                    messagebox.showerror("Error", "Invalid time format. Use HH:MM")
            ctk.CTkButton(dialog, text="Save Changes", command=save_edit, fg_color="orange", width=150).pack(pady=15)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to edit schedule: {str(e)}")

    def delete_selected_schedule(self):
        selected = self.schedule_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please click on a schedule row to select it first")
            return
        try:
            item = selected[0]
            values = self.schedule_tree.item(item, "values")
            if not values or len(values) < 2:
                raise ValueError("Invalid schedule data")
            schedule_text = f"{values[0]} - {values[1]}"
            if messagebox.askyesno("Confirm Delete", f"Delete schedule: {schedule_text}?"):
                old_start, old_end = values[0], values[1]
                for i, (start, end) in enumerate(self.security.schedules):
                    if start == old_start and end == old_end:
                        del self.security.schedules[i]
                        break
                self.security.save_schedules()
                self.update_schedule_list()
                messagebox.showinfo("Success", "Schedule deleted successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete schedule: {str(e)}")

    def update_schedule_list(self):
        for item in self.schedule_tree.get_children():
            self.schedule_tree.delete(item)
        for schedule in self.security.schedules:
            self.schedule_tree.insert("", "end", values=(schedule[0], schedule[1], "⚠ Inactive"))

    def enable_camera(self):
        self.authenticate("enable")

    def disable_camera(self):
        self.authenticate("disable")

    def show_project_info(self):
        logo_path = resource_path("suprajatechnologieslogo.jpeg").replace("\\", "/")
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>USB Physical Security Project</title>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
  <style>
    body {{ font-family: 'Poppins', sans-serif; background: #f4f7fc; color: #333; padding: 40px; position: relative; }} 
    .logo-outside {{ position: absolute; top: 20px; right: 40px; }}
    .logo-outside img {{ width: 100px; height: 100px; border-radius: 50%; object-fit: cover; border: 2px solid #ccc; }}
    .container {{ max-width: 900px; margin: auto; background: #fff; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.08); overflow: hidden; padding: 30px 40px; }}
    h1 {{ text-align: center; font-size: 2rem; color: #2c3e50; margin-bottom: 20px; }}
    .intro {{ text-align: center; font-size: 1rem; color: #555; margin-bottom: 30px; }}
    .intro strong {{ color: #2c3e50; }}
    .section {{ margin-bottom: 30px; }}
    .section-title {{ font-size: 1.2rem; font-weight: 600; color: #1f2d3d; margin-bottom: 15px; border-left: 4px solid #3498db; padding-left: 10px; }}
    .info-table {{ width: 100%; border-collapse: collapse; }}
    .info-table th, .info-table td {{ padding: 14px; border-bottom: 1px solid #eee; text-align: left; }}
    .info-table th {{ background-color: #f1f3f6; color: #34495e; }}
    .highlight {{ font-weight: bold; color: green; }}
    .employee-container {{ display: flex; gap: 40px; flex-wrap: wrap; }}
    .employee-card {{ flex: 1; min-width: 300px; }}
    .employee-card table {{ width: 100%; border-collapse: collapse; }}
    .employee-card th, .employee-card td {{ padding: 10px; border-bottom: 1px solid #eee; text-align: left; }}
    .employee-card th {{ background-color: #f1f3f6; color: #34495e; }}
  </style>
</head>
<body>
  <div class="logo-outside">
    <img src="file://{logo_path}" alt="Supraja Technologies Logo">
  </div>
  <div class="container">
    <h1>Project Information</h1>
    <p class="intro">This project was developed by <strong>ROKKAM KARTEEK AND LUTTA DEVIPRASAD</strong> as part of a 
      <strong>Cyber Security Internship</strong>. It is designed to 
      <strong>Secure the Organizations in Real World from Cyber Frauds performed by Hackers</strong>.
    </p>
    <div class="section">
      <div class="section-title">Project Details</div>
      <table class="info-table">
        <tr><th>Project Name</th><td>Web Cam Security from Spyware</td></tr>
        <tr><th>Project Description</th><td>Implementing Physical Security Policy on Web Cam in Devices to Prevent Spyware Activities</td></tr>
        <tr><th>Project Start Date</th><td>29-May-2025</td></tr>
        <tr><th>Project End Date</th><td>10-June-2025</td></tr>
        <tr><th>Project Status</th><td><span class="highlight">Completed</span></td></tr>
      </table>
    </div>
    <div class="section">
      <div class="section-title">Developer Details</div>
      <div class="employee-container">
        <div class="employee-card">
          <table>
            <tr><th>Name</th><td>LUTTA DEVIPRASAD</td></tr>
            <tr><th>Employee ID</th><td>ST#IS#7262</td></tr>
            <tr><th>Email</th><td>deviprasadlutta@gmail.com</td></tr>
          </table>
        </div>
        <div class="employee-card">
          <table>
            <tr><th>Name</th><td>ROKKAM KARTEEK</td></tr>
            <tr><th>Employee ID</th><td>ST#IS#7261</td></tr>
            <tr><th>Email</th><td>karteekrokkam@gmail.com</td></tr>
          </table>
        </div>
      </div>
    </div>
    <div class="section">
      <div class="section-title">Company Details</div>
      <table class="info-table">
        <tr><th>Company</th><td>Supraja Technologies</td></tr>
        <tr><th>Contact Mail</th><td>contact@suprajatechnologies.com</td></tr>
      </table>
    </div>
  </div>
</body>
</html>
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
            f.write(html_content)
            temp_path = f.name
        webbrowser.open(f'file://{temp_path}')

if __name__ == "__main__":
    if sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
    try:
        security_system = WebcamSecurityCore()
        app = SecurityDashboard(security_system)
        app.mainloop()
        security_system.stop()
    except Exception as e:
        log_action(f"Application error: {str(e)}")
        messagebox.showerror("Error", f"Application error: {str(e)}")