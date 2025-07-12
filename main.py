import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import hashlib
import os
import smtplib
import random

USERS_FILE = "users.json"
SENDER_EMAIL = "youremail@gmail.com"         # Replace with your Gmail
SENDER_PASSWORD = "yourapppassword"          # Replace with Gmail App Password

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def send_otp(email):
    otp = str(random.randint(100000, 999999))
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        message = f"Subject: OTP Verification\n\nYour OTP is: {otp}"
        server.sendmail(SENDER_EMAIL, email, message)
        server.quit()
        return otp
    except Exception as e:
        print("Email error:", e)
        return None

class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("E-Authentication System")
        self.root.geometry("400x350")
        self.users = load_users()

        self.username = tk.StringVar()
        self.email = tk.StringVar()
        self.password = tk.StringVar()

        self.otp = ""
        self.otp_username = ""

        self.build_main_screen()

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def build_main_screen(self):
        self.clear()
        tk.Label(self.root, text="E-Authentication", font=("Arial", 18)).pack(pady=10)

        tk.Button(self.root, text="Register", width=20, command=self.register_screen).pack(pady=10)
        tk.Button(self.root, text="Login", width=20, command=self.login_screen).pack(pady=10)
        tk.Button(self.root, text="Forgot Password", width=20, command=self.forgot_password_screen).pack(pady=10)
        tk.Button(self.root, text="Admin Login", width=20, command=self.admin_login_screen).pack(pady=10)

    def register_screen(self):
        self.clear()
        tk.Label(self.root, text="Register", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.root, text="Username").pack()
        tk.Entry(self.root, textvariable=self.username, width=30).pack(pady=5)

        tk.Label(self.root, text="Email").pack()
        tk.Entry(self.root, textvariable=self.email, width=30).pack(pady=5)

        tk.Label(self.root, text="Password").pack()
        tk.Entry(self.root, textvariable=self.password, show="*", width=30).pack(pady=5)

        tk.Button(self.root, text="Register", command=self.register_user).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.build_main_screen).pack()

    def login_screen(self):
        self.clear()
        tk.Label(self.root, text="Login", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.root, text="Username").pack()
        tk.Entry(self.root, textvariable=self.username, width=30).pack(pady=5)

        tk.Label(self.root, text="Password").pack()
        tk.Entry(self.root, textvariable=self.password, show="*", width=30).pack(pady=5)

        tk.Button(self.root, text="Login", command=self.login_user).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.build_main_screen).pack()

    def forgot_password_screen(self):
        self.clear()
        tk.Label(self.root, text="Reset Password", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.root, text="Username").pack()
        tk.Entry(self.root, textvariable=self.username, width=30).pack(pady=5)

        tk.Button(self.root, text="Send OTP", command=self.send_reset_otp).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.build_main_screen).pack()

    def register_user(self):
        uname = self.username.get()
        email = self.email.get()
        passwd = self.password.get()

        if uname in self.users:
            messagebox.showerror("Error", "Username already exists.")
            return
        self.users[uname] = {
            "email": email,
            "password": hash_password(passwd)
        }
        save_users(self.users)
        messagebox.showinfo("Success", "Registered successfully.")
        self.username.set("")
        self.email.set("")
        self.password.set("")
        self.build_main_screen()

    def login_user(self):
        uname = self.username.get()
        passwd = self.password.get()

        if uname not in self.users:
            messagebox.showerror("Error", "User not found.")
            return
        if self.users[uname]["password"] != hash_password(passwd):
            messagebox.showerror("Error", "Wrong password.")
            return
        self.otp = send_otp(self.users[uname]["email"])
        if not self.otp:
            messagebox.showerror("Error", "Failed to send OTP.")
            return
        self.otp_username = uname
        self.otp_popup()

    def otp_popup(self):
        popup = tk.Toplevel(self.root)
        popup.title("OTP Verification")
        popup.geometry("300x150")
        tk.Label(popup, text="Enter OTP sent to your email").pack(pady=5)
        otp_entry = tk.Entry(popup)
        otp_entry.pack(pady=5)

        def verify():
            if otp_entry.get() == self.otp:
                messagebox.showinfo("Success", f"Welcome, {self.otp_username}")
                popup.destroy()
                self.username.set("")
                self.password.set("")
            else:
                messagebox.showerror("Error", "Invalid OTP")

        def resend():
            self.otp = send_otp(self.users[self.otp_username]["email"])
            messagebox.showinfo("Info", "OTP Resent")

        tk.Button(popup, text="Verify", command=verify).pack(pady=5)
        tk.Button(popup, text="Resend OTP", command=resend).pack()

    def send_reset_otp(self):
        uname = self.username.get()
        if uname not in self.users:
            messagebox.showerror("Error", "Username not found.")
            return
        self.otp = send_otp(self.users[uname]["email"])
        if not self.otp:
            messagebox.showerror("Error", "Failed to send OTP.")
            return
        self.otp_username = uname
        self.reset_password_popup()

    def reset_password_popup(self):
        popup = tk.Toplevel(self.root)
        popup.title("Reset Password")
        popup.geometry("300x200")

        tk.Label(popup, text="Enter OTP").pack()
        otp_entry = tk.Entry(popup)
        otp_entry.pack()

        tk.Label(popup, text="New Password").pack()
        new_pass_entry = tk.Entry(popup, show="*")
        new_pass_entry.pack()

        def reset_pass():
            if otp_entry.get() == self.otp:
                new_pass = new_pass_entry.get()
                self.users[self.otp_username]["password"] = hash_password(new_pass)
                save_users(self.users)
                messagebox.showinfo("Success", "Password reset successfully")
                popup.destroy()
            else:
                messagebox.showerror("Error", "Incorrect OTP")

        tk.Button(popup, text="Reset Password", command=reset_pass).pack(pady=10)

    def admin_login_screen(self):
        self.clear()
        tk.Label(self.root, text="Admin Login", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.root, text="Admin Username").pack()
        tk.Entry(self.root, textvariable=self.username, width=30).pack()

        tk.Label(self.root, text="Admin Password").pack()
        tk.Entry(self.root, textvariable=self.password, show="*", width=30).pack()

        tk.Button(self.root, text="Login", command=self.admin_dashboard).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.build_main_screen).pack()

    def admin_dashboard(self):
        if self.username.get() != ADMIN_USERNAME or self.password.get() != ADMIN_PASSWORD:
            messagebox.showerror("Error", "Invalid Admin credentials.")
            return

        self.clear()
        tk.Label(self.root, text="Admin Dashboard", font=("Arial", 16)).pack(pady=10)

        for user in self.users:
            tk.Label(self.root, text=f"{user} | {self.users[user]['email']}").pack()

        def delete_user():
            target = simpledialog.askstring("Delete User", "Enter username to delete:")
            if target in self.users:
                del self.users[target]
                save_users(self.users)
                messagebox.showinfo("Deleted", f"User '{target}' deleted.")
                self.admin_dashboard()
            else:
                messagebox.showerror("Error", "User not found.")

        def reset_user_pass():
            target = simpledialog.askstring("Reset Password", "Enter username to reset password:")
            if target in self.users:
                new_pass = simpledialog.askstring("New Password", "Enter new password:")
                self.users[target]["password"] = hash_password(new_pass)
                save_users(self.users)
                messagebox.showinfo("Success", f"Password reset for '{target}'.")
            else:
                messagebox.showerror("Error", "User not found.")

        tk.Button(self.root, text="Delete User", command=delete_user).pack(pady=5)
        tk.Button(self.root, text="Reset User Password", command=reset_user_pass).pack(pady=5)
        tk.Button(self.root, text="Back", command=self.build_main_screen).pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()
