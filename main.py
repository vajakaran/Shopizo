import tkinter as tk
from tkinter import messagebox
import os
import webbrowser

FILE_NAME = "datasheet.txt"

def save_to_txt():
    name = entry_name.get()
    email = entry_email.get()
    password = entry_password.get()
    mobile = entry_mobile.get()

    if name and email and password and mobile:
        formatted_data = f"{name:<15} | {email:<25} | {password:<15} | {mobile:<15}\n"
        file_exists = os.path.isfile(FILE_NAME)

        with open(FILE_NAME, "a") as file:
            if not file_exists:
                file.write(f"{'Name':<15} | {'Email':<25} | {'Password':<15} | {'Mobile':<15}\n")
                file.write("-" * 75 + "\n")
            file.write(formatted_data)

        messagebox.showinfo("Success", "Registration Successful!")
        entry_name.delete(0, tk.END)
        entry_email.delete(0, tk.END)
        entry_password.delete(0, tk.END)
        entry_mobile.delete(0, tk.END)
    else:
        messagebox.showwarning("Error", "All fields are required!")

def forgot_password_window():
    win = tk.Toplevel(root)
    win.title("Forgot Password")
    win.geometry("350x300")
    win.config(bg="#ecf0f1")

    tk.Label(win, text="🔐 Reset Password", font=("Helvetica", 16, "bold"), bg="#ecf0f1").pack(pady=15)

    tk.Label(win, text="📧 Email", bg="#ecf0f1", font=("Arial", 12)).pack()
    email_entry = tk.Entry(win, font=("Arial", 12), width=30)
    email_entry.pack()

    tk.Label(win, text="🆕 New Password", bg="#ecf0f1", font=("Arial", 12)).pack(pady=5)
    new_pass_entry = tk.Entry(win, font=("Arial", 12), width=30, show="*")
    new_pass_entry.pack()

    tk.Label(win, text="✅ Confirm Password", bg="#ecf0f1", font=("Arial", 12)).pack(pady=5)
    confirm_pass_entry = tk.Entry(win, font=("Arial", 12), width=30, show="*")
    confirm_pass_entry.pack()

    def reset_password():
        email = email_entry.get().strip()
        new_pass = new_pass_entry.get().strip()
        confirm_pass = confirm_pass_entry.get().strip()

        if not email or not new_pass or not confirm_pass:
            messagebox.showwarning("Error", "All fields are required!", parent=win)
            return
        if new_pass != confirm_pass:
            messagebox.showerror("Mismatch", "Passwords do not match!", parent=win)
            return

        if not os.path.isfile(FILE_NAME):
            messagebox.showerror("Error", "Data file not found!", parent=win)
            return

        updated = False
        lines = []
        with open(FILE_NAME, "r") as file:
            for line in file:
                if email in line:
                    parts = line.strip().split("|")
                    if len(parts) >= 4:
                        parts[2] = f" {new_pass:<15} "
                        new_line = " | ".join(parts) + "\n"
                        lines.append(new_line)
                        updated = True
                    else:
                        lines.append(line)
                else:
                    lines.append(line)

        if updated:
            with open(FILE_NAME, "w") as file:
                file.writelines(lines)
            messagebox.showinfo("Success", "Password reset successful!", parent=win)
            win.destroy()
        else:
            messagebox.showerror("Not Found", "Email not found!", parent=win)

    tk.Button(win, text="🔁 Reset Password", bg="#27ae60", fg="white", font=("Arial", 12, "bold"),
              command=reset_password).pack(pady=15)

def login_window():
    win = tk.Toplevel(root)
    win.title("Login")
    win.geometry("350x250")
    win.config(bg="#f4f6f7")

    tk.Label(win, text="🔓 Login", font=("Helvetica", 16, "bold"), bg="#f4f6f7").pack(pady=15)

    tk.Label(win, text="📧 Email", font=("Arial", 12), bg="#f4f6f7").pack()
    email_entry = tk.Entry(win, font=("Arial", 12), width=30)
    email_entry.pack()

    tk.Label(win, text="🔒 Password", font=("Arial", 12), bg="#f4f6f7").pack(pady=5)
    pass_entry = tk.Entry(win, font=("Arial", 12), width=30, show="*")
    pass_entry.pack()

    def check_login():
        email = email_entry.get().strip()
        password = pass_entry.get().strip()

        if not email or not password:
            messagebox.showwarning("Error", "All fields required", parent=win)
            return

        found = False
        with open(FILE_NAME, "r") as file:
            for line in file:
                if email in line and password in line:
                    found = True
                    break

        if found:
            messagebox.showinfo("Login Success", "Welcome!", parent=win)
            win.destroy()
            webbrowser.open("index.html")
        else:
            messagebox.showerror("Login Failed", "Incorrect Email or Password", parent=win)

    tk.Button(win, text="Login ✅", font=("Arial", 12, "bold"), bg="#2ecc71", fg="white",
              command=check_login).pack(pady=15)

def logout():
    messagebox.showinfo("Logout", "You have been logged out.")

# ------------------- GUI Setup -------------------
root = tk.Tk()
root.title("User Auth System")
root.geometry("450x520")
root.config(bg="#f8f8f8")
root.resizable(False, False)

tk.Label(root, text="📝 Register", font=("Helvetica", 18, "bold"), bg="#f8f8f8", fg="#2c3e50").pack(pady=20)

form_frame = tk.Frame(root, bg="white", bd=2)
form_frame.pack(pady=10)

def create_field(label, row):
    tk.Label(form_frame, text=label, font=("Arial", 12, "bold"), bg="white", fg="#34495e")\
        .grid(row=row, column=0, padx=10, pady=10, sticky="w")
    entry = tk.Entry(form_frame, font=("Arial", 12), width=28, bd=2, relief="groove")
    entry.grid(row=row, column=1, padx=10, pady=10)
    return entry

entry_name = create_field("👤 Name", 0)
entry_email = create_field("📧 Email", 1)
entry_password = create_field("🔒 Password", 2)
entry_password.config(show="*")
entry_mobile = create_field("📱 Mobile", 3)

tk.Button(root, text="✅ Register", font=("Arial", 12, "bold"), bg="#16a085", fg="white",
          command=save_to_txt).pack(pady=10)

tk.Button(root, text="🔓 Login", font=("Arial", 11, "bold"), bg="#3498db", fg="white",
          command=login_window).pack(pady=5)

tk.Button(root, text="🔑 Forgot Password?", font=("Arial", 10, "underline"), fg="blue",
          bg="#f8f8f8", bd=0, command=forgot_password_window).pack(pady=5)

# 👇👇👇 LOGOUT BUTTON BELOW REGISTER 👇👇👇
tk.Button(root, text="🚪 Logout", font=("Arial", 11, "bold"), bg="#e74c3c", fg="white",
          command=logout).pack(pady=10)

root.mainloop()
