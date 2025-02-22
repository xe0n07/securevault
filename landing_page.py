import sqlite3
import hashlib
import random
from tkinter import *
import subprocess
from customtkinter import *

# Set Theme
set_appearance_mode("dark")

# Root Window
root = CTk()
root.title("Secure Vault")
root.geometry("1300x700")

#Light and Dark Toggle 
def toggle_theme(theme):
    set_appearance_mode(theme)

    # Refresh all open Toplevel windows
    for window in root.winfo_toplevels():
        if isinstance(window, CTkToplevel):
            window.update()
            for widget in window.winfo_children():
                widget.update()

def create_theme_toggle(window):
    theme_switch = CTkSegmentedButton(root, values=["Light", "Dark"], command=toggle_theme)
    theme_switch.pack(side="right", pady=10)

create_theme_toggle(root)

chk = BooleanVar()  # Checkbox variable

conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        otp TEXT,
        security_q1 TEXT,
        security_a1 TEXT,
        security_q2 TEXT,
        security_a2 TEXT
    )
""")
conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def show_password(entry_widget):
    entry_widget.configure(show="" if chk.get() else "*")

def generate_otp():
    digits = [str(random.randint(0, 9)) for _ in range(6)]
    return "-".join(["".join(digits[i:i+2]) for i in range(0, 6, 2)])

def verify_security_answers(username, answers):
    cursor.execute("SELECT security_a1, security_a2 FROM users WHERE username = ?", (username,))
    stored_answers = cursor.fetchone()
    correct_answers = 0
    for stored, provided in zip(stored_answers, answers):
        if stored == provided:
            correct_answers += 1
    return correct_answers >= 1

def signup():
    username = un.get()
    password = hash_password(pw.get())
    otp = generate_otp()
    
    security_answers = [
        (q1.get(), a1.get()), (q2.get(), a2.get())
    ]
    
    try:
        cursor.execute("""
            INSERT INTO users (username, password, otp, 
            security_q1, security_a1, security_q2, security_a2) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, password, otp, *[item for pair in security_answers for item in pair]))
        conn.commit()
        signup_status.configure(text=f"Signup Successful! Your OTP: {otp}", text_color="green")
    except sqlite3.IntegrityError:
        signup_status.configure(text="Username already exists!", text_color="red")

def signin():
    username = username_entry.get()
    otp = otp_entry.get()
    
    cursor.execute("SELECT * FROM users WHERE username = ? AND otp = ?", (username, otp))
    user = cursor.fetchone()
    
    if user:
        signin_status.configure(text="SIGN-IN SUCCESS.", text_color="green")
        subprocess.Popen(["python", "dashboard.py"])
    else:
        signin_status.configure(text="Invalid Credentials!", text_color="red")

def forgot_pin():
    forgot_window = CTkToplevel(root)
    forgot_window.geometry("400x600")
    forgot_window.title("Recover PIN")
    forgot_window.transient(root)
    forgot_window.grab_set()
    forgot_window.focus_set()

    create_theme_toggle(forgot_window)

    label_width=120
    CTkLabel(forgot_window, text="Enter Username:", width=label_width, anchor="center").pack()
    username_entry = CTkEntry(forgot_window)
    username_entry.pack()
    
    CTkLabel(forgot_window, text="Enter Password:", width=label_width, anchor="center").pack()
    password_entry = CTkEntry(forgot_window, show="*")
    password_entry.pack()

    # Show Password Checkbox
    CTkCheckBox(forgot_window, text="Show Password", font=("Space Grotesk", 12), checkmark_color="#FFFFFF", border_color="#81C784", fg_color="#81C784", checkbox_height=25, checkbox_width=25, corner_radius=36, variable=chk, 
                command=lambda: show_password(password_entry)).pack(pady=5)
    
    security_questions = [
        "Where were you born?",
        "What is your favorite book?"
    ]
    
    answer_entries = []
    for q in security_questions:
        CTkLabel(forgot_window, text=q).pack()
        answer = CTkEntry(forgot_window)
        answer.pack()
        answer_entries.append(answer)
    
    def verify_and_reset():
        username = username_entry.get()
        password = hash_password(password_entry.get())
        answers = [entry.get() for entry in answer_entries]
        
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        stored_password = cursor.fetchone()
        
        if stored_password and stored_password[0] == password and verify_security_answers(username, answers):
            new_otp = generate_otp()
            cursor.execute("UPDATE users SET otp = ? WHERE username = ?", (new_otp, username))
            conn.commit()
            CTkLabel(forgot_window, text=f"Your new OTP is: {new_otp}", text_color="green").pack()
        else:
            CTkLabel(forgot_window, text="Invalid credentials or answers!", text_color="red").pack()
    
    CTkButton(forgot_window, text="Verify and Reset OTP", command=verify_and_reset).pack()


def open_signin_page(event=None):
    global username_entry, otp_entry, signin_status
    signin_window = CTkToplevel(root)
    signin_window.geometry("700x700")
    signin_window.title("Sign In")

    frame=CTkFrame(signin_window, corner_radius=15)
    frame.pack(pady=20, padx=20, fill="both")

    signin_window.transient(root)
    signin_window.grab_set()
    signin_window.focus_set()

    label_width=120
    CTkLabel(frame, text="SECURE VAULT", font=("Space Grotesk", 20, "bold"), width=label_width, anchor="center").pack(pady=10)

    CTkLabel(frame, text="Welcome Back!", font=("Space Grotesk", 16), width=label_width, anchor="center").pack()
    
    CTkLabel(frame, text="Username:", font=("Space Grotesk", 12), width=label_width, anchor="center").pack(pady=5)
    username_entry = CTkEntry(frame, width=300)
    username_entry.pack()

    CTkLabel(frame, text="One-Time PIN:", font=("Space Grotesk", 12), width=label_width, anchor="center").pack(pady=5)
    otp_entry = CTkEntry(frame, width=300)
    otp_entry.pack()

    # Restrict OTP entry to digits and hyphen
    def validate_otp_entry(char):
        return char.isdigit() or char == '-'
    
    otp_entry.configure(validate="key", validatecommand=(otp_entry.register(validate_otp_entry), '%S'))

    CTkButton(frame, text="Sign In", font=("Space Grotesk", 12), command=signin,
              corner_radius=32, fg_color="#C850C0", hover_color="#4158D0").pack(pady=10, anchor="center")

    signin_status = CTkLabel(frame, text="", font=("Space Grotesk", 12))
    signin_status.pack()

    CTkButton(frame, text="Forgot PIN?", font=("Space Grotesk", 12), command=forgot_pin,
              corner_radius=32, fg_color="#C850C0", hover_color="#4158D0").pack(pady=10, anchor="center")

def open_signup_page(event=None):
    global un, pw, q1, a1, q2, a2, signup_status
    signup_window = CTkToplevel(root)
    signup_window.geometry("1000x700")
    signup_window.title("Sign Up")

    signup_window.transient(root)
    signup_window.grab_set()
    signup_window.focus_set()
    
    frame=CTkFrame(signup_window)
    frame.pack(pady=10, padx=10, fill="both")

    label_width=120
    CTkLabel(frame, text="Create Your Account", font=("Space Grotesk", 16,"bold"), width=label_width, anchor="center").pack(pady=10)

    CTkLabel(frame, text="Username", font=("Space Grotesk", 12), width=label_width, anchor="center").pack(pady=5)
    un = CTkEntry(frame, width=300)
    un.pack()

    CTkLabel(frame, text="Password", font=("Space Grotesk", 12), width=label_width, anchor="center").pack(pady=5)
    pw = CTkEntry(frame, show="*", width=300)
    pw.pack()

    CTkCheckBox(frame, text="Show Password", font=("Space Grotesk", 12), checkmark_color="#FFFFFF", border_width=2, border_color="#81C784", fg_color="#81C784", checkbox_height=25, checkbox_width=25, corner_radius=36, variable=chk, 
                command=lambda: show_password(pw)).pack(pady=5)

    security_questions = [
        "Where were you born?",
        "What is your favorite book?"
    ]

    q1, a1 = StringVar(), StringVar()
    q2, a2 = StringVar(), StringVar()

    for i, q in enumerate(security_questions, 1):
        CTkLabel(frame, text=f"Security Question {i}:", font=("Space Grotesk", 12), width=label_width, anchor="center").pack(pady=5)
        question = CTkOptionMenu(frame, variable=eval(f'q{i}'), values=security_questions, width=250, height=10, corner_radius=10)
        question.pack()
        CTkLabel(frame, text="Answer:", font=("Space Grotesk", 12), width=label_width, anchor="center").pack()
        answer = CTkEntry(frame, textvariable=eval(f'a{i}'), width=250, height=10, corner_radius=10)
        answer.pack()

    CTkButton(frame, text="Sign Up", font=("Space Grotesk", 12), command=signup,
              corner_radius=32, fg_color="#C850C0", hover_color="#4158D0").pack(pady=10, anchor="center")

    signup_status = CTkLabel(frame, text="", font=("Space Grotesk", 12))
    signup_status.pack()

CTkLabel(root, text="Let's Get In", font=("Space Grotesk", 40)).pack(pady=20)
CTkLabel(root, text="Join Secure Vault Today!", font=("Space Grotesk", 30)).pack(pady=10)

CTkButton(root, text="Sign In With Your Account", font=("Space Grotesk", 20),
          command=open_signin_page, corner_radius=32, 
          fg_color="#C850C0", hover_color="#4158D0", height=50, width=250).pack(pady=30, anchor="center")

CTkLabel(root, text="Don't have an account?", font=("Space Grotesk", 18)).pack()
signup_link = CTkLabel(root, text="Sign Up", text_color="blue", font=("Space Grotesk", 22, "underline"))
signup_link.pack(pady=10)
signup_link.bind("<Button-1>", open_signup_page)



root.mainloop()
conn.close()
