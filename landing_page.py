import sqlite3
import hashlib
from tkinter import *
from customtkinter import *

set_appearance_mode("dark")

root = CTk()
root.title("Login")
root.geometry("700x500")

chk = BooleanVar()

# Database Connection
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute(
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password TEXT
    )"""
)
conn.commit()

# Hash Password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Sign Up Function
def signup():
    username = un.get()
    email = ea.get()
    password = hash_password(pw.get())

    if username and email and pw.get():
        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
            conn.commit()
            CTkLabel(frame2, text="Signup Successful!", text_color="green").pack()
        except sqlite3.IntegrityError:
            CTkLabel(frame2, text="Username already exists!", text_color="red").pack()
    else:
        CTkLabel(frame2, text="Please fill all fields!", text_color="red").pack()

# Sign In Function
def signin():
    username = ea.get()
    password = hash_password(pw.get())

    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()

    if user:
        CTkLabel(frame4, text="Login Successful!", text_color="green").pack()
    else:
        CTkLabel(frame4, text="Invalid Credentials!", text_color="red").pack()

# Show/Hide Password
def show_password(pw):
    pw.configure(show="" if chk.get() else "*")

# Sign-In Page
def open_signin_page(event=None):
    global ea, pw, frame4
    signin_window = CTkToplevel(root)
    signin_window.geometry("400x400")
    signin_window.title("Sign In")

    frame4 = CTkFrame(signin_window)
    frame4.pack(expand=True)

    CTkLabel(frame4, text="SECURE VAULT", font=("Space Grotesk", 16)).pack()
    CTkLabel(frame4, text="Welcome Back!", font=("Space Grotesk", 10)).pack()
    CTkLabel(frame4, text="Username:", font=("Space Grotesk", 12)).pack()
    ea = CTkEntry(frame4)
    ea.pack()
    
    CTkLabel(frame4, text="Password:", font=("Space Grotesk", 12)).pack()
    pw = CTkEntry(frame4, show="*")
    pw.pack()

    CTkCheckBox(frame4, text="Show", variable=chk, command=lambda: show_password(pw)).pack()

    CTkButton(frame4, text="Sign In", command=signin, corner_radius=32, fg_color="#C850C0", hover_color="#4158D0").pack(pady=10)

# Sign-Up Page
def open_signup_page(event=None):
    global un, ea, pw, frame2
    signup_window = CTkToplevel(root)
    signup_window.geometry("400x400")
    signup_window.title("Sign Up")

    frame2 = CTkFrame(signup_window)
    frame2.pack(expand=True)

    CTkLabel(frame2, text="Create Your Account", font=("Space Grotesk", 16)).pack()
    CTkLabel(frame2, text="Username", font=("Space Grotesk", 12)).pack()
    un = CTkEntry(frame2)
    un.pack()

    CTkLabel(frame2, text="Email Address", font=("Space Grotesk", 12)).pack()
    ea = CTkEntry(frame2)
    ea.pack()

    CTkLabel(frame2, text="Password", font=("Space Grotesk", 12)).pack()
    pw = CTkEntry(frame2, show="*")
    pw.pack()

    CTkCheckBox(frame2, text="Show", variable=chk, command=lambda: show_password(pw)).pack()
    CTkButton(frame2, text="Sign Up", command=signup, corner_radius=32, fg_color="#C850C0", hover_color="#4158D0").pack(pady=10)

# Main Frame
frame = CTkFrame(root)
frame.pack(expand=True)

CTkLabel(frame, text="Let's get in", font=("Space Grotesk", 20)).pack()
CTkLabel(frame, text="Join Secure Vault Today!", font=("Space Grotesk", 18)).pack()

CTkButton(frame, text="Sign In With Your Account", command=open_signin_page, corner_radius=32, fg_color="#C850C0", hover_color="#4158D0").pack(pady=10)

CTkLabel(frame, text="Don't have an Account?", font=("Space Grotesk", 8)).pack()
signup_link = CTkLabel(frame, text="Sign Up", text_color="blue", font=("Space Grotesk", 8, "underline"))
signup_link.pack()
signup_link.bind("<Button-1>", open_signup_page)

root.mainloop()
