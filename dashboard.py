import tkinter as tk
from customtkinter import *
import sqlite3
from cryptography.fernet import Fernet

# Generate a key for encryption and decryption
# You must store and use the same key for encryption and decryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Initialize the main window
root = CTk()
root.title("Secure Vault")
root.geometry("1300x700")

conn = sqlite3.connect("user_database.db")
cursor = conn.cursor()

menu_bar_colour = "#2C2F33"
button_color = "#23272A"
selected_color = "#7289DA"

menu_bar_frame = CTkFrame(root, fg_color=menu_bar_colour, width=250)
menu_bar_frame.pack(side=tk.LEFT, fill="y", padx=5, pady=25)
menu_bar_frame.pack_propagate(False)

content_frame = CTkFrame(root, fg_color="white", width=1500, height=850)
content_frame.pack(side=tk.RIGHT, fill="both", expand=True, padx=5, pady=25)

menu_buttons = {}

def switch_page(page_function):
    """ Clears the content frame and calls the selected page function """
    for widget in content_frame.winfo_children():
        widget.destroy()
    
    page_function()

def logins():
    label = CTkLabel(content_frame, text="Logins Page", font=("Arial", 24, "bold"), text_color="black")
    label.pack(pady=20)
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS logins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT,
                    email TEXT,
                    password TEXT NOT NULL)''')
    conn.commit()

    # Function to encrypt password
    def encrypt_password(password):
        return password
    # Function to decrypt password
    def decrypt_password(encrypted_password):
        return encrypted_password
    
    # Function to add login details
    def add_login():
        service = service_entry.get()
        username = username_entry.get()
        email = email_entry.get()
        password = password_entry.get()

        if service and password:
            encrypted_pass = encrypt_password(password)
            cursor.execute("INSERT INTO logins (service, username, email, password) VALUES (?, ?, ?, ?)",
                           (service, username, email, encrypted_pass))
            conn.commit()
            load_logins()
        else:
            status_label.configure(text="Service & Password are required!", text_color="red")

    # Function to load logins
    def load_logins():
        login_listbox.delete(0, tk.END)
        cursor.execute("SELECT service, username FROM logins")
        for row in cursor.fetchall():
            login_listbox.insert(tk.END, f"{row[0]} - {row[1]} - ")

    # Function to delete login
    def delete_login():
        try:
            selected = login_listbox.get(login_listbox.curselection())
            service = selected.split(" - ")[0]
            username = selected.split(" - ")[1]
            cursor.execute("DELETE FROM logins WHERE service=? and username=?", (service    ,username,))
            conn.commit()
            load_logins()
        except:
            status_label.configure(text="Select an entry to delete!", text_color="red")

    # Function to show selected login details
    def view_login():
        try:
            selected = login_listbox.get(login_listbox.curselection())
            service = selected.split(" - ")[0]
            username = selected.split(" - ")[1]
            cursor.execute("SELECT * FROM logins WHERE service=? and username=?", (service,username,))
            data = cursor.fetchone()
            service_entry.delete(0, tk.END)
            username_entry.delete(0, tk.END)
            email_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)

            service_entry.insert(0, data[1])
            username_entry.insert(0, data[2])
            email_entry.insert(0, data[3])
            password_entry.insert(0, data[4])  # Decrypt password before displaying
        except:
            status_label.configure(text="Select an entry to view!", text_color="red")

    # Function to update login details
    def update_login():
        try:
            selected = login_listbox.get(login_listbox.curselection())
            login_id = selected.split(" - ")[0]
            service = service_entry.get()
            username = username_entry.get()
            email = email_entry.get()
            password = password_entry.get()

            if service and password:
                encrypted_pass = encrypt_password(password)
                cursor.execute("UPDATE logins SET service=?, username=?, email=?, password=? WHERE id=?",
                               (service, username, email, encrypted_pass, login_id))
                conn.commit()
                load_logins()
            else:
                status_label.configure(text="Service & Password are required!", text_color="red")
        except:
            status_label.configure(text="Select an entry to update!", text_color="red")

    # Toggle show password
    def toggle_password():
        if show_password_var.get():
            password_entry.configure(show="")
        else:
            password_entry.configure(show="*")

    # UI Components
    CTkLabel(content_frame, text="Manage Login Credentials", font=("Arial", 20, "bold")).pack(pady=10)

    input_frame = CTkFrame(content_frame, width=1200, height=800)
    input_frame.pack()

    CTkLabel(input_frame, text="Service Name:").grid(row=0, column=0, padx=5, pady=5)
    service_entry = CTkEntry(input_frame, width=250)
    service_entry.grid(row=0, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Username:").grid(row=1, column=0, padx=5, pady=5)
    username_entry = CTkEntry(input_frame, width=250)
    username_entry.grid(row=1, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Email:").grid(row=2, column=0, padx=5, pady=5)
    email_entry = CTkEntry(input_frame, width=250)
    email_entry.grid(row=2, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Password:").grid(row=3, column=0, padx=5, pady=5)
    password_entry = CTkEntry(input_frame, width=250, show="*")
    password_entry.grid(row=3, column=1, padx=5, pady=5)

    show_password_var = tk.BooleanVar()
    show_password_check = CTkCheckBox(input_frame, text="Show Password", variable=show_password_var, command=toggle_password)
    show_password_check.grid(row=4, column=1, pady=5)

    button_frame = CTkFrame(content_frame)
    button_frame.pack(pady=5)

    CTkButton(button_frame, text="Add", command=add_login, fg_color="green").grid(row=0, column=0, padx=5)
    CTkButton(button_frame, text="Update", command=update_login, fg_color="blue").grid(row=0, column=1, padx=5)
    CTkButton(button_frame, text="Delete", command=delete_login, fg_color="red").grid(row=0, column=2, padx=5)

    # Listbox to show stored logins
    login_listbox = tk.Listbox(content_frame, width=80, height=10)
    login_listbox.pack(pady=5)

    CTkButton(content_frame, text="View", command=view_login, fg_color="purple").pack()

    # Status label
    status_label = CTkLabel(content_frame, text="", text_color="red")
    status_label.pack()

    # Load existing logins
    load_logins()

def secure_notes():
    label = CTkLabel(content_frame, text="Secure Notes Page", font=("Arial", 24, "bold"), text_color="black")
    label.pack(pady=20)
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS secure_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    note TEXT NOT NULL)''')
    conn.commit()

    # Function to encrypt note
    def encrypt_note(note):
        return cipher_suite.encrypt(note.encode()).decode()

    # Function to decrypt note
    def decrypt_note(encrypted_note):
        return cipher_suite.decrypt(encrypted_note.encode()).decode()

    # Function to add note
    def add_note():
        title = title_entry.get()
        note = note_text.get("1.0", tk.END).strip()

        if title and note:
            encrypted_note = encrypt_note(note)
            cursor.execute("INSERT INTO secure_notes (title, note) VALUES (?, ?)",
                           (title, encrypted_note))
            conn.commit()
            load_notes()
        else:
            status_label.configure(text="Title & Note are required!", text_color="red")

    # Function to load notes
    def load_notes():
        notes_listbox.delete(0, tk.END)
        cursor.execute("SELECT title,note FROM secure_notes")
        for row in cursor.fetchall():
            notes_listbox.insert(tk.END, f"{row[0]}")

    # Function to delete note
    def delete_note():
        try:
            selected = notes_listbox.get(notes_listbox.curselection())
            title = selected.split(" - ")[0]
            cursor.execute("DELETE FROM secure_notes WHERE title=?", (title,))
            conn.commit()
            load_notes()
        except:
            status_label.configure(text="Select a note to delete!", text_color="red")

    # Function to show selected note details
    def view_note():
        try:
            selected = notes_listbox.get(notes_listbox.curselection())
            title = selected.split(" - ")[0]
            # note = selected.split(" - ")[1]
            cursor.execute("SELECT * FROM secure_notes WHERE title=? and note=?", (title, note))
            data = cursor.fetchone()
            title_entry.delete(0, tk.END)
            note_text.delete("1.0", tk.END)

            title_entry.insert(0, data[1])
            note_text.insert("1.0", decrypt_note(data[2]))  # Decrypt note before displaying
        except:
            status_label.configure(text="Select a note to view!", text_color="red")

    # Function to update note details
    def update_note():
        try:
            selected = notes_listbox.get(notes_listbox.curselection())
            note_id = selected.split(" - ")[0]
            title = title_entry.get()
            note = note_text.get("1.0", tk.END).strip()

            if title and note:
                encrypted_note = encrypt_note(note)
                cursor.execute("UPDATE secure_notes SET title=?, note=? WHERE id=?",
                               (title, encrypted_note, note_id))
                conn.commit()
                load_notes()
            else:
                status_label.configure(text="Title & Note are required!", text_color="red")
        except:
            status_label.configure(text="Select a note to update!", text_color="red")

    # UI Components
    # CTkLabel(content_frame, text="Manage Secure Notes", font=("Arial", 20, "bold")).pack(pady=10)

    input_frame = CTkFrame(content_frame)
    input_frame.pack(pady=5)

    CTkLabel(input_frame, text="Title:").grid(row=0, column=0, padx=5, pady=5)
    title_entry = CTkEntry(input_frame, width=250)
    title_entry.grid(row=0, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Note:").grid(row=1, column=0, padx=5, pady=5)
    note_text = tk.Text(input_frame, width=50, height=10)
    note_text.grid(row=1, column=1, padx=5, pady=5)

    button_frame = CTkFrame(content_frame)
    button_frame.pack(pady=5)

    CTkButton(button_frame, text="Add", command=add_note, fg_color="green").grid(row=0, column=0, padx=5)
    CTkButton(button_frame, text="Update", command=update_note, fg_color="blue").grid(row=0, column=1, padx=5)
    CTkButton(button_frame, text="Delete", command=delete_note, fg_color="red").grid(row=0, column=2, padx=5)

    # Listbox to show stored notes
    notes_listbox = tk.Listbox(content_frame, width=50, height=10)
    notes_listbox.pack(pady=5)

    CTkButton(content_frame, text="View", command=view_note, fg_color="purple").pack()

    # Status label
    status_label = CTkLabel(content_frame, text="", text_color="red")
    status_label.pack()

    # Load existing notes
    load_notes()

def credit_card():
    label = CTkLabel(content_frame, text="Credit Card Page", font=("Arial", 24, "bold"), text_color="black")
    label.pack(pady=20)
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS credit_cards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    card_number TEXT NOT NULL,
                    service_provider TEXT NOT NULL,
                    validity_from TEXT NOT NULL,
                    validity_upto TEXT NOT NULL,
                    security_number TEXT NOT NULL)''')
    conn.commit()

    # Function to encrypt data
    def encrypt_data(data):
        return cipher_suite.encrypt(data.encode()).decode()

    # Function to decrypt data
    def decrypt_data(encrypted_data):
        return cipher_suite.decrypt(encrypted_data.encode()).decode()

    # Function to add credit card details
    def add_credit_card():
        card_number = card_number_entry.get()
        service_provider = service_provider_entry.get()
        validity_from = validity_from_entry.get()
        validity_upto = validity_upto_entry.get()
        security_number = security_number_entry.get()

        if card_number and service_provider and validity_from and validity_upto and security_number:
            encrypted_card_number = encrypt_data(card_number)
            encrypted_security_number = encrypt_data(security_number)
            cursor.execute("INSERT INTO credit_cards (card_number, service_provider, validity_from, validity_upto, security_number) VALUES (?, ?, ?, ?, ?)",
                           (encrypted_card_number, service_provider, validity_from, validity_upto, encrypted_security_number))
            conn.commit()
            load_credit_cards()
        else:
            status_label.configure(text="All fields are required!", text_color="red")

    # Function to load credit cards
    def load_credit_cards():
        credit_card_listbox.delete(0, tk.END)
        cursor.execute("SELECT id, service_provider FROM credit_cards")
        for row in cursor.fetchall():
            credit_card_listbox.insert(tk.END, f"{row[0]} - {row[1]}")

    # Function to delete credit card
    def delete_credit_card():
        try:
            selected = credit_card_listbox.get(credit_card_listbox.curselection())
            card_id = selected.split(" - ")[0]
            cursor.execute("DELETE FROM credit_cards WHERE id=?", (card_id,))
            conn.commit()
            load_credit_cards()
        except:
            status_label.configure(text="Select a card to delete!", text_color="red")

    # Function to show selected credit card details
    def view_credit_card():
        try:
            selected = credit_card_listbox.get(credit_card_listbox.curselection())
            card_id = selected.split(" - ")[0]
            cursor.execute("SELECT * FROM credit_cards WHERE id=?", (card_id,))
            data = cursor.fetchone()
            card_number_entry.delete(0, tk.END)
            service_provider_entry.delete(0, tk.END)
            validity_from_entry.delete(0, tk.END)
            validity_upto_entry.delete(0, tk.END)
            security_number_entry.delete(0, tk.END)

            card_number_entry.insert(0, decrypt_data(data[1]))
            service_provider_entry.insert(0, data[2])
            validity_from_entry.insert(0, data[3])
            validity_upto_entry.insert(0, data[4])
            security_number_entry.insert(0, decrypt_data(data[5]))  # Decrypt security number before displaying
        except:
            status_label.configure(text="Select a card to view!", text_color="red")

    # Function to update credit card details
    def update_credit_card():
        try:
            selected = credit_card_listbox.get(credit_card_listbox.curselection())
            card_id = selected.split(" - ")[0]
            card_number = card_number_entry.get()
            service_provider = service_provider_entry.get()
            validity_from = validity_from_entry.get()
            validity_upto = validity_upto_entry.get()
            security_number = security_number_entry.get()

            if card_number and service_provider and validity_from and validity_upto and security_number:
                encrypted_card_number = encrypt_data(card_number)
                encrypted_security_number = encrypt_data(security_number)
                cursor.execute("UPDATE credit_cards SET card_number=?, service_provider=?, validity_from=?, validity_upto=?, security_number=? WHERE id=?",
                               (encrypted_card_number, service_provider, validity_from, validity_upto, encrypted_security_number, card_id))
                conn.commit()
                load_credit_cards()
            else:
                status_label.configure(text="All fields are required!", text_color="red")
        except:
            status_label.configure(text="Select a card to update!", text_color="red")

    # UI Components
    # CTkLabel(content_frame, text="Manage Credit Card Details", font=("Arial", 20, "bold")).pack(pady=10)

    input_frame = CTkFrame(content_frame)
    input_frame.pack(pady=5)

    CTkLabel(input_frame, text="Card Number:").grid(row=0, column=0, padx=5, pady=5)
    card_number_entry = CTkEntry(input_frame, width=250)
    card_number_entry.grid(row=0, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Service Provider:").grid(row=1, column=0, padx=5, pady=5)
    service_provider_entry = CTkEntry(input_frame, width=250)
    service_provider_entry.grid(row=1, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Validity From:").grid(row=2, column=0, padx=5, pady=5)
    validity_from_entry = CTkEntry(input_frame, width=250)
    validity_from_entry.grid(row=2, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Validity Upto:").grid(row=3, column=0, padx=5, pady=5)
    validity_upto_entry = CTkEntry(input_frame, width=250)
    validity_upto_entry.grid(row=3, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Security Number:").grid(row=4, column=0, padx=5, pady=5)
    security_number_entry = CTkEntry(input_frame, width=250)
    security_number_entry.grid(row=4, column=1, padx=5, pady=5)

    button_frame = CTkFrame(content_frame)
    button_frame.pack(pady=5)

    CTkButton(button_frame, text="Add", command=add_credit_card, fg_color="green").grid(row=0, column=0, padx=5)
    CTkButton(button_frame, text="Update", command=update_credit_card, fg_color="blue").grid(row=0, column=1, padx=5)
    CTkButton(button_frame, text="Delete", command=delete_credit_card, fg_color="red").grid(row=0, column=2, padx=5)

    # Listbox to show stored credit cards
    credit_card_listbox = tk.Listbox(content_frame, width=50, height=10)
    credit_card_listbox.pack(pady=5)

    CTkButton(content_frame, text="View", command=view_credit_card, fg_color="purple").pack()

    # Status label
    status_label = CTkLabel(content_frame, text="", text_color="red")
    status_label.pack()

    # Load existing credit cards
    load_credit_cards()

def passwords():
    label = CTkLabel(content_frame, text="Passwords Page", font=("Arial", 24, "bold"), text_color="black")
    label.pack(pady=20)

def email_acc():
    label = CTkLabel(content_frame, text="Email Accounts Page", font=("Arial", 24, "bold"), text_color="black")
    label.pack(pady=20)
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS email_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_provider TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    recovery_email TEXT,
                    recovery_mobile TEXT)''')
    conn.commit()

    # Function to encrypt data
    def encrypt_data(data):
        return cipher_suite.encrypt(data.encode()).decode()

    # Function to decrypt data
    def decrypt_data(encrypted_data):
        return cipher_suite.decrypt(encrypted_data.encode()).decode()

    # Function to add email account details
    def add_email_account():
        service_provider = service_provider_entry.get()
        email = email_entry.get()
        password = password_entry.get()
        recovery_email = recovery_email_entry.get()
        recovery_mobile = recovery_mobile_entry.get()

        if service_provider and email and password:
            encrypted_password = encrypt_data(password)
            cursor.execute("INSERT INTO email_accounts (service_provider, email, password, recovery_email, recovery_mobile) VALUES (?, ?, ?, ?, ?)",
                           (service_provider, email, encrypted_password, recovery_email, recovery_mobile))
            conn.commit()
            load_email_accounts()
        else:
            status_label.configure(text="Service Provider, Email & Password are required!", text_color="red")

    # Function to load email accounts
    def load_email_accounts():
        email_account_listbox.delete(0, tk.END)
        cursor.execute("SELECT id, service_provider FROM email_accounts")
        for row in cursor.fetchall():
            email_account_listbox.insert(tk.END, f"{row[0]} - {row[1]}")

    # Function to delete email account
    def delete_email_account():
        try:
            selected = email_account_listbox.get(email_account_listbox.curselection())
            account_id = selected.split(" - ")[0]
            cursor.execute("DELETE FROM email_accounts WHERE id=?", (account_id,))
            conn.commit()
            load_email_accounts()
        except:
            status_label.configure(text="Select an account to delete!", text_color="red")

    # Function to show selected email account details
    def view_email_account():
        try:
            selected = email_account_listbox.get(email_account_listbox.curselection())
            account_id = selected.split(" - ")[0]
            cursor.execute("SELECT * FROM email_accounts WHERE id=?", (account_id,))
            data = cursor.fetchone()
            service_provider_entry.delete(0, tk.END)
            email_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
            recovery_email_entry.delete(0, tk.END)
            recovery_mobile_entry.delete(0, tk.END)

            service_provider_entry.insert(0, data[1])
            email_entry.insert(0, data[2])
            password_entry.insert(0, decrypt_data(data[3]))  # Decrypt password before displaying
            recovery_email_entry.insert(0, data[4])
            recovery_mobile_entry.insert(0, data[5])
        except:
            status_label.configure(text="Select an account to view!", text_color="red")

    # Function to update email account details
    def update_email_account():
        try:
            selected = email_account_listbox.get(email_account_listbox.curselection())
            account_id = selected.split(" - ")[0]
            service_provider = service_provider_entry.get()
            email = email_entry.get()
            password = password_entry.get()
            recovery_email = recovery_email_entry.get()
            recovery_mobile = recovery_mobile_entry.get()

            if service_provider and email and password:
                encrypted_password = encrypt_data(password)
                cursor.execute("UPDATE email_accounts SET service_provider=?, email=?, password=?, recovery_email=?, recovery_mobile=? WHERE id=?",
                               (service_provider, email, encrypted_password, recovery_email, recovery_mobile, account_id))
                conn.commit()
                load_email_accounts()
            else:
                status_label.configure(text="Service Provider, Email & Password are required!", text_color="red")
        except:
            status_label.configure(text="Select an account to update!", text_color="red")

    # UI Components
    # CTkLabel(content_frame, text="Manage Email Accounts", font=("Arial", 20, "bold")).pack(pady=10)

    input_frame = CTkFrame(content_frame)
    input_frame.pack(pady=5)

    CTkLabel(input_frame, text="Service Provider:").grid(row=0, column=0, padx=5, pady=5)
    service_provider_entry = CTkEntry(input_frame, width=250)
    service_provider_entry.grid(row=0, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Email:").grid(row=1, column=0, padx=5, pady=5)
    email_entry = CTkEntry(input_frame, width=250)
    email_entry.grid(row=1, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Password:").grid(row=2, column=0, padx=5, pady=5)
    password_entry = CTkEntry(input_frame, width=250, show="*")
    password_entry.grid(row=2, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Recovery Email:").grid(row=3, column=0, padx=5, pady=5)
    recovery_email_entry = CTkEntry(input_frame, width=250)
    recovery_email_entry.grid(row=3, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Recovery Mobile:").grid(row=4, column=0, padx=5, pady=5)
    recovery_mobile_entry = CTkEntry(input_frame, width=250)
    recovery_mobile_entry.grid(row=4, column=1, padx=5, pady=5)

    show_password_var = tk.BooleanVar()
    show_password_check = CTkCheckBox(input_frame, text="Show Password", variable=show_password_var, command=lambda: password_entry.configure(show="" if show_password_var.get() else "*"))
    show_password_check.grid(row=5, column=1, pady=5)

    button_frame = CTkFrame(content_frame)
    button_frame.pack(pady=5)

    CTkButton(button_frame, text="Add", command=add_email_account, fg_color="green").grid(row=0, column=0, padx=5)
    CTkButton(button_frame, text="Update", command=update_email_account, fg_color="blue").grid(row=0, column=1, padx=5)
    CTkButton(button_frame, text="Delete", command=delete_email_account, fg_color="red").grid(row=0, column=2, padx=5)

    # Listbox to show stored email accounts
    email_account_listbox = tk.Listbox(content_frame, width=50, height=10)
    email_account_listbox.pack(pady=5)

    CTkButton(content_frame, text="View", command=view_email_account, fg_color="purple").pack()

    # Status label
    status_label = CTkLabel(content_frame, text="", text_color="red")
    status_label.pack()

    # Load existing email accounts
    load_email_accounts()

def bank_acc():
    label = CTkLabel(content_frame, text="Bank Accounts Page", font=("Arial", 24, "bold"), text_color="black")
    label.pack(pady=20)
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS bank_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bank_name TEXT NOT NULL,
                    account_number TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    login_pin TEXT NOT NULL,
                    transaction_pin TEXT NOT NULL)''')
    conn.commit()

    # Function to encrypt data
    def encrypt_data(data):
        return data

    # Function to decrypt data
    def decrypt_data(encrypted_data):
        return encrypted_data

    # Function to add bank account details
    def add_bank_account():
        bank_name = bank_name_entry.get()
        account_number = account_number_entry.get()
        branch = branch_entry.get()
        login_pin = login_pin_entry.get()
        transaction_pin = transaction_pin_entry.get()

        if bank_name and account_number and branch and login_pin.isdigit() and transaction_pin.isdigit():
            encrypted_login_pin = encrypt_data(login_pin)
            encrypted_transaction_pin = encrypt_data(transaction_pin)
            cursor.execute("INSERT INTO bank_accounts (bank_name, account_number, branch, login_pin, transaction_pin) VALUES (?, ?, ?, ?, ?)",
                           (bank_name, account_number, branch, encrypted_login_pin, encrypted_transaction_pin))
            conn.commit()
            load_bank_accounts()
        else:
            status_label.configure(text="All fields are required and PINs must be numeric!", text_color="red")

    # Function to load bank accounts
    def load_bank_accounts():
        bank_account_listbox.delete(0, tk.END)
        cursor.execute("SELECT account_number, bank_name, branch FROM bank_accounts")
        for row in cursor.fetchall():
            bank_account_listbox.insert(tk.END, f"{row[0]} - {str.upper(row[1])} - [{row[2]}]")

    # Function to delete bank account
    def delete_bank_account():
        try:
            selected = bank_account_listbox.get(bank_account_listbox.curselection())
            account_id = selected.split(" - ")[0]
            cursor.execute("DELETE FROM bank_accounts WHERE account_number=?", (account_id,))
            conn.commit()
            load_bank_accounts()
        except:
            status_label.configure(text="Select an account to delete!", text_color="red")

    # Function to show selected bank account details
    def view_bank_account():
        try:
            selected = bank_account_listbox.get(bank_account_listbox.curselection())
            account_id = selected.split(" - ")[0]
            cursor.execute("SELECT * FROM bank_accounts WHERE account_number=?", (account_id,))
            data = cursor.fetchone()
            bank_name_entry.delete(0, tk.END)
            account_number_entry.delete(0, tk.END)
            branch_entry.delete(0, tk.END)
            login_pin_entry.delete(0, tk.END)
            transaction_pin_entry.delete(0, tk.END)

            bank_name_entry.insert(0, data[1])
            account_number_entry.insert(0, data[2])
            branch_entry.insert(0, data[3])
            login_pin_entry.insert(0, decrypt_data(data[4]))  # Decrypt login pin before displaying
            transaction_pin_entry.insert(0, decrypt_data(data[5]))  # Decrypt transaction pin before displaying
        except:
            status_label.configure(text="Select an account to view!", text_color="red")

    # Function to update bank account details
    def update_bank_account():
        try:
            selected = bank_account_listbox.get(bank_account_listbox.curselection())
            account_id = selected.split(" - ")[0]
            bank_name = bank_name_entry.get()
            account_number = account_number_entry.get()
            branch = branch_entry.get()
            login_pin = login_pin_entry.get()
            transaction_pin = transaction_pin_entry.get()

            if bank_name and account_number and branch and login_pin.isdigit() and transaction_pin.isdigit():
                encrypted_login_pin = encrypt_data(login_pin)
                encrypted_transaction_pin = encrypt_data(transaction_pin)
                cursor.execute("UPDATE bank_accounts SET bank_name=?, account_number=?, branch=?, login_pin=?, transaction_pin=? WHERE account_number=?",
                               (bank_name, account_number, branch, encrypted_login_pin, encrypted_transaction_pin, account_id))
                conn.commit()
                load_bank_accounts()
            else:
                status_label.configure(text="All fields are required and PINs must be numeric!", text_color="red")
        except:
            status_label.configure(text="Select an account to update!", text_color="red")

    # UI Components
    # CTkLabel(content_frame, text="Manage Bank Accounts", font=("Arial", 20, "bold")).pack(pady=10)

    input_frame = CTkFrame(content_frame)
    input_frame.pack(pady=5)

    CTkLabel(input_frame, text="Bank Name:").grid(row=0, column=0, padx=5, pady=5)
    bank_name_entry = CTkEntry(input_frame, width=250)
    bank_name_entry.grid(row=0, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Account Number:").grid(row=1, column=0, padx=5, pady=5)
    account_number_entry = CTkEntry(input_frame, width=250)
    account_number_entry.grid(row=1, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Branch:").grid(row=2, column=0, padx=5, pady=5)
    branch_entry = CTkEntry(input_frame, width=250)
    branch_entry.grid(row=2, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Login PIN:").grid(row=3, column=0, padx=5, pady=5)
    login_pin_entry = CTkEntry(input_frame, width=250, show="*")
    login_pin_entry.grid(row=3, column=1, padx=5, pady=5)

    CTkLabel(input_frame, text="Transaction PIN:").grid(row=4, column=0, padx=5, pady=5)
    transaction_pin_entry = CTkEntry(input_frame, width=250, show="*")
    transaction_pin_entry.grid(row=4, column=1, padx=5, pady=5)

    show_login_pin_var = tk.BooleanVar()
    show_login_pin_check = CTkCheckBox(input_frame, text="Show Login PIN", variable=show_login_pin_var, command=lambda: login_pin_entry.configure(show="" if show_login_pin_var.get() else "*"))
    show_login_pin_check.grid(row=5, column=1, pady=5)

    show_transaction_pin_var = tk.BooleanVar()
    show_transaction_pin_check = CTkCheckBox(input_frame, text="Show Transaction PIN", variable=show_transaction_pin_var, command=lambda: transaction_pin_entry.configure(show="" if show_transaction_pin_var.get() else "*"))
    show_transaction_pin_check.grid(row=6, column=1, pady=5)

    button_frame = CTkFrame(content_frame)
    button_frame.pack(pady=5)

    CTkButton(button_frame, text="Add", command=add_bank_account, fg_color="green").grid(row=0, column=0, padx=5)
    CTkButton(button_frame, text="Update", command=update_bank_account, fg_color="blue").grid(row=0, column=1, padx=5)
    CTkButton(button_frame, text="Delete", command=delete_bank_account, fg_color="red").grid(row=0, column=2, padx=5)

    # Listbox to show stored bank accounts
    bank_account_listbox = tk.Listbox(content_frame, width=50, height=10)
    bank_account_listbox.pack(pady=5)

    CTkButton(content_frame, text="View", command=view_bank_account, fg_color="purple").pack()

    # Status label
    status_label = CTkLabel(content_frame, text="", text_color="red")
    status_label.pack()

    # Load existing bank accounts
    load_bank_accounts()

# Sidebar menu items
menu_items = {
    "Logins": logins,
    "Secure Notes": secure_notes,
    "Credit Card": credit_card,
    "Email Accounts": email_acc,
    "Bank Accounts": bank_acc
}

# Create buttons for each menu item
for item, function in menu_items.items():
    btn = CTkButton(menu_bar_frame, text=item, fg_color=button_color, text_color="white",
                    hover_color="#5865F2", corner_radius=5, command=lambda f=function: switch_page(f))
    btn.pack(fill="x", pady=5, padx=10)
    menu_buttons[item] = btn
switch_page(logins)
# Run the main loop
root.mainloop()
