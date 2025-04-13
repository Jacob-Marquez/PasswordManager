import tkinter as tk
from tkinter import messagebox, simpledialog
from password_manager import PasswordManager
from generator import generate_password

class PasswordManagerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("500x400")
        self.pm = PasswordManager()
        self.conn = None

        self.login_frame = LoginFrame(self)
        self.vault_frame = None

    def show_vault(self):
        self.login_frame.pack_forget()
        self.vault_frame = VaultFrame(self, self.pm, self.conn)
        self.vault_frame.pack(fill="both", expand=True)

class LoginFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        tk.Label(self, text="Master Password").pack(pady=10)
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(self, text="Login", command=self.login).pack(pady=5)
        tk.Button(self, text="Create Account", command=self.create_account).pack(pady=5)

        self.pack()

    def login(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter your master password.")
            return

        self.master.pm.user_password = password
        self.master.pm.access_account()
        if self.master.pm.encryption_key:
            self.master.conn = self.master.pm.connect_database()
            self.master.show_vault()

    def create_account(self):
        choice = messagebox.askquestion("Password Option", "Generate secure master password?")
        if choice == 'yes':
            master_password = generate_password(16).decode('utf-8')
            messagebox.showinfo("Generated Password", f"Your master password is:\n{master_password}\nPlease save it securely.")
        else:
            master_password = simpledialog.askstring("Create Password", "Enter a 16 character master password:", show="*")

        if master_password:
            self.master.pm.create_account(master_password)
            if self.master.pm.encryption_key:
                self.master.conn = self.master.pm.connect_database()
                self.master.show_vault()

class VaultFrame(tk.Frame):
    def __init__(self, master, pm, conn):
        super().__init__(master)
        self.master = master
        self.pm = pm
        self.conn = conn

        tk.Label(self, text="Stored Entries").pack()
        self.entries_box = tk.Text(self, height=15, width=60)
        self.entries_box.pack(pady=10)
        self.load_entries()

        tk.Button(self, text="Add Entry", command=self.add_entry).pack()
        tk.Button(self, text="Logout", command=self.logout).pack(pady=5)

    def load_entries(self):
        self.entries_box.delete(1.0, tk.END)
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT id, platform, username, password FROM vault")
            for row in cursor.fetchall():
                try:
                    decrypted = self.pm.decrypt_data(row[3], self.pm.encryption_key)
                    self.entries_box.insert(tk.END, f"ID: {row[0]}, Platform: {row[1]}, Username: {row[2]}, Password: {decrypted}\n")
                except Exception as e:
                    self.entries_box.insert(tk.END, f"Could not decrypt entry ID {row[0]}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def add_entry(self):
        platform = simpledialog.askstring("Platform", "Enter platform name:")
        username = simpledialog.askstring("Username", "Enter username/email:")
        choice = messagebox.askquestion("Password", "Generate password?")
        if choice == 'yes':
            password = generate_password(16).decode('utf-8')
        else:
            password = simpledialog.askstring("Password", "Enter password:", show="*")

        if platform and username and password:
            if not self.pm.encryption_key:
                messagebox.showerror("Error", "Encryption key not available.")
                return
            encrypted = PasswordManager.encrypt_entry(password, self.pm.encryption_key)
            cursor = self.conn.cursor()
            cursor.execute("INSERT INTO vault (platform, username, password) VALUES (?, ?, ?)", (platform, username, encrypted))
            self.conn.commit()
            self.load_entries()

    def logout(self):
        self.pm.encryption_key = None
        self.pack_forget()
        self.master.login_frame.pack()