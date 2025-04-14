import tkinter as tk
from tkinter import messagebox, simpledialog
from password_manager import PasswordManager
from generator import generate_password

class PasswordManagerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("600x500")
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
        tk.Label(self, text="Master Password", font=("Arial", 14)).pack(pady=10)
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
        try:
            self.master.conn = self.master.pm.access_account_gui(password)
            self.master.show_vault()
        except Exception as e:
            messagebox.showerror("Login Error", str(e))

    def create_account(self):
        choice = messagebox.askquestion("Password Option", "Generate secure master password?")
        if choice == 'yes':
            master_password = generate_password(16).decode('utf-8')
            self.show_generated_password(master_password)
        else:
            master_password = simpledialog.askstring("Create Password",
                                                     "Enter a 16 character master password:",
                                                     show="*")
        if master_password:
            try:
                conn = self.master.pm.create_account(master_password)
                if self.master.pm.encryption_key:
                    self.master.conn = conn
                    self.master.show_vault()
            except Exception as e:
                messagebox.showerror("Account Creation Error", str(e))

    def show_generated_password(self, master_password):
        top = tk.Toplevel(self)
        top.title("Generated Master Password")
        tk.Label(top, text="Your generated master password is:").pack(pady=5)
        password_entry = tk.Entry(top, width=50)
        password_entry.insert(0, master_password)
        password_entry.config(state="readonly")
        password_entry.pack(pady=5)
        tk.Button(top, text="Copy to Clipboard",
                  command=lambda: self.copy_to_clipboard(master_password)).pack(pady=5)
        tk.Button(top, text="OK", command=top.destroy).pack(pady=5)

    def copy_to_clipboard(self, text):
        self.master.clipboard_clear()
        self.master.clipboard_append(text)
        messagebox.showinfo("Copied", "Master password copied to clipboard.")

class VaultFrame(tk.Frame):
    INACTIVITY_TIMEOUT = 300000  # 5 minutes in milliseconds

    def __init__(self, master, pm, conn):
        super().__init__(master)
        self.master = master
        self.pm = pm
        self.conn = conn
        tk.Label(self, text="Stored Entries", font=("Arial", 14)).pack(pady=10)
        self.entries_listbox = tk.Listbox(self, width=80, height=15)
        self.entries_listbox.pack(pady=10)
        self.load_entries()
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Add Entry", command=self.add_entry).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Update Entry", command=self.update_entry).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Delete Entry", command=self.delete_entry).grid(row=0, column=2, padx=5)
        tk.Button(btn_frame, text="Logout", command=self.logout).grid(row=0, column=3, padx=5)
        # Set up inactivity timer.
        self.inactivity_id = self.after(self.INACTIVITY_TIMEOUT, self.auto_logout)
        self.bind_all("<Any-KeyPress>", self.reset_timer)
        self.bind_all("<Any-Button>", self.reset_timer)

    def reset_timer(self, event=None):
        if self.inactivity_id:
            self.after_cancel(self.inactivity_id)
        self.inactivity_id = self.after(self.INACTIVITY_TIMEOUT, self.auto_logout)

    def auto_logout(self):
        messagebox.showinfo("Session Timeout", "No activity detected. Logging out for security.")
        self.logout()

    def load_entries(self):
        self.entries_listbox.delete(0, tk.END)
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT id, platform, username, password FROM vault")
            rows = cursor.fetchall()
            for row in rows:
                try:
                    decrypted_platform = self.pm.decrypt_data(row[1], self.pm.encryption_key)
                    decrypted_username = self.pm.decrypt_data(row[2], self.pm.encryption_key)
                    decrypted_password = self.pm.decrypt_data(row[3], self.pm.encryption_key)
                    entry_str = (f"ID: {row[0]} | Platform: {decrypted_platform} | "
                                 f"Username: {decrypted_username} | Password: {decrypted_password}")
                except Exception:
                    entry_str = f"ID: {row[0]} | [Decryption Error]"
                self.entries_listbox.insert(tk.END, entry_str)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def add_entry(self):
        platform = simpledialog.askstring("Platform", "Enter platform name:")
        username = simpledialog.askstring("Username", "Enter username/email:")
        if not (platform and username):
            messagebox.showwarning("Input Error", "Platform and Username cannot be empty.")
            return

        choice = messagebox.askquestion("Password", "Generate password?")
        if choice == 'yes':
            password = generate_password(16).decode('utf-8')
        else:
            password = simpledialog.askstring("Password", "Enter password:", show="*")

        if not password:
            messagebox.showwarning("Input Error", "Password cannot be empty.")
            return
        if not self.pm.encryption_key:
            messagebox.showerror("Error", "Encryption key not available.")
            return

        try:
            # Encrypt all fields before storing.
            encrypted_platform = self.pm.encrypt_entry(platform, self.pm.encryption_key)
            encrypted_username = self.pm.encrypt_entry(username, self.pm.encryption_key)
            encrypted_password = self.pm.encrypt_entry(password, self.pm.encryption_key)
            cursor = self.conn.cursor()
            cursor.execute("INSERT INTO vault (platform, username, password) VALUES (?, ?, ?)",
                           (encrypted_platform, encrypted_username, encrypted_password))
            self.conn.commit()
            self.load_entries()
            messagebox.showinfo("Success", "Entry added successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update_entry(self):
        entry_id = simpledialog.askinteger("Update Entry", "Enter the ID of the entry you want to update:")
        if entry_id is None:
            return

        update_choice = simpledialog.askstring("Update Options",
            "Enter '1' to update Username, '2' to update Password, '3' for both:")
        if update_choice not in ['1', '2', '3']:
            messagebox.showwarning("Input Error", "Invalid choice.")
            return
        
        new_username = None
        new_password = None
        if update_choice in ['1', '3']:
            new_username = simpledialog.askstring("New Username", "Enter new username:")
        if update_choice in ['2', '3']:
            pwd_choice = messagebox.askquestion("Password", "Generate new password?")
            if pwd_choice == 'yes':
                new_password = generate_password(16).decode('utf-8')
            else:
                new_password = simpledialog.askstring("New Password", "Enter new password:", show="*")
        
        try:
            cursor = self.conn.cursor()
            if new_username and new_password:
                encrypted_username = self.pm.encrypt_entry(new_username, self.pm.encryption_key)
                encrypted_password = self.pm.encrypt_entry(new_password, self.pm.encryption_key)
                cursor.execute("UPDATE vault SET username = ?, password = ? WHERE id = ?",
                               (encrypted_username, encrypted_password, entry_id))
            elif new_username:
                encrypted_username = self.pm.encrypt_entry(new_username, self.pm.encryption_key)
                cursor.execute("UPDATE vault SET username = ? WHERE id = ?",
                               (encrypted_username, entry_id))
            elif new_password:
                encrypted_password = self.pm.encrypt_entry(new_password, self.pm.encryption_key)
                cursor.execute("UPDATE vault SET password = ? WHERE id = ?",
                               (encrypted_password, entry_id))
            else:
                messagebox.showinfo("Update Cancelled", "No fields to update.")
                return
            self.conn.commit()
            self.load_entries()
            messagebox.showinfo("Success", "Entry updated successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_entry(self):
        entry_id = simpledialog.askinteger("Delete Entry", "Enter the ID of the entry you want to delete:")
        if entry_id is None:
            return
        confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete entry ID {entry_id}?")
        if not confirm:
            return
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
            self.conn.commit()
            self.load_entries()
            messagebox.showinfo("Deleted", "Entry deleted successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def logout(self):
        if self.inactivity_id:
            self.after_cancel(self.inactivity_id)
        # Wipe the encryption key from memory.
        self.pm.encryption_key = None
        self.destroy()
        self.master.login_frame = LoginFrame(self.master)
