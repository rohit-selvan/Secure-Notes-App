import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
import hashlib
import os

key = Fernet.generate_key()
cipher = Fernet(key)
password_file = "password_hash.txt"

class SecureNotesApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Notes App")
        self.geometry("600x500")
        self.configure(bg="#e8f4f8")  
        self.notes_file = "secure_notes.enc"
        self.authenticate_user()
        self.create_widgets()

    def authenticate_user(self):
        if not os.path.exists(password_file):
            self.set_password()
        else:
            self.verify_password()

    def set_password(self):
        password = simpledialog.askstring("Set Password", "Enter a new password:", show="*")
        if password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            with open(password_file, "w") as file:
                file.write(hashed_password)
            messagebox.showinfo("Success", "Password set successfully!")
        else:
            messagebox.showwarning("Password Required", "You must set a password to use the app.")
            self.destroy()

    def verify_password(self):
        password = simpledialog.askstring("Login", "Enter your password:", show="*")
        if password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            with open(password_file, "r") as file:
                stored_hash = file.read().strip()
            if hashed_password != stored_hash:
                messagebox.showerror("Authentication Failed", "Incorrect password. Exiting.")
                self.destroy()
        else:
            messagebox.showwarning("Password Required", "You must enter your password to use the app.")
            self.destroy()

    def create_widgets(self):
        # Title
        tk.Label(self, text="Secure Notes App", font=("Verdana", 24, "bold"), bg="#e8f4f8", fg="#2c3e50").pack(pady=20)
        
        # Textbox for notes
        self.text_area = tk.Text(self, font=("Verdana", 12), height=15, width=70, wrap=tk.WORD)
        self.text_area.pack(pady=10)
        
        # Buttons for Save and Load
        button_frame = tk.Frame(self, bg="#e8f4f8")
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Save Notes", command=self.save_notes, font=("Verdana", 14), bg="#3498db", fg="white", width=15).grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Load Notes", command=self.load_notes, font=("Verdana", 14), bg="#2ecc71", fg="white", width=15).grid(row=0, column=1, padx=10)

    def save_notes(self):
        notes = self.text_area.get("1.0", tk.END).strip()
        if not notes:
            messagebox.showwarning("Empty Notes", "Please write something before saving.")
            return
        try:
            encrypted_notes = cipher.encrypt(notes.encode())
            with open(self.notes_file, "wb") as file:
                file.write(encrypted_notes)
            messagebox.showinfo("Success", "Notes saved securely!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while saving: {str(e)}")

    def load_notes(self):
        if not os.path.exists(self.notes_file):
            messagebox.showwarning("No Notes Found", "No saved notes found.")
            return
        try:
            with open(self.notes_file, "rb") as file:
                encrypted_notes = file.read()
            decrypted_notes = cipher.decrypt(encrypted_notes).decode()
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert(tk.END, decrypted_notes)
            messagebox.showinfo("Success", "Notes loaded successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while loading: {str(e)}")

if __name__ == "__main__":
    app = SecureNotesApp()
    app.mainloop()
