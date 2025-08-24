import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
import secrets
import json
import os
import base64
import cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from master password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def encrypt_password(master_password: str, plaintext: str) -> dict:
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    f = Fernet(key)
    token = f.encrypt(plaintext.encode())
    return {
        "salt": base64.b64encode(salt).decode(),
        "password": token.decode()
    }

def decrypt_password(master_password: str, enc_data: dict) -> str:
    salt = base64.b64decode(enc_data["salt"])
    key = derive_key(master_password, salt)
    f = Fernet(key)
    return f.decrypt(enc_data["password"].encode()).decode()

#Saving the password to file
DATA_FILE = 'Pwrds.json'

if os.path.exists(DATA_FILE):
	with open(DATA_FILE, 'r') as f:
		pass_store = json.load(f)
else:
	pass_store = []

# Check to see if pyperclip is installed
try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-=[];,.!@#$%^&*()_+{}:<>?/'

def genPass():
    try:
        length = int(length_entry.get())
        if length < 6:
            messagebox.showwarning('Password too weak.', 'Please try again.')
            password_var.set('')
            return
        password = secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') + ''.join(
            secrets.choice(chars) for _ in range(length - 1))
        password_var.set(password)
    except ValueError:
        messagebox.showerror('Invalid input', 'Please enter a valid number.')
        password_var.set('')

def copyButton():
    if HAS_PYPERCLIP:
        pyperclip.copy(password_var.get())
        messagebox.showinfo('Password copied', 'Password copied to clipboard.')
    else:
        messagebox.showwarning('Password Generator', 'pyperclip required to copy password.')

# Toggle password visibility
def togPass():
    if password_entry.cget('show') == '':
        # currently visible → hide it
        password_entry.config(show='*')
        toggle_button.config(text='Show')
    else:
        # currently hidden → show it
        password_entry.config(show='')
        toggle_button.config(text='Hide')

#Save the password to DATA_FILE
def savePass():
    password = password_var.get()
    if not password:
        messagebox.showwarning('Missing info', 'Generate a password first.')
        return

    service = simpledialog.askstring("Save Password", "Enter account name:")
    if not service:
        return

    master = simpledialog.askstring("Master Password", "Enter master password:", show='*')
    if not master:
        return

    encrypted_entry = {
        "service": encrypt_password(master, service),
        "data": encrypt_password(master, password)
    }


    pass_store.append(encrypted_entry)
    with open(DATA_FILE, 'w') as f:
        json.dump(pass_store, f, indent=4)

    messagebox.showinfo('Saved', f'Password saved for: {service}')

#Password Manager part
def viewPass():
    if not pass_store:
        messagebox.showinfo('Password Manager', 'No saved passwords.')
        return

    master = simpledialog.askstring("Master Password", "Enter master password:", show='*')
    if not master:
        return

    view_win = tk.Toplevel(window)
    view_win.title('Saved Passwords')
    view_win.geometry('450x400')
    view_win.resizable(False, False)

    frame = tk.Frame(view_win)
    frame.pack(expand=True, fill='both')

    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side='right', fill='y')

    canvas = tk.Canvas(frame, yscrollcommand=scrollbar.set)
    canvas.pack(side='left', fill='both', expand=True)
    scrollbar.config(command=canvas.yview)

    inner_frame = tk.Frame(canvas)
    canvas.create_window((0, 0), window=inner_frame, anchor='nw')

    for i, entry in enumerate(pass_store, start=1):
        try:
            service = decrypt_password(master, entry["service"])
            password = decrypt_password(master, entry["data"])
        except Exception:
            messagebox.showerror("Error", "Wrong master password!")
            service = "???"
            password = "********"
            
        row_frame = tk.Frame(inner_frame)
        row_frame.pack(fill='x', padx=10, pady=2)

        tk.Label(row_frame, text=f'{i}. {service}:', width=20, anchor='w').pack(side='left')

        pwd_entry = tk.Entry(row_frame, font=('Courier', 10))
        pwd_entry.pack(side='left', fill='x', expand=True)
        pwd_entry.insert(0, password)
        pwd_entry.config(state='readonly')

        copy_btn = tk.Button(row_frame, text="Copy", command=lambda p=password: pyperclip.copy(p))
        copy_btn.pack(side='left', padx=5)

    inner_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox('all'))


#Main GUI setup
window = tk.Tk()
window.title('Password Generator')
window.geometry('250x400')
window.resizable(False, False)

tk.Label(window, text='Password length: ', font=('Courier', 14, 'bold')).pack(pady=10)

length_entry = tk.Entry(window, justify='center')
length_entry.pack()

gen_button = tk.Button(window, text='Generate Password', command=genPass, relief='ridge', bd=2)
gen_button.pack(pady=10)

password_var = tk.StringVar()

password_entry = tk.Entry(
    window, textvariable=password_var, font=('Courier', 12, 'bold'),
    fg='black', justify='center', state='readonly', readonlybackground='white'
)
password_entry.pack(pady=5, ipadx=5)

# IMPORTANT: create button and pack on separate lines
toggle_button = tk.Button(window, text='Hide', command=togPass, relief='ridge', bd=2)
toggle_button.pack(pady=5)

password_entry.config(show='*')
toggle_button.config(text='Show')

tk.Button(window, text='Copy', command=copyButton, relief='ridge', bd=2).pack(pady=5)
tk.Button(window, text='Save', command=savePass, relief='ridge', bd=2).pack(pady=5)
tk.Button(window, text='Saved Passwords', command=viewPass, relief='ridge', bd=2).pack(pady=5)
tk.Button(window, text='Exit', command=window.destroy, relief='ridge', bd=2).pack(pady=5)

window.mainloop()
