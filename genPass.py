import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
import cryptography
import secrets
import json
import os

#Saving the password to file
DATA_FILE = 'encPass.json'

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
        messagebox.showwarning('Password generator', 'pyperclip required to copy password.')

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

# GUI setup
window = tk.Tk()
window.title('Password Generator')
window.geometry('250x450')
window.resizable(False, False)

tk.Label(window, text='Password length: ').pack(pady=10)

length_entry = tk.Entry(window, justify='center')
length_entry.pack()

gen_button = tk.Button(window, text='Generate Password', command=genPass)
gen_button.pack(pady=10)

password_var = tk.StringVar()

password_entry = tk.Entry(
    window, textvariable=password_var, font=('Courier', 12),
    fg='green', justify='center', state='readonly', readonlybackground='white'
)
password_entry.pack(pady=5, ipadx=5)

#Save the password to DATA_FILE
def savePass():
    password = password_var.get()
    if not password:
        messagebox.showwarning('Missing info', 'Generate a password first.')
        return

    # Ask user for the service/account name in a popup
    service = simpledialog.askstring("Save Password", "Enter account/service name:")
    if not service:
        return  # user cancelled or entered nothing

    pass_store.append((service, password))
    with open(DATA_FILE, 'w') as f:
        json.dump(pass_store, f, indent=4)

    messagebox.showinfo('Saved', f'Password saved for: {service}')


#Password Manager part
def viewPass():
    if not pass_store:
        messagebox.showinfo('Password Manager', 'No saved passwords.')
        return

    view_win = tk.Toplevel(window)
    view_win.title('Saved Passwords')
    view_win.geometry('450x400')
    view_win.resizable(False, False)

    # Frame + scrollbar
    frame = tk.Frame(view_win)
    frame.pack(expand=True, fill='both')

    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side='right', fill='y')

    canvas = tk.Canvas(frame, yscrollcommand=scrollbar.set)
    canvas.pack(side='left', fill='both', expand=True)
    scrollbar.config(command=canvas.yview)

    inner_frame = tk.Frame(canvas)
    canvas.create_window((0, 0), window=inner_frame, anchor='nw')

    for i, (service, password) in enumerate(pass_store, start=1):
        row_frame = tk.Frame(inner_frame)
        row_frame.pack(fill='x', padx=10, pady=2)  # pack vertically

        # Service label
        tk.Label(row_frame, text=f'{i}. {service}:', width=20, anchor='w').pack(side='left')

        # Password entry
        pwd_entry = tk.Entry(row_frame, font=('Courier', 10))
        pwd_entry.pack(side='left', fill='x', expand=True)
        pwd_entry.insert(0, password)
        pwd_entry.config(state='readonly')  # read-only but selectable
        
        copy_btn = tk.Button(row_frame, text="Copy", command=lambda p=password: pyperclip.copy(p))
        copy_btn.pack(side='left', padx=5)

    # Update scroll region
    inner_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox('all'))

	
# IMPORTANT: create button and pack on separate lines
toggle_button = tk.Button(window, text='Hide', command=togPass)
toggle_button.pack(pady=5)

password_entry.config(show='*')
toggle_button.config(text='Show')

tk.Button(window, text='Copy', command=copyButton).pack(pady=5)
tk.Button(window, text='Save', command=savePass).pack(pady=5)
tk.Button(window, text='Saved Passwords', command=viewPass).pack(pady=5)
tk.Button(window, text='Exit', command=window.destroy).pack(pady=5)

window.mainloop()
