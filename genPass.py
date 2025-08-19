import tkinter as tk
from tkinter import messagebox
import secrets
import pyperclip

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-=[];,.!@#$%^&*()_+{}:<>?/'

def genPass():
	try:
		length = int(length_entry.get())
		if length < 6:
			messagebox.showwarning('Password too weak.', 'Please try again.')
			password_var.set('')
			return
			
		password = secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') + ''.join(
		secrets.choice(chars) for i in range(length - 1))
		password_var.set(password)
		
	except ValueError:
		messagebox.showerror('Invalid input', 'Please enter a valid number.')
		password_var.set('')


def aboutButton():
	messagebox.showinfo('Password Generator', 'By: lynx1349 v0.01')
	
	
def copyButton():
	messagebox.showinfo('Password copied', 'Password copied to clipboard.')
	pyperclip.copy(password_var.get())


#GUI setup
window = tk.Tk()
window.title('Password Generator')
window.geometry('500x300')
window.resizable(False, False)

tk.Label(window, text='Password length: ').pack(pady=10)

length_entry = tk.Entry(window, justify='center')
length_entry.pack()

gen_button = tk.Button(window, text='Generate Password', command=genPass)
gen_button.pack(pady=10)

password_var = tk.StringVar()

password_entry = tk.Entry(window, textvariable=password_var, font=('Courier', 12),
			  fg='green', justify='center', state='readonly', readonlybackground='white')
password_entry.pack(pady=5, ipadx=5)

tk.Button(window, text='Copy', command=copyButton).pack(pady=5)
tk.Button(window, text='About', command=aboutButton).pack(pady=5)
tk.Button(window, text='Exit', command=window.destroy).pack(pady=5)

window.mainloop()
