import tkinter as tk
from tkinter import messagebox
import random
import pyperclip

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-=[];,.!@#$%^&*()_+{}:<>?/'

def genPass():
	try:
		length = int(length_entry.get())
		if length < 6:
			messagebox.showwarning('Password to weak.', 'Please try again.')
			password_var.set('')
			return
			
		password = ''.join(random.choice(chars) for i in range(length))
		password_var.set(password)
		result_var.set('Password copied to clipboard.')
		pyperclip.copy(password)
		
	except ValueError:
		messagebox.showerror('Invalid input', 'Please enter a valid number.')
		password_var.set('')

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

result_var = tk.StringVar()
password_var = tk.StringVar()

password_entry = tk.Entry(window, textvariable=password_var, font=('Courier', 12),
			  fg='green', justify='center', state='readonly', readonlybackground='white')
password_entry.pack(pady=5, ipadx=5)

result_label = tk.Label(window, textvariable=result_var, fg='blue')
result_label.pack(pady=5)

tk.Button(window, text='About', command=window.destroy).pack(pady=5)
tk.Button(window, text='Exit', command=window.destroy).pack(pady=5)

window.mainloop()
