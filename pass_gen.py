import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")
        self.master.geometry("400x300")

        self.label_length = tk.Label(master, text="Password Length:")
        self.label_length.grid(row=0, column=0, padx=10, pady=10)
        self.length_var = tk.IntVar(value=12)
        self.entry_length = ttk.Spinbox(master, from_=4, to=100, textvariable=self.length_var)
        self.entry_length.grid(row=0, column=1, padx=10, pady=10)

        self.label_complexity = tk.Label(master, text="Complexity:")
        self.label_complexity.grid(row=1, column=0, padx=10, pady=10)
        self.complexity_var = tk.StringVar(value="Medium")
        self.complexity_options = ["Low", "Medium", "High"]
        self.complexity_dropdown = ttk.Combobox(master, values=self.complexity_options, textvariable=self.complexity_var, state="readonly")
        self.complexity_dropdown.grid(row=1, column=1, padx=10, pady=10)

        self.check_uppercase = tk.BooleanVar(value=True)
        self.check_uppercase_checkbox = tk.Checkbutton(master, text="Include Uppercase", variable=self.check_uppercase)
        self.check_uppercase_checkbox.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        self.check_numbers = tk.BooleanVar(value=True)
        self.check_numbers_checkbox = tk.Checkbutton(master, text="Include Numbers", variable=self.check_numbers)
        self.check_numbers_checkbox.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        self.check_symbols = tk.BooleanVar(value=True)
        self.check_symbols_checkbox = tk.Checkbutton(master, text="Include Symbols", variable=self.check_symbols)
        self.check_symbols_checkbox.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        self.btn_generate = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.btn_generate.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        self.btn_copy = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.btn_copy.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

    def generate_password(self):
        length = self.length_var.get()
        complexity = self.complexity_var.get()
        uppercase = self.check_uppercase.get()
        numbers = self.check_numbers.get()
        symbols = self.check_symbols.get()

        if complexity == "Low":
            if uppercase:
                chars = string.ascii_lowercase
            else:
                chars = string.ascii_lowercase + string.ascii_uppercase
        elif complexity == "Medium":
            if uppercase:
                chars = string.ascii_letters
            else:
                chars = string.ascii_letters + string.digits
        elif complexity == "High":
            if uppercase and numbers and symbols:
                chars = string.ascii_letters + string.digits + string.punctuation
            elif uppercase and numbers:
                chars = string.ascii_letters + string.digits
            elif uppercase and symbols:
                chars = string.ascii_letters + string.punctuation
            elif numbers and symbols:
                chars = string.ascii_lowercase + string.digits + string.punctuation
            elif uppercase:
                chars = string.ascii_letters
            elif numbers:
                chars = string.ascii_lowercase + string.digits
            elif symbols:
                chars = string.ascii_lowercase + string.punctuation
            else:
                chars = string.ascii_lowercase

        password = ''.join(random.choice(chars) for _ in range(length))
        messagebox.showinfo("Generated Password", password)

    def copy_to_clipboard(self):
        password = self.generate_password()
        pyperclip.copy(password)
        messagebox.showinfo("Copied to Clipboard", "Password copied to clipboard!")

def main():
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()
