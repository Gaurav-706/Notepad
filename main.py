import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
from cryptography.fernet import Fernet
import base64
import hashlib

class Notepad:
    def __init__(self, root):
        self.root = root
        self.root.title("Untitled - Notepad")
        self.root.geometry("600x400")

        self.text_area = tk.Text(self.root, undo=True)
        self.text_area.pack(fill=tk.BOTH, expand=1)

        self.file = None

        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        # File Menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="New", command=self.new_file)
        self.file_menu.add_command(label="Open", command=self.open_file)
        self.file_menu.add_command(label="Save", command=self.save_file)
        self.file_menu.add_command(label="Save as Private", command=self.save_private)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.exit_app)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)

        # Edit Menu
        self.edit_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.edit_menu.add_command(label="Cut", command=lambda: self.text_area.event_generate("<<Cut>>"))
        self.edit_menu.add_command(label="Copy", command=lambda: self.text_area.event_generate("<<Copy>>"))
        self.edit_menu.add_command(label="Paste", command=lambda: self.text_area.event_generate("<<Paste>>"))
        self.menu_bar.add_cascade(label="Edit", menu=self.edit_menu)

        # Help Menu
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.help_menu.add_command(label="About Notepad", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)

        # Scrollbar
        self.scroll_bar = tk.Scrollbar(self.text_area)
        self.scroll_bar.pack(side=tk.RIGHT, fill=tk.Y)
        self.scroll_bar.config(command=self.text_area.yview)
        self.text_area.config(yscrollcommand=self.scroll_bar.set)

    def new_file(self):
        self.root.title("Untitled - Notepad")
        self.file = None
        self.text_area.delete(1.0, tk.END)

    def open_file(self):
        file_path = filedialog.askopenfilename(defaultextension=".txt",
                                               filetypes=[("All Files", "*.*"),
                                                          ("Text Documents", "*.txt")])
        if file_path:
            try:
                with open(file_path, "r") as file:
                    self.text_area.delete(1.0, tk.END)
                    self.text_area.insert(1.0, file.read())
                self.file = file_path
                self.root.title(f"{os.path.basename(file_path)} - Notepad")
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file: {e}")

    def save_file(self):
        if self.file:
            try:
                with open(self.file, "w") as file:
                    file.write(self.text_area.get(1.0, tk.END))
                self.root.title(f"{os.path.basename(self.file)} - Notepad")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file: {e}")
        else:
            self.save_as_file()

    def save_as_file(self):
        file_path = filedialog.asksaveasfilename(initialfile='Untitled.txt',
                                                 defaultextension=".txt",
                                                 filetypes=[("All Files", "*.*"),
                                                            ("Text Documents", "*.txt")])
        if file_path:
            try:
                with open(file_path, "w") as file:
                    file.write(self.text_area.get(1.0, tk.END))
                self.file = file_path
                self.root.title(f"{os.path.basename(file_path)} - Notepad")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file: {e}")

    def save_private(self):
        password = simpledialog.askstring("Password", "Enter a password for encryption:", show='*')
        if password:
            key = self.generate_key(password)
            fernet = Fernet(key)
            data = self.text_area.get(1.0, tk.END).encode()
            encrypted = fernet.encrypt(data)

            private_dir = "private_notes"
            if not os.path.exists(private_dir):
                os.makedirs(private_dir)

            file_path = filedialog.asksaveasfilename(initialdir=private_dir,
                                                     title="Save Private Note",
                                                     defaultextension=".enc",
                                                     filetypes=[("Encrypted Files", "*.enc")])
            if file_path:
                try:
                    with open(file_path, "wb") as file:
                        file.write(encrypted)
                    messagebox.showinfo("Success", "Note saved as private successfully.")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not save private note: {e}")

    def generate_key(self, password):
        hash = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(hash)

    def exit_app(self):
        self.root.quit()

    def show_about(self):
        messagebox.showinfo("About Notepad", "Notepad Application with Private Notes Feature\nDeveloped by Gaurav Maurya")

if __name__ == "__main__":
    root = tk.Tk()
    notepad_app = Notepad(root)
    root.mainloop()
