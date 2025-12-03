import tkinter as tk
from tkinter import ttk, filedialog
import sv_ttk
import os
import threading
import time
from cryptography.exceptions import InvalidTag  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class ModernLogEncryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryptor")
        self.root.geometry("700x650")
        self.root.resizable(False, False)

        sv_ttk.set_theme("dark")

        # --- Variables ---
        self.file_path = tk.StringVar()
        self.password = tk.StringVar()
        self.operation_mode = tk.StringVar(value="encrypt")
        self.password_visible = False
        
        self.setup_ui()

    def setup_ui(self):
        # Main Container
        main_layout = ttk.Frame(self.root, padding=25)
        main_layout.pack(fill=tk.BOTH, expand=True)

        # 1. Title
        title_lbl = ttk.Label(main_layout, text="File Encryptor", font=("Segoe UI Variable Display", 22, "bold"))
        title_lbl.pack(anchor="center", pady=(0, 25))

        # 2. Input Section
        input_frame = ttk.LabelFrame(main_layout, text="Configuration", padding=(20, 20))
        input_frame.pack(fill=tk.X, pady=(0, 20))
        input_frame.columnconfigure(1, weight=1)

        # File
        ttk.Label(input_frame, text="Target File:", width=12).grid(row=0, column=0, sticky="w", pady=(0, 15))
        self.entry_file = ttk.Entry(input_frame, textvariable=self.file_path)
        self.entry_file.grid(row=0, column=1, sticky="ew", padx=(5, 10), pady=(0, 15))
        self.btn_browse = ttk.Button(input_frame, text="Browse...", command=self.browse_file)
        self.btn_browse.grid(row=0, column=2, pady=(0, 15), sticky="ew")

        # Password
        ttk.Label(input_frame, text="Password:", width=12).grid(row=1, column=0, sticky="w", pady=(0, 15))
        self.entry_pass = ttk.Entry(input_frame, textvariable=self.password, show="•")
        self.entry_pass.grid(row=1, column=1, sticky="ew", padx=(5, 10), pady=(0, 15))
        
        # Show/Hide Button
        self.btn_eye = ttk.Button(input_frame, text="Show", command=self.toggle_password_visibility, width=6)
        self.btn_eye.grid(row=1, column=2, sticky="ew", pady=(0, 15))

        # Operation Mode
        ttk.Label(input_frame, text="Operation:", width=12).grid(row=2, column=0, sticky="w")
        radio_frame = ttk.Frame(input_frame)
        radio_frame.grid(row=2, column=1, columnspan=2, sticky="w", padx=5)
        
        r1 = ttk.Radiobutton(radio_frame, text="Encrypt Mode", variable=self.operation_mode, value="encrypt")
        r1.pack(side=tk.LEFT, padx=(0, 20))
        r2 = ttk.Radiobutton(radio_frame, text="Decrypt Mode", variable=self.operation_mode, value="decrypt")
        r2.pack(side=tk.LEFT)

        # 3. Action Button
        self.btn_action = ttk.Button(main_layout, text="START OPERATION", style="Accent.TButton", command=self.start_process)
        self.btn_action.pack(fill=tk.X, pady=(0, 20), ipady=8)

        # 4. Terminal
        log_frame = ttk.LabelFrame(main_layout, text="Process Terminal", padding=2)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        term_container = ttk.Frame(log_frame)
        term_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.scrollbar = ttk.Scrollbar(term_container, orient="vertical")
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_box = tk.Text(
            term_container, height=10, state='disabled', font=("Consolas", 10),
            bg="#181818", fg="#d0d0d0", insertbackground="white", relief="flat",
            highlightthickness=0, yscrollcommand=self.scrollbar.set
        )
        self.log_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.config(command=self.log_box.yview)

        # Colors
        self.log_box.tag_config("INFO", foreground="#58a6ff")   
        self.log_box.tag_config("SUCCESS", foreground="#3fb950") 
        self.log_box.tag_config("ERROR", foreground="#ff7b72")   
        self.log_box.tag_config("WARN", foreground="#d29922")    

        self.log("System Ready.", "INFO")

    # --- UI Logic ---
    def toggle_password_visibility(self):
        if self.password_visible:
            self.entry_pass.config(show="•")
            self.btn_eye.config(text="Show")
            self.password_visible = False
        else:
            self.entry_pass.config(show="")
            self.btn_eye.config(text="Hide")
            self.password_visible = True

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename: self.file_path.set(filename)

    def log(self, message, tag=None):
        def _update():
            self.log_box.configure(state='normal')
            timestamp = time.strftime("[%H:%M:%S] ")
            self.log_box.insert(tk.END, timestamp + message + "\n", tag)
            self.log_box.see(tk.END)
            self.log_box.configure(state='disabled')
        self.root.after(0, _update)

    def toggle_inputs(self, enable):
        state = "normal" if enable else "disabled"
        self.entry_file.config(state=state)
        self.entry_pass.config(state=state)
        self.btn_action.config(state=state)
        self.btn_browse.config(state=state)
        self.btn_eye.config(state=state)

    # --- Encryption Logic ---
    def start_process(self):
        fpath = self.file_path.get()
        pwd = self.password.get()
        mode = self.operation_mode.get()

        if not fpath or not os.path.exists(fpath):
            self.log("File not found.", "ERROR")
            return
        if not pwd:
            self.log("Password cannot be empty.", "ERROR")
            return

        self.toggle_inputs(False)
        self.log_box.configure(state='normal')
        self.log_box.delete(1.0, tk.END)
        self.log_box.configure(state='disabled')
        
        self.log(f"Starting {mode.upper()} process...", "INFO")
        t = threading.Thread(target=self.run_crypto_task, args=(mode, fpath, pwd))
        t.start()

    def run_crypto_task(self, mode, fpath, pwd):
        try:
            start_time = time.time()
            if mode == "encrypt":
                output_path = fpath + ".encrypted"
                self.log(f"Input: {os.path.basename(fpath)}")
                self.log("Generating secure salt and nonce...")
                self.encrypt_logic(fpath, output_path, pwd)
            else:
                if fpath.endswith(".encrypted"): output_path = fpath[:-10]
                else: output_path = fpath + ".decrypted"
                self.log(f"Input: {os.path.basename(fpath)}")
                self.log("Reading header info...")
                self.decrypt_logic(fpath, output_path, pwd)
            
            elapsed = round(time.time() - start_time, 2)
            self.log("-" * 40)
            self.log(f"Operation Complete in {elapsed}s", "SUCCESS")
            self.log(f"Saved: {os.path.basename(output_path)}", "SUCCESS")

        except InvalidTag:
            self.log("Decryption Failed!", "ERROR")
            self.log("The output file contains garbage and will be deleted.", "WARN")
            if 'output_path' in locals() and os.path.exists(output_path):
                try: os.remove(output_path)
                except: pass
        
        except Exception as e:
            self.log(f"{str(e)}", "ERROR")
            if 'output_path' in locals() and os.path.exists(output_path):
                try: os.remove(output_path)
                except: pass
        finally:
            self.root.after(0, lambda: self.toggle_inputs(True))

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=600_000, backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_logic(self, input_file, output_file, password):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self.derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        processed = 0
        with open(output_file, 'wb') as f_out:
            f_out.write(salt); f_out.write(nonce); f_out.write(b'\0' * 16)
            with open(input_file, 'rb') as f_in:
                while True:
                    chunk = f_in.read(1024 * 1024)
                    if not chunk: break
                    f_out.write(encryptor.update(chunk))
                    processed += len(chunk)
                    if processed % (1024 * 1024 * 50) == 0:
                        self.log(f"Processed: {processed // (1024*1024)} MB...")
            f_out.write(encryptor.finalize())
            tag = encryptor.tag
            f_out.seek(16 + 12); f_out.write(tag)
        self.log("Finalizing integrity tag...", "INFO")

    def decrypt_logic(self, input_file, output_file, password):
        with open(input_file, 'rb') as f_in:
            salt = f_in.read(16); nonce = f_in.read(12); tag = f_in.read(16)
            if not salt or not nonce or not tag: raise ValueError("Corrupted header.")
            key = self.derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            with open(output_file, 'wb') as f_out:
                while True:
                    chunk = f_in.read(1024 * 1024)
                    if not chunk: break
                    f_out.write(decryptor.update(chunk))
                f_out.write(decryptor.finalize())

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernLogEncryptor(root)
    root.mainloop()