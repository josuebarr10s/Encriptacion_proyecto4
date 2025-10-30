import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.backends import default_backend
import base64


ctk.set_appearance_mode("System")
ctk.set_default_color_theme("dark-blue")  # Azul/lila oscuro elegante


def generate_rsa_keypair(key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key_to_pem(private_key, filepath: str, password: bytes = None):
    encryption = BestAvailableEncryption(password) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    with open(filepath, 'wb') as f:
        f.write(pem)

def save_public_key_to_pem(public_key, filepath: str):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filepath, 'wb') as f:
        f.write(pem)

def load_private_key_from_pem(filepath: str, password: bytes = None):
    with open(filepath, 'rb') as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password, backend=default_backend())

def load_public_key_from_pem(filepath: str):
    with open(filepath, 'rb') as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())

def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_sign(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


class RSAApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔐 RSA Security Tool")
        self.geometry("1300x800")
        self.configure(fg_color="#E6E6FA")  # Fondo lila suave

        self.private_key = None
        self.public_key = None

        self.notebook = ctk.CTkTabview(self, width=1200, height=700)
        self.notebook.pack(pady=20, padx=20, fill="both", expand=True)
        self.notebook.add("Generar Claves")
        self.notebook.add("Cifrar/Descifrar")
        self.notebook.add("Firmar/Verificar")

        self._build_keys_tab()
        self._build_encrypt_tab()
        self._build_sign_tab()

    def _build_keys_tab(self):
        frame = self.notebook.tab("Generar Claves")
        frame.configure(fg_color="#D8BFD8")  # Lila suave

        ctk.CTkLabel(frame, text="Generar Claves RSA", font=("Helvetica", 20, "bold")).pack(pady=15)

        self.keysize_var = ctk.StringVar(value="2048")
        ctk.CTkComboBox(frame, values=["1024", "2048", "3072", "4096"], variable=self.keysize_var, width=180).pack(
            pady=5)

        ctk.CTkButton(frame, text="Generar Claves", command=self.generate_keys,
                      fg_color="#87CEEB", hover_color="#7EC0EE", width=180).pack(pady=15)

        # Estado
        self.priv_status = ctk.CTkLabel(frame, text="Clave Privada: NO cargada", text_color="red")
        self.priv_status.pack(pady=5)
        self.pub_status = ctk.CTkLabel(frame, text="Clave Pública: NO cargada", text_color="red")
        self.pub_status.pack(pady=5)

        # Guardar/Cargar
        btn_frame = ctk.CTkFrame(frame, fg_color="#D8BFD8")
        btn_frame.pack(pady=15)
        ctk.CTkButton(btn_frame, text="Guardar Clave Privada", command=self.save_private_key, fg_color="#9370DB").pack(
            side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Guardar Clave Pública", command=self.save_public_key, fg_color="#9370DB").pack(
            side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Cargar Clave Privada", command=self.load_private_key, fg_color="#6495ED").pack(
            side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Cargar Clave Pública", command=self.load_public_key, fg_color="#6495ED").pack(
            side="left", padx=10)

    def generate_keys(self):
        key_size = int(self.keysize_var.get())
        self.private_key, self.public_key = generate_rsa_keypair(key_size)
        self.priv_status.configure(text=f"Clave Privada: CARGADA ({key_size} bits)", text_color="green")
        self.pub_status.configure(text=f"Clave Pública: CARGADA ({key_size} bits)", text_color="green")
        messagebox.showinfo('Éxito', 'Par de claves RSA generado correctamente.')

    def save_private_key(self):
        if not self.private_key:
            messagebox.showwarning('Atención', 'No hay clave privada cargada.')
            return
        filepath = filedialog.asksaveasfilename(defaultextension='.pem')
        if filepath:
            save_private_key_to_pem(self.private_key, filepath)

    def save_public_key(self):
        if not self.public_key:
            messagebox.showwarning('Atención', 'No hay clave pública cargada.')
            return
        filepath = filedialog.asksaveasfilename(defaultextension='.pem')
        if filepath:
            save_public_key_to_pem(self.public_key, filepath)

    def load_private_key(self):
        filepath = filedialog.askopenfilename(filetypes=[('PEM files', '*.pem')])
        if filepath:
            self.private_key = load_private_key_from_pem(filepath)
            self.priv_status.configure(text=f"Clave Privada: CARGADA", text_color="green")

    def load_public_key(self):
        filepath = filedialog.askopenfilename(filetypes=[('PEM files', '*.pem')])
        if filepath:
            self.public_key = load_public_key_from_pem(filepath)
            self.pub_status.configure(text=f"Clave Pública: CARGADA", text_color="green")

    # -----------------
    # Encrypt / Decrypt Tab
    # -----------------
    def _build_encrypt_tab(self):
        frame = self.notebook.tab("Cifrar/Descifrar")
        frame.configure(fg_color="#E6E6FA")

        ctk.CTkLabel(frame, text="Cifrar / Descifrar", font=("Helvetica", 20, "bold")).pack(pady=15)

        # Entrada
        self.input_text = ctk.CTkTextbox(frame, width=850, height=200, corner_radius=8)
        self.input_text.pack(pady=10)

        btn_frame = ctk.CTkFrame(frame, fg_color="#D8BFD8")
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Abrir Archivo", command=self.open_text_file_for_encrypt,
                      fg_color="#87CEEB").pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Cifrar", command=self.encrypt_text, fg_color="#9370DB").pack(side="left",
                                                                                                    padx=10)
        ctk.CTkButton(btn_frame, text="Descifrar", command=self.decrypt_text, fg_color="#6495ED").pack(side="left",
                                                                                                       padx=10)

        ctk.CTkLabel(frame, text="Salida (Base64)", font=("Helvetica", 16, "bold")).pack(pady=5)
        self.output_text = ctk.CTkTextbox(frame, width=850, height=200, corner_radius=8)
        self.output_text.pack(pady=10)

    def open_text_file_for_encrypt(self):
        filepath = filedialog.askopenfilename(filetypes=[('Text files', '*.txt')])
        if filepath:
            with open(filepath, 'r', encoding='utf-8') as f: data = f.read()
            self.input_text.delete('0.0', 'end')
            self.input_text.insert('0.0', data)

    def encrypt_text(self):
        if not self.public_key: messagebox.showwarning('Atención', 'No hay clave pública'); return
        data = self.input_text.get('0.0', 'end').encode('utf-8')
        ciphertext = rsa_encrypt(self.public_key, data)
        self.output_text.delete('0.0', 'end')
        self.output_text.insert('0.0', base64.b64encode(ciphertext).decode('utf-8'))

    def decrypt_text(self):
        if not self.private_key: messagebox.showwarning('Atención', 'No hay clave privada'); return
        data = base64.b64decode(self.output_text.get('0.0', 'end').encode('utf-8'))
        plaintext = rsa_decrypt(self.private_key, data)
        self.input_text.delete('0.0', 'end')
        self.input_text.insert('0.0', plaintext.decode('utf-8'))

    # -----------------
    # Sign / Verify Tab
    # -----------------
    def _build_sign_tab(self):
        frame = self.notebook.tab("Firmar/Verificar")
        frame.configure(fg_color="#E0FFFF")  # Celeste claro

        ctk.CTkLabel(frame, text="Firmar / Verificar", font=("Helvetica", 20, "bold")).pack(pady=15)

        # Entrada
        self.sign_input_text = ctk.CTkTextbox(frame, width=850, height=200, corner_radius=8)
        self.sign_input_text.pack(pady=10)

        btn_frame = ctk.CTkFrame(frame, fg_color="#D8BFD8")
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Abrir Archivo", command=self.open_file_for_sign, fg_color="#87CEEB").pack(
            side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Firmar", command=self.sign_message, fg_color="#9370DB").pack(side="left",
                                                                                                    padx=10)
        ctk.CTkButton(btn_frame, text="Verificar", command=self.verify_signature, fg_color="#6495ED").pack(side="left",
                                                                                                           padx=10)

        ctk.CTkLabel(frame, text="Firma (Base64)", font=("Helvetica", 16, "bold")).pack(pady=5)
        self.signature_text = ctk.CTkTextbox(frame, width=850, height=200, corner_radius=8)
        self.signature_text.pack(pady=10)

    def open_file_for_sign(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            with open(filepath, 'r', encoding='utf-8') as f: data = f.read()
            self.sign_input_text.delete('0.0', 'end')
            self.sign_input_text.insert('0.0', data)

    def sign_message(self):
        if not self.private_key: messagebox.showwarning('Atención', 'No hay clave privada'); return
        data = self.sign_input_text.get('0.0', 'end').encode('utf-8')
        signature = rsa_sign(self.private_key, data)
        self.signature_text.delete('0.0', 'end')
        self.signature_text.insert('0.0', base64.b64encode(signature).decode('utf-8'))

    def verify_signature(self):
        if not self.public_key: messagebox.showwarning('Atención', 'No hay clave pública'); return
        data = self.sign_input_text.get('0.0', 'end').encode('utf-8')
        signature = base64.b64decode(self.signature_text.get('0.0', 'end').encode('utf-8'))
        valid = rsa_verify(self.public_key, data, signature)
        messagebox.showinfo('Verificación', 'Firma VÁLIDA' if valid else 'Firma NO válida')


# -----------------
# Main
# -----------------
if __name__ == '__main__':
    app = RSAApp()
    app.mainloop()