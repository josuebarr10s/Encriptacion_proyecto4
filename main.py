# rsa_app_final.py
import os
import base64
import traceback
import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

COLORS = {
    "primary": "#2E86AB",
    "secondary": "#A23B72",
    "success": "#27AE60",
    "warning": "#F39C12",
    "danger": "#E74C3C",
    "light": "#ECF0F1",
    "dark": "#2C3E50",
    "accent": "#3498DB",
    "background": "#F8F9FA",
    "card": "#FFFFFF",
}

KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)


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

# RSA basic ops
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


def hybrid_encrypt(public_key, data: bytes) -> dict:
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    encrypted_key = rsa_encrypt(public_key, aes_key)
    return {
        "key": base64.b64encode(encrypted_key).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def hybrid_decrypt(private_key, envelope: dict) -> bytes:
    encrypted_key = base64.b64decode(envelope["key"])
    aes_key = rsa_decrypt(private_key, encrypted_key)
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext


AUTO_PRIV = os.path.join(KEY_DIR, "private_auto.pem")
AUTO_PUB = os.path.join(KEY_DIR, "public_auto.pem")

def auto_save_keys(private_key, public_key, password: bytes = None):
    try:
        save_private_key_to_pem(private_key, AUTO_PRIV, password=password)
        save_public_key_to_pem(public_key, AUTO_PUB)
    except Exception:
        pass

def auto_load_keys():
    priv = None
    pub = None
    try:
        if os.path.exists(AUTO_PRIV):
            try:
                priv = load_private_key_from_pem(AUTO_PRIV, password=None)
            except Exception:
                # Si está cifrada, pedimos contraseña
                pwd = simpledialog.askstring("Contraseña", "Ingrese la contraseña para la clave privada (auto):", show='*')
                if pwd is not None:
                    priv = load_private_key_from_pem(AUTO_PRIV, password=pwd.encode('utf-8'))
        if os.path.exists(AUTO_PUB):
            pub = load_public_key_from_pem(AUTO_PUB)
    except Exception:
        # Si falla la carga automática no interrumpimos
        pass
    return priv, pub


class RSAApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔐 RSA Security Tool")
        self.geometry("1200x700")
        self.minsize(1000, 600)
        self.configure(fg_color=COLORS["background"])

        self.private_key = None
        self.public_key = None

        # Intentar cargar últimas claves automáticamente
        loaded_priv, loaded_pub = auto_load_keys()
        if loaded_priv:
            self.private_key = loaded_priv
        if loaded_pub:
            self.public_key = loaded_pub

        # Layout base
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.main_frame = ctk.CTkFrame(self, fg_color=COLORS["background"])
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Header
        header_frame = ctk.CTkFrame(self.main_frame, fg_color=COLORS["primary"], height=70)
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 10))
        header_frame.grid_columnconfigure(0, weight=1)
        header_frame.grid_propagate(False)

        ctk.CTkLabel(header_frame, text="🔐 HERRAMIENTA DE SEGURIDAD RSA",
                     font=("Arial", 20, "bold"), text_color="white").pack(expand=True, pady=20)

        # Theme toggle (light/dark)
        theme_btn = ctk.CTkButton(header_frame, text="🌓", width=40, command=self.toggle_theme,
                                  fg_color=COLORS["secondary"], hover_color=COLORS["accent"])
        theme_btn.pack(side="right", padx=12)

        # Notebook
        self.notebook = ctk.CTkTabview(self.main_frame, fg_color=COLORS["card"],
                                       segmented_button_fg_color=COLORS["primary"],
                                       segmented_button_selected_color=COLORS["accent"])
        self.notebook.grid(row=1, column=0, sticky="nsew")
        self.notebook.grid_columnconfigure(0, weight=1)
        self.notebook.grid_rowconfigure(0, weight=1)

        self.notebook.add("🔑 Generar Claves")
        self.notebook.add("📧 Cifrar/Descifrar")
        self.notebook.add("✍️ Firmar/Verificar")

        # Configurar tabs
        for tab_name in ["🔑 Generar Claves", "📧 Cifrar/Descifrar", "✍️ Firmar/Verificar"]:
            tab = self.notebook.tab(tab_name)
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)

        # Construir secciones
        self._build_keys_tab()
        self._build_encrypt_tab()
        self._build_sign_tab()

        # Footer
        footer_frame = ctk.CTkFrame(self.main_frame, fg_color=COLORS["light"], height=40)
        footer_frame.grid(row=2, column=0, sticky="ew", padx=0, pady=(10, 0))
        footer_frame.grid_columnconfigure(0, weight=1)
        footer_frame.grid_propagate(False)

        ctk.CTkLabel(footer_frame, text="© 2024 RSA Security Tool",
                     text_color=COLORS["dark"], font=("Arial", 10)).pack(expand=True, pady=10)


    def _build_keys_tab(self):
        frame = self.notebook.tab("🔑 Generar Claves")
        frame.configure(fg_color=COLORS["card"])
        frame.grid_columnconfigure(0, weight=1)

        container = ctk.CTkScrollableFrame(frame, fg_color=COLORS["card"])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.grid_columnconfigure(0, weight=1)

        title_frame = ctk.CTkFrame(container, fg_color=COLORS["light"], corner_radius=8)
        title_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        ctk.CTkLabel(title_frame, text="Generación de Claves RSA",
                     font=("Arial", 18, "bold"), text_color=COLORS["dark"]).pack(pady=15)

        config_frame = ctk.CTkFrame(container, fg_color=COLORS["card"], corner_radius=8)
        config_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        config_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(config_frame, text="Tamaño de Clave:",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(pady=5)

        self.keysize_var = ctk.StringVar(value="2048")
        key_combo = ctk.CTkComboBox(config_frame, values=["1024", "2048", "3072", "4096"],
                                    variable=self.keysize_var, width=200)
        key_combo.pack(pady=10)

        ctk.CTkButton(container, text="🔄 Generar Claves", command=self.generate_keys,
                      fg_color=COLORS["success"], hover_color="#219955",
                      font=("Arial", 14, "bold"), height=40).grid(row=2, column=0, sticky="ew", padx=10, pady=10)

        status_frame = ctk.CTkFrame(container, fg_color=COLORS["light"], corner_radius=8)
        status_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        status_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(status_frame, text="Estado de las Claves:",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(pady=10)

        self.priv_status = ctk.CTkLabel(status_frame, text="🔒 Clave Privada: NO CARGADA",
                                        text_color=COLORS["danger"], font=("Arial", 12))
        self.priv_status.pack(pady=5)

        self.pub_status = ctk.CTkLabel(status_frame, text="🔓 Clave Pública: NO CARGADA",
                                       text_color=COLORS["danger"], font=("Arial", 12))
        self.pub_status.pack(pady=5)

        action_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        action_frame.grid(row=4, column=0, sticky="ew", padx=10, pady=10)
        action_frame.grid_columnconfigure(0, weight=1)
        action_frame.grid_columnconfigure(1, weight=1)

        # Guardar
        ctk.CTkButton(action_frame, text="💾 Guardar Privada", command=self.save_private_key,
                      fg_color=COLORS["primary"], width=160).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(action_frame, text="💾 Guardar Pública", command=self.save_public_key,
                      fg_color=COLORS["primary"], width=160).grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Cargar
        ctk.CTkButton(action_frame, text="📂 Cargar Privada", command=self.load_private_key,
                      fg_color=COLORS["secondary"], width=160).grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(action_frame, text="📂 Cargar Pública", command=self.load_public_key,
                      fg_color=COLORS["secondary"], width=160).grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # Mostrar estados si se cargaron automáticamente
        if self.private_key:
            self.priv_status.configure(text="✅ Privada: CARGADA (auto)", text_color=COLORS["success"])
        if self.public_key:
            self.pub_status.configure(text="✅ Pública: CARGADA (auto)", text_color=COLORS["success"])


    def generate_keys(self):
        try:
            key_size = int(self.keysize_var.get())
            self.private_key, self.public_key = generate_rsa_keypair(key_size)
            # Auto-guardar (sin contraseña)
            auto_save_keys(self.private_key, self.public_key, password=None)
            self.priv_status.configure(text=f"✅ Privada: CARGADA ({key_size} bits)", text_color=COLORS["success"])
            self.pub_status.configure(text=f"✅ Pública: CARGADA ({key_size} bits)", text_color=COLORS["success"])
            messagebox.showinfo('Éxito', f'Claves RSA de {key_size} bits generadas y guardadas automáticamente.')
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror('Error', f'Error al generar claves: {str(e)}')

    def save_private_key(self):
        if not self.private_key:
            messagebox.showwarning('Atención', 'No hay clave privada cargada.')
            return
        # Preguntar si quiere proteger con contraseña
        pwd = simpledialog.askstring("Contraseña (opcional)", "Ingrese contraseña para proteger la clave privada (dejar vacío = sin contraseña):", show='*')
        filepath = filedialog.asksaveasfilename(defaultextension='.pem', title="Guardar Clave Privada")
        if filepath:
            try:
                if pwd:
                    save_private_key_to_pem(self.private_key, filepath, password=pwd.encode('utf-8'))
                else:
                    save_private_key_to_pem(self.private_key, filepath)
                messagebox.showinfo('Éxito', 'Clave privada guardada.')
            except Exception as e:
                traceback.print_exc()
                messagebox.showerror('Error', f'No se pudo guardar la clave privada: {str(e)}')

    def save_public_key(self):
        if not self.public_key:
            messagebox.showwarning('Atención', 'No hay clave pública cargada.')
            return
        filepath = filedialog.asksaveasfilename(defaultextension='.pem', title="Guardar Clave Pública")
        if filepath:
            try:
                save_public_key_to_pem(self.public_key, filepath)
                messagebox.showinfo('Éxito', 'Clave pública guardada.')
            except Exception as e:
                traceback.print_exc()
                messagebox.showerror('Error', f'No se pudo guardar la clave pública: {str(e)}')

    def load_private_key(self):
        filepath = filedialog.askopenfilename(filetypes=[('PEM files', '*.pem')], title="Cargar Clave Privada")
        if filepath:
            try:
                # Intentar sin contraseña
                try:
                    self.private_key = load_private_key_from_pem(filepath, password=None)
                except Exception:
                    pwd = simpledialog.askstring("Contraseña", "La clave está protegida. Ingrese la contraseña:", show='*')
                    if pwd is None:
                        return
                    self.private_key = load_private_key_from_pem(filepath, password=pwd.encode('utf-8'))
                self.priv_status.configure(text="✅ Privada: CARGADA", text_color=COLORS["success"])
                messagebox.showinfo('Éxito', 'Clave privada cargada.')
                # auto-save loaded as last used (no password)
                try:
                    auto_save_keys(self.private_key, self.public_key, password=None)
                except Exception:
                    pass
            except Exception as e:
                traceback.print_exc()
                messagebox.showerror('Error', f'Error al cargar la clave privada: {str(e)}')

    def load_public_key(self):
        filepath = filedialog.askopenfilename(filetypes=[('PEM files', '*.pem')], title="Cargar Clave Pública")
        if filepath:
            try:
                self.public_key = load_public_key_from_pem(filepath)
                self.pub_status.configure(text="✅ Pública: CARGADA", text_color=COLORS["success"])
                messagebox.showinfo('Éxito', 'Clave pública cargada.')
                # auto-save loaded as last used
                try:
                    auto_save_keys(self.private_key, self.public_key, password=None)
                except Exception:
                    pass
            except Exception as e:
                traceback.print_exc()
                messagebox.showerror('Error', f'Error al cargar la clave pública: {str(e)}')


    def _build_encrypt_tab(self):
        frame = self.notebook.tab("📧 Cifrar/Descifrar")
        frame.configure(fg_color=COLORS["card"])
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        container = ctk.CTkScrollableFrame(frame, fg_color=COLORS["card"])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.grid_columnconfigure(0, weight=1)

        title_frame = ctk.CTkFrame(container, fg_color=COLORS["light"], corner_radius=8)
        title_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        ctk.CTkLabel(title_frame, text="Cifrado y Descifrado",
                     font=("Arial", 18, "bold"), text_color=COLORS["dark"]).pack(pady=15)

        input_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        input_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        input_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(input_frame, text="📝 Texto Original:",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.input_text = ctk.CTkTextbox(input_frame, height=120, corner_radius=8,
                                         fg_color=COLORS["light"], border_color=COLORS["primary"])
        self.input_text.pack(fill="x", pady=5)

        btn_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        btn_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)
        btn_frame.grid_columnconfigure(2, weight=1)

        ctk.CTkButton(btn_frame, text="📂 Abrir Archivo", command=self.open_text_file_for_encrypt,
                      fg_color=COLORS["accent"], height=35).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(btn_frame, text="🔒 Cifrar Texto", command=self.encrypt_text,
                      fg_color=COLORS["success"], height=35).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(btn_frame, text="🔓 Descifrar Texto", command=self.decrypt_text,
                      fg_color=COLORS["warning"], height=35).grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        # Botones para archivos
        ctk.CTkButton(btn_frame, text="📁 Cifrar Archivo", command=self.encrypt_file,
                      fg_color=COLORS["secondary"], height=35).grid(row=1, column=0, columnspan=3, padx=5, pady=8, sticky="ew")

        # Salida
        output_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        output_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        output_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(output_frame, text="📄 Texto Cifrado/Envelope (Base64 JSON):",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.output_text = ctk.CTkTextbox(output_frame, height=120, corner_radius=8,
                                          fg_color=COLORS["light"], border_color=COLORS["secondary"])
        self.output_text.pack(fill="x", pady=5)

        # Limpiar campos
        ctk.CTkButton(container, text="🧹 Limpiar Campos", command=self.clear_encrypt_fields,
                      fg_color=COLORS["danger"], height=36).grid(row=4, column=0, padx=10, pady=8, sticky="e")


    def open_text_file_for_encrypt(self):
        filepath = filedialog.askopenfilename(filetypes=[('Text files', '*.txt'), ('All files', '*.*')])
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = f.read()
                self.input_text.delete('0.0', 'end')
                self.input_text.insert('0.0', data)
            except Exception as e:
                traceback.print_exc()
                messagebox.showerror('Error', f'No se pudo leer el archivo: {str(e)}')

    def encrypt_text(self):
        if not self.public_key:
            messagebox.showwarning('Atención', 'No hay clave pública cargada.')
            return
        data = self.input_text.get('0.0', 'end').strip().encode('utf-8')
        if not data:
            messagebox.showwarning('Atención', 'No hay texto para cifrar.')
            return
        try:
            envelope = hybrid_encrypt(self.public_key, data)
            envelope_json = {
                "key": envelope["key"],
                "nonce": envelope["nonce"],
                "ciphertext": envelope["ciphertext"]
            }
            # mostrar como JSON base64-friendly (string)
            import json as _json
            self.output_text.delete('0.0', 'end')
            self.output_text.insert('0.0', _json.dumps(envelope_json))
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror('Error', f'Error al cifrar: {str(e)}')

    def decrypt_text(self):
        if not self.private_key:
            messagebox.showwarning('Atención', 'No hay clave privada cargada.')
            return
        try:
            raw = self.output_text.get('0.0', 'end').strip()
            if not raw:
                messagebox.showwarning('Atención', 'No hay texto cifrado en la salida.')
                return
            import json as _json
            envelope = _json.loads(raw)
            plaintext = hybrid_decrypt(self.private_key, envelope)
            self.input_text.delete('0.0', 'end')
            try:
                self.input_text.insert('0.0', plaintext.decode('utf-8'))
            except Exception:
                # si no es texto UTF-8, mostrar info
                self.input_text.insert('0.0', plaintext)
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror('Error', f'Error al descifrar: {str(e)}')

    def encrypt_file(self):
        if not self.public_key:
            messagebox.showwarning('Atención', 'No hay clave pública cargada.')
            return
        filepath = filedialog.askopenfilename(title="Seleccionar archivo para cifrar")
        if not filepath:
            return
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            envelope = hybrid_encrypt(self.public_key, data)
            import json as _json
            save_path = filedialog.asksaveasfilename(defaultextension='.enc.json', title="Guardar archivo cifrado")
            if save_path:
                with open(save_path, "w", encoding="utf-8") as out:
                    _json.dump(envelope, out)
                messagebox.showinfo("Éxito", f"Archivo cifrado guardado en:\n{save_path}")
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror('Error', f'Error al cifrar archivo: {str(e)}')

    def clear_encrypt_fields(self):
        self.input_text.delete('0.0', 'end')
        self.output_text.delete('0.0', 'end')


    def _build_sign_tab(self):
        frame = self.notebook.tab("✍️ Firmar/Verificar")
        frame.configure(fg_color=COLORS["card"])
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        container = ctk.CTkScrollableFrame(frame, fg_color=COLORS["card"])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.grid_columnconfigure(0, weight=1)

        title_frame = ctk.CTkFrame(container, fg_color=COLORS["light"], corner_radius=8)
        title_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        ctk.CTkLabel(title_frame, text="Firma y Verificación Digital",
                     font=("Arial", 18, "bold"), text_color=COLORS["dark"]).pack(pady=15)

        message_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        message_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        message_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(message_frame, text="📝 Mensaje a Firmar/Verificar:",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.sign_input_text = ctk.CTkTextbox(message_frame, height=120, corner_radius=8,
                                              fg_color=COLORS["light"], border_color=COLORS["primary"])
        self.sign_input_text.pack(fill="x", pady=5)

        btn_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        btn_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)
        btn_frame.grid_columnconfigure(2, weight=1)

        ctk.CTkButton(btn_frame, text="📂 Abrir Archivo", command=self.open_file_for_sign,
                      fg_color=COLORS["accent"], height=35).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(btn_frame, text="✍️ Firmar", command=self.sign_message,
                      fg_color=COLORS["success"], height=35).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(btn_frame, text="✅ Verificar", command=self.verify_signature,
                      fg_color=COLORS["warning"], height=35).grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        signature_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        signature_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        signature_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(signature_frame, text="🔏 Firma Digital (Base64):",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.signature_text = ctk.CTkTextbox(signature_frame, height=120, corner_radius=8,
                                             fg_color=COLORS["light"], border_color=COLORS["secondary"])
        self.signature_text.pack(fill="x", pady=5)

        # Limpiar firma
        ctk.CTkButton(container, text="🧹 Limpiar Firmas", command=self.clear_sign_fields,
                      fg_color=COLORS["danger"], height=36).grid(row=4, column=0, padx=10, pady=8, sticky="e")


    def open_file_for_sign(self):
        filepath = filedialog.askopenfilename(filetypes=[('All files', '*.*')])
        if filepath:
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                # intentar mostrar como texto, si no, mostrar mensaje binario
                try:
                    text = data.decode('utf-8')
                    self.sign_input_text.delete('0.0', 'end')
                    self.sign_input_text.insert('0.0', text)
                except Exception:
                    self.sign_input_text.delete('0.0', 'end')
                    self.sign_input_text.insert('0.0', f"[Archivo binario cargado: {os.path.basename(filepath)}]")
                    # almacenar ruta para firmar binario
                    self._last_binary_to_sign = filepath
            except Exception as e:
                traceback.print_exc()
                messagebox.showerror('Error', f'No se pudo leer el archivo: {str(e)}')

    def sign_message(self):
        if not self.private_key:
            messagebox.showwarning('Atención', 'No hay clave privada cargada.')
            return
        # Ver si el usuario cargó un archivo binario para firmar
        data = None
        if hasattr(self, "_last_binary_to_sign") and os.path.exists(getattr(self, "_last_binary_to_sign")):
            try:
                with open(self._last_binary_to_sign, 'rb') as f:
                    data = f.read()
            except Exception:
                data = None
        if data is None:
            data = self.sign_input_text.get('0.0', 'end').strip().encode('utf-8')
        if not data:
            messagebox.showwarning('Atención', 'No hay mensaje para firmar.')
            return
        try:
            signature = rsa_sign(self.private_key, data)
            self.signature_text.delete('0.0', 'end')
            self.signature_text.insert('0.0', base64.b64encode(signature).decode('utf-8'))
            messagebox.showinfo('Éxito', 'Firma generada y mostrada en el cuadro de Firma.')
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror('Error', f'Error al firmar: {str(e)}')

    def verify_signature(self):
        if not self.public_key:
            messagebox.showwarning('Atención', 'No hay clave pública cargada.')
            return
        try:
            # si hay archivo binario previamente cargado, tomarlo
            data = None
            if hasattr(self, "_last_binary_to_sign") and os.path.exists(getattr(self, "_last_binary_to_sign")):
                try:
                    with open(self._last_binary_to_sign, 'rb') as f:
                        data = f.read()
                except Exception:
                    data = None
            if data is None:
                data = self.sign_input_text.get('0.0', 'end').strip().encode('utf-8')
            sig_raw = self.signature_text.get('0.0', 'end').strip()
            if not sig_raw:
                messagebox.showwarning('Atención', 'No hay firma para verificar.')
                return
            signature = base64.b64decode(sig_raw.encode('utf-8'))
            valid = rsa_verify(self.public_key, data, signature)
            if valid:
                messagebox.showinfo('Verificación', '✅ FIRMA VÁLIDA')
            else:
                messagebox.showerror('Verificación', '❌ FIRMA NO VÁLIDA')
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror('Error', f'Error en verificación: {str(e)}')

    def clear_sign_fields(self):
        self.sign_input_text.delete('0.0', 'end')
        self.signature_text.delete('0.0', 'end')
        if hasattr(self, "_last_binary_to_sign"):
            delattr(self, "_last_binary_to_sign")


    def toggle_theme(self):
        mode = ctk.get_appearance_mode()
        ctk.set_appearance_mode("Light" if mode == "Dark" else "Dark")


if __name__ == '__main__':
    app = RSAApp()
    app.mainloop()
