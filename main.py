import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.backends import default_backend
import base64

# Configuración de tema y colores
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

# Paleta de colores
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
        self.geometry("1200x700")
        self.minsize(1000, 600)  # Tamaño mínimo
        self.configure(fg_color=COLORS["background"])

        # Configurar grid responsivo
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.private_key = None
        self.public_key = None

        # Frame principal
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

        # Configurar responsividad en cada tab
        for tab_name in ["🔑 Generar Claves", "📧 Cifrar/Descifrar", "✍️ Firmar/Verificar"]:
            tab = self.notebook.tab(tab_name)
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)

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

        # Contenedor scrollable
        container = ctk.CTkScrollableFrame(frame, fg_color=COLORS["card"])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.grid_columnconfigure(0, weight=1)

        # Título
        title_frame = ctk.CTkFrame(container, fg_color=COLORS["light"], corner_radius=8)
        title_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        title_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(title_frame, text="Generación de Claves RSA",
                     font=("Arial", 18, "bold"), text_color=COLORS["dark"]).pack(pady=15)

        # Configuración
        config_frame = ctk.CTkFrame(container, fg_color=COLORS["card"], corner_radius=8)
        config_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        config_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(config_frame, text="Tamaño de Clave:",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(pady=5)

        self.keysize_var = ctk.StringVar(value="2048")
        key_combo = ctk.CTkComboBox(config_frame, values=["1024", "2048", "3072", "4096"],
                                    variable=self.keysize_var, width=200)
        key_combo.pack(pady=10)

        # Botón generar
        ctk.CTkButton(container, text="🔄 Generar Claves", command=self.generate_keys,
                      fg_color=COLORS["success"], hover_color="#219955",
                      font=("Arial", 14, "bold"), height=40).grid(row=2, column=0, sticky="ew", padx=10, pady=10)

        # Estado
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

        # Botones de acción - en dos filas para pantallas pequeñas
        action_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        action_frame.grid(row=4, column=0, sticky="ew", padx=10, pady=10)
        action_frame.grid_columnconfigure(0, weight=1)
        action_frame.grid_columnconfigure(1, weight=1)

        # Fila 1 - Guardar
        save_frame = ctk.CTkFrame(action_frame, fg_color=COLORS["card"])
        save_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
        save_frame.grid_columnconfigure(0, weight=1)
        save_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(save_frame, text="💾 Guardar Privada", command=self.save_private_key,
                      fg_color=COLORS["primary"], width=140).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(save_frame, text="💾 Guardar Pública", command=self.save_public_key,
                      fg_color=COLORS["primary"], width=140).grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Fila 2 - Cargar
        load_frame = ctk.CTkFrame(action_frame, fg_color=COLORS["card"])
        load_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        load_frame.grid_columnconfigure(0, weight=1)
        load_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(load_frame, text="📂 Cargar Privada", command=self.load_private_key,
                      fg_color=COLORS["secondary"], width=140).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(load_frame, text="📂 Cargar Pública", command=self.load_public_key,
                      fg_color=COLORS["secondary"], width=140).grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    def generate_keys(self):
        key_size = int(self.keysize_var.get())
        self.private_key, self.public_key = generate_rsa_keypair(key_size)
        self.priv_status.configure(text=f"✅ Privada: CARGADA ({key_size} bits)", text_color=COLORS["success"])
        self.pub_status.configure(text=f"✅ Pública: CARGADA ({key_size} bits)", text_color=COLORS["success"])
        messagebox.showinfo('Éxito', f'Claves RSA de {key_size} bits generadas.')

    def save_private_key(self):
        if not self.private_key:
            messagebox.showwarning('Atención', 'No hay clave privada cargada.')
            return
        filepath = filedialog.asksaveasfilename(defaultextension='.pem', title="Guardar Clave Privada")
        if filepath:
            save_private_key_to_pem(self.private_key, filepath)
            messagebox.showinfo('Éxito', 'Clave privada guardada.')

    def save_public_key(self):
        if not self.public_key:
            messagebox.showwarning('Atención', 'No hay clave pública cargada.')
            return
        filepath = filedialog.asksaveasfilename(defaultextension='.pem', title="Guardar Clave Pública")
        if filepath:
            save_public_key_to_pem(self.public_key, filepath)
            messagebox.showinfo('Éxito', 'Clave pública guardada.')

    def load_private_key(self):
        filepath = filedialog.askopenfilename(filetypes=[('PEM files', '*.pem')], title="Cargar Clave Privada")
        if filepath:
            self.private_key = load_private_key_from_pem(filepath)
            self.priv_status.configure(text="✅ Privada: CARGADA", text_color=COLORS["success"])
            messagebox.showinfo('Éxito', 'Clave privada cargada.')

    def load_public_key(self):
        filepath = filedialog.askopenfilename(filetypes=[('PEM files', '*.pem')], title="Cargar Clave Pública")
        if filepath:
            self.public_key = load_public_key_from_pem(filepath)
            self.pub_status.configure(text="✅ Pública: CARGADA", text_color=COLORS["success"])
            messagebox.showinfo('Éxito', 'Clave pública cargada.')

    def _build_encrypt_tab(self):
        frame = self.notebook.tab("📧 Cifrar/Descifrar")
        frame.configure(fg_color=COLORS["card"])
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Contenedor principal con scroll
        container = ctk.CTkScrollableFrame(frame, fg_color=COLORS["card"])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.grid_columnconfigure(0, weight=1)

        # Título
        title_frame = ctk.CTkFrame(container, fg_color=COLORS["light"], corner_radius=8)
        title_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        ctk.CTkLabel(title_frame, text="Cifrado y Descifrado",
                     font=("Arial", 18, "bold"), text_color=COLORS["dark"]).pack(pady=15)

        # Entrada
        input_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        input_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        input_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(input_frame, text="📝 Texto Original:",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.input_text = ctk.CTkTextbox(input_frame, height=120, corner_radius=8,
                                         fg_color=COLORS["light"], border_color=COLORS["primary"])
        self.input_text.pack(fill="x", pady=5)

        # Botones responsivos
        btn_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        btn_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)
        btn_frame.grid_columnconfigure(2, weight=1)

        ctk.CTkButton(btn_frame, text="📂 Abrir Archivo", command=self.open_text_file_for_encrypt,
                      fg_color=COLORS["accent"], height=35).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(btn_frame, text="🔒 Cifrar", command=self.encrypt_text,
                      fg_color=COLORS["success"], height=35).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(btn_frame, text="🔓 Descifrar", command=self.decrypt_text,
                      fg_color=COLORS["warning"], height=35).grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        # Salida
        output_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        output_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        output_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(output_frame, text="📄 Texto Cifrado (Base64):",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.output_text = ctk.CTkTextbox(output_frame, height=120, corner_radius=8,
                                          fg_color=COLORS["light"], border_color=COLORS["secondary"])
        self.output_text.pack(fill="x", pady=5)

    def open_text_file_for_encrypt(self):
        filepath = filedialog.askopenfilename(filetypes=[('Text files', '*.txt'), ('All files', '*.*')])
        if filepath:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = f.read()
            self.input_text.delete('0.0', 'end')
            self.input_text.insert('0.0', data)

    def encrypt_text(self):
        if not self.public_key:
            messagebox.showwarning('Atención', 'No hay clave pública cargada.')
            return
        data = self.input_text.get('0.0', 'end').strip().encode('utf-8')
        if not data:
            messagebox.showwarning('Atención', 'No hay texto para cifrar.')
            return
        ciphertext = rsa_encrypt(self.public_key, data)
        self.output_text.delete('0.0', 'end')
        self.output_text.insert('0.0', base64.b64encode(ciphertext).decode('utf-8'))

    def decrypt_text(self):
        if not self.private_key:
            messagebox.showwarning('Atención', 'No hay clave privada cargada.')
            return
        try:
            data = base64.b64decode(self.output_text.get('0.0', 'end').strip().encode('utf-8'))
            plaintext = rsa_decrypt(self.private_key, data)
            self.input_text.delete('0.0', 'end')
            self.input_text.insert('0.0', plaintext.decode('utf-8'))
        except Exception as e:
            messagebox.showerror('Error', f'Error al descifrar: {str(e)}')

    def _build_sign_tab(self):
        frame = self.notebook.tab("✍️ Firmar/Verificar")
        frame.configure(fg_color=COLORS["card"])
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Contenedor scrollable
        container = ctk.CTkScrollableFrame(frame, fg_color=COLORS["card"])
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.grid_columnconfigure(0, weight=1)

        # Título
        title_frame = ctk.CTkFrame(container, fg_color=COLORS["light"], corner_radius=8)
        title_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        ctk.CTkLabel(title_frame, text="Firma y Verificación Digital",
                     font=("Arial", 18, "bold"), text_color=COLORS["dark"]).pack(pady=15)

        # Mensaje
        message_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        message_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        message_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(message_frame, text="📝 Mensaje a Firmar/Verificar:",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.sign_input_text = ctk.CTkTextbox(message_frame, height=120, corner_radius=8,
                                              fg_color=COLORS["light"], border_color=COLORS["primary"])
        self.sign_input_text.pack(fill="x", pady=5)

        # Botones
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

        # Firma
        signature_frame = ctk.CTkFrame(container, fg_color=COLORS["card"])
        signature_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        signature_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(signature_frame, text="🔏 Firma Digital (Base64):",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.signature_text = ctk.CTkTextbox(signature_frame, height=120, corner_radius=8,
                                             fg_color=COLORS["light"], border_color=COLORS["secondary"])
        self.signature_text.pack(fill="x", pady=5)

    def open_file_for_sign(self):
        filepath = filedialog.askopenfilename(filetypes=[('All files', '*.*')])
        if filepath:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = f.read()
            self.sign_input_text.delete('0.0', 'end')
            self.sign_input_text.insert('0.0', data)

    def sign_message(self):
        if not self.private_key:
            messagebox.showwarning('Atención', 'No hay clave privada cargada.')
            return
        data = self.sign_input_text.get('0.0', 'end').strip().encode('utf-8')
        if not data:
            messagebox.showwarning('Atención', 'No hay mensaje para firmar.')
            return
        signature = rsa_sign(self.private_key, data)
        self.signature_text.delete('0.0', 'end')
        self.signature_text.insert('0.0', base64.b64encode(signature).decode('utf-8'))

    def verify_signature(self):
        if not self.public_key:
            messagebox.showwarning('Atención', 'No hay clave pública cargada.')
            return
        try:
            data = self.sign_input_text.get('0.0', 'end').strip().encode('utf-8')
            signature = base64.b64decode(self.signature_text.get('0.0', 'end').strip().encode('utf-8'))
            valid = rsa_verify(self.public_key, data, signature)
            if valid:
                messagebox.showinfo('Verificación', '✅ FIRMA VÁLIDA')
            else:
                messagebox.showerror('Verificación', '❌ FIRMA NO VÁLIDA')
        except Exception as e:
            messagebox.showerror('Error', f'Error en verificación: {str(e)}')


if __name__ == '__main__':
    app = RSAApp()
    app.mainloop()