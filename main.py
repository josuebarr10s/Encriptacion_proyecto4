import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.backends import default_backend
import base64

# Configuración de tema y colores
ctk.set_appearance_mode("Light")  # Tema claro más amigable
ctk.set_default_color_theme("blue")

# Paleta de colores moderna y profesional
COLORS = {
    "primary": "#2E86AB",  # Azul principal
    "secondary": "#A23B72",  # Magenta suave
    "success": "#27AE60",  # Verde éxito
    "warning": "#F39C12",  # Naranja advertencia
    "danger": "#E74C3C",  # Rojo peligro
    "light": "#ECF0F1",  # Fondo claro
    "dark": "#2C3E50",  # Texto oscuro
    "accent": "#3498DB",  # Azul acento
    "background": "#F8F9FA",  # Fondo general
    "card": "#FFFFFF",  # Fondo tarjetas
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
        self.title("🔐 RSA Security Tool - Criptografía Segura")
        self.geometry("1400x850")
        self.configure(fg_color=COLORS["background"])

        self.private_key = None
        self.public_key = None

        # Header principal
        header_frame = ctk.CTkFrame(self, fg_color=COLORS["primary"], height=80)
        header_frame.pack(fill="x", padx=20, pady=(20, 10))
        header_frame.pack_propagate(False)

        ctk.CTkLabel(header_frame, text="🔐 HERRAMIENTA DE SEGURIDAD RSA",
                     font=("Arial", 24, "bold"), text_color="white").pack(pady=20)

        # Notebook con pestañas
        self.notebook = ctk.CTkTabview(self, width=1300, height=700,
                                       fg_color=COLORS["card"], segmented_button_fg_color=COLORS["primary"],
                                       segmented_button_selected_color=COLORS["accent"],
                                       segmented_button_selected_hover_color=COLORS["secondary"])
        self.notebook.pack(pady=20, padx=20, fill="both", expand=True)

        self.notebook.add("🔑 Generar Claves")
        self.notebook.add("📧 Cifrar/Descifrar")
        self.notebook.add("✍️ Firmar/Verificar")

        self._build_keys_tab()
        self._build_encrypt_tab()
        self._build_sign_tab()

        # Footer
        footer_frame = ctk.CTkFrame(self, fg_color=COLORS["light"], height=40)
        footer_frame.pack(fill="x", padx=20, pady=(10, 20))
        footer_frame.pack_propagate(False)

        ctk.CTkLabel(footer_frame, text="© 2024 RSA Security Tool - Criptografía Segura",
                     text_color=COLORS["dark"], font=("Arial", 12)).pack(pady=10)

    def _build_keys_tab(self):
        frame = self.notebook.tab("🔑 Generar Claves")
        frame.configure(fg_color=COLORS["card"])

        # Título
        title_frame = ctk.CTkFrame(frame, fg_color=COLORS["light"], corner_radius=10)
        title_frame.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(title_frame, text="Generación de Claves RSA",
                     font=("Arial", 20, "bold"), text_color=COLORS["dark"]).pack(pady=15)

        # Configuración de clave
        config_frame = ctk.CTkFrame(frame, fg_color=COLORS["card"], corner_radius=10)
        config_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(config_frame, text="Tamaño de Clave:",
                     font=("Arial", 14, "bold"), text_color=COLORS["dark"]).pack(pady=5)

        self.keysize_var = ctk.StringVar(value="2048")
        key_combo = ctk.CTkComboBox(config_frame, values=["1024", "2048", "3072", "4096"],
                                    variable=self.keysize_var, width=200,
                                    fg_color=COLORS["light"], button_color=COLORS["primary"],
                                    dropdown_fg_color=COLORS["light"])
        key_combo.pack(pady=10)

        # Botón generar
        ctk.CTkButton(frame, text="🔄 Generar Nuevas Claves", command=self.generate_keys,
                      fg_color=COLORS["success"], hover_color="#219955",
                      font=("Arial", 14, "bold"), width=250, height=40).pack(pady=15)

        # Estado de claves
        status_frame = ctk.CTkFrame(frame, fg_color=COLORS["light"], corner_radius=10)
        status_frame.pack(fill="x", padx=20, pady=15)

        ctk.CTkLabel(status_frame, text="Estado de las Claves:",
                     font=("Arial", 16, "bold"), text_color=COLORS["dark"]).pack(pady=10)

        self.priv_status = ctk.CTkLabel(status_frame, text="🔒 Clave Privada: NO CARGADA",
                                        text_color=COLORS["danger"], font=("Arial", 12, "bold"))
        self.priv_status.pack(pady=5)

        self.pub_status = ctk.CTkLabel(status_frame, text="🔓 Clave Pública: NO CARGADA",
                                       text_color=COLORS["danger"], font=("Arial", 12, "bold"))
        self.pub_status.pack(pady=5)

        # Botones de guardar/cargar
        action_frame = ctk.CTkFrame(frame, fg_color=COLORS["card"])
        action_frame.pack(fill="x", padx=20, pady=20)

        btn_frame1 = ctk.CTkFrame(action_frame, fg_color=COLORS["card"])
        btn_frame1.pack(pady=10)

        ctk.CTkButton(btn_frame1, text="💾 Guardar Clave Privada", command=self.save_private_key,
                      fg_color=COLORS["primary"], hover_color=COLORS["accent"], width=200).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame1, text="💾 Guardar Clave Pública", command=self.save_public_key,
                      fg_color=COLORS["primary"], hover_color=COLORS["accent"], width=200).pack(side="left", padx=10)

        btn_frame2 = ctk.CTkFrame(action_frame, fg_color=COLORS["card"])
        btn_frame2.pack(pady=10)

        ctk.CTkButton(btn_frame2, text="📂 Cargar Clave Privada", command=self.load_private_key,
                      fg_color=COLORS["secondary"], hover_color="#8A2BE2", width=200).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame2, text="📂 Cargar Clave Pública", command=self.load_public_key,
                      fg_color=COLORS["secondary"], hover_color="#8A2BE2", width=200).pack(side="left", padx=10)

    def generate_keys(self):
        key_size = int(self.keysize_var.get())
        self.private_key, self.public_key = generate_rsa_keypair(key_size)
        self.priv_status.configure(text=f"✅ Clave Privada: CARGADA ({key_size} bits)", text_color=COLORS["success"])
        self.pub_status.configure(text=f"✅ Clave Pública: CARGADA ({key_size} bits)", text_color=COLORS["success"])
        messagebox.showinfo('Éxito', f'✅ Par de claves RSA de {key_size} bits generado correctamente.')

    def save_private_key(self):
        if not self.private_key:
            messagebox.showwarning('Atención', '❌ No hay clave privada cargada.')
            return
        filepath = filedialog.asksaveasfilename(defaultextension='.pem', title="Guardar Clave Privada")
        if filepath:
            save_private_key_to_pem(self.private_key, filepath)
            messagebox.showinfo('Éxito', '✅ Clave privada guardada correctamente.')

    def save_public_key(self):
        if not self.public_key:
            messagebox.showwarning('Atención', '❌ No hay clave pública cargada.')
            return
        filepath = filedialog.asksaveasfilename(defaultextension='.pem', title="Guardar Clave Pública")
        if filepath:
            save_public_key_to_pem(self.public_key, filepath)
            messagebox.showinfo('Éxito', '✅ Clave pública guardada correctamente.')

    def load_private_key(self):
        filepath = filedialog.askopenfilename(filetypes=[('PEM files', '*.pem')], title="Cargar Clave Privada")
        if filepath:
            self.private_key = load_private_key_from_pem(filepath)
            self.priv_status.configure(text="✅ Clave Privada: CARGADA", text_color=COLORS["success"])
            messagebox.showinfo('Éxito', '✅ Clave privada cargada correctamente.')

    def load_public_key(self):
        filepath = filedialog.askopenfilename(filetypes=[('PEM files', '*.pem')], title="Cargar Clave Pública")
        if filepath:
            self.public_key = load_public_key_from_pem(filepath)
            self.pub_status.configure(text="✅ Clave Pública: CARGADA", text_color=COLORS["success"])
            messagebox.showinfo('Éxito', '✅ Clave pública cargada correctamente.')

    def _build_encrypt_tab(self):
        frame = self.notebook.tab("📧 Cifrar/Descifrar")
        frame.configure(fg_color=COLORS["card"])

        # Título
        title_frame = ctk.CTkFrame(frame, fg_color=COLORS["light"], corner_radius=10)
        title_frame.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(title_frame, text="Cifrado y Descifrado de Mensajes",
                     font=("Arial", 20, "bold"), text_color=COLORS["dark"]).pack(pady=15)

        # Área de entrada
        input_frame = ctk.CTkFrame(frame, fg_color=COLORS["card"])
        input_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(input_frame, text="📝 Texto Original:",
                     font=("Arial", 16, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.input_text = ctk.CTkTextbox(input_frame, width=900, height=150, corner_radius=8,
                                         fg_color=COLORS["light"], border_color=COLORS["primary"])
        self.input_text.pack(pady=5)

        # Botones de acción
        btn_frame = ctk.CTkFrame(frame, fg_color=COLORS["card"])
        btn_frame.pack(pady=15)

        ctk.CTkButton(btn_frame, text="📂 Abrir Archivo", command=self.open_text_file_for_encrypt,
                      fg_color=COLORS["accent"], hover_color="#2980B9", width=150).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="🔒 Cifrar", command=self.encrypt_text,
                      fg_color=COLORS["success"], hover_color="#219955", width=120).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="🔓 Descifrar", command=self.decrypt_text,
                      fg_color=COLORS["warning"], hover_color="#E67E22", width=120).pack(side="left", padx=10)

        # Área de salida
        output_frame = ctk.CTkFrame(frame, fg_color=COLORS["card"])
        output_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(output_frame, text="📄 Texto Cifrado (Base64):",
                     font=("Arial", 16, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.output_text = ctk.CTkTextbox(output_frame, width=900, height=150, corner_radius=8,
                                          fg_color=COLORS["light"], border_color=COLORS["secondary"])
        self.output_text.pack(pady=5)

    def open_text_file_for_encrypt(self):
        filepath = filedialog.askopenfilename(filetypes=[('Text files', '*.txt'), ('All files', '*.*')])
        if filepath:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = f.read()
            self.input_text.delete('0.0', 'end')
            self.input_text.insert('0.0', data)
            messagebox.showinfo('Éxito', '✅ Archivo cargado correctamente.')

    def encrypt_text(self):
        if not self.public_key:
            messagebox.showwarning('Atención', '❌ No hay clave pública cargada.')
            return
        data = self.input_text.get('0.0', 'end').strip().encode('utf-8')
        if not data:
            messagebox.showwarning('Atención', '❌ No hay texto para cifrar.')
            return
        ciphertext = rsa_encrypt(self.public_key, data)
        self.output_text.delete('0.0', 'end')
        self.output_text.insert('0.0', base64.b64encode(ciphertext).decode('utf-8'))
        messagebox.showinfo('Éxito', '✅ Texto cifrado correctamente.')

    def decrypt_text(self):
        if not self.private_key:
            messagebox.showwarning('Atención', '❌ No hay clave privada cargada.')
            return
        try:
            data = base64.b64decode(self.output_text.get('0.0', 'end').strip().encode('utf-8'))
            plaintext = rsa_decrypt(self.private_key, data)
            self.input_text.delete('0.0', 'end')
            self.input_text.insert('0.0', plaintext.decode('utf-8'))
            messagebox.showinfo('Éxito', '✅ Texto descifrado correctamente.')
        except Exception as e:
            messagebox.showerror('Error', f'❌ Error al descifrar: {str(e)}')

    def _build_sign_tab(self):
        frame = self.notebook.tab("✍️ Firmar/Verificar")
        frame.configure(fg_color=COLORS["card"])

        # Título
        title_frame = ctk.CTkFrame(frame, fg_color=COLORS["light"], corner_radius=10)
        title_frame.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(title_frame, text="Firma y Verificación Digital",
                     font=("Arial", 20, "bold"), text_color=COLORS["dark"]).pack(pady=15)

        # Área de mensaje
        message_frame = ctk.CTkFrame(frame, fg_color=COLORS["card"])
        message_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(message_frame, text="📝 Mensaje a Firmar/Verificar:",
                     font=("Arial", 16, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.sign_input_text = ctk.CTkTextbox(message_frame, width=900, height=150, corner_radius=8,
                                              fg_color=COLORS["light"], border_color=COLORS["primary"])
        self.sign_input_text.pack(pady=5)

        # Botones de acción
        btn_frame = ctk.CTkFrame(frame, fg_color=COLORS["card"])
        btn_frame.pack(pady=15)

        ctk.CTkButton(btn_frame, text="📂 Abrir Archivo", command=self.open_file_for_sign,
                      fg_color=COLORS["accent"], hover_color="#2980B9", width=150).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="✍️ Firmar", command=self.sign_message,
                      fg_color=COLORS["success"], hover_color="#219955", width=120).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="✅ Verificar", command=self.verify_signature,
                      fg_color=COLORS["warning"], hover_color="#E67E22", width=120).pack(side="left", padx=10)

        # Área de firma
        signature_frame = ctk.CTkFrame(frame, fg_color=COLORS["card"])
        signature_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(signature_frame, text="🔏 Firma Digital (Base64):",
                     font=("Arial", 16, "bold"), text_color=COLORS["dark"]).pack(anchor="w", pady=(0, 5))

        self.signature_text = ctk.CTkTextbox(signature_frame, width=900, height=150, corner_radius=8,
                                             fg_color=COLORS["light"], border_color=COLORS["secondary"])
        self.signature_text.pack(pady=5)

    def open_file_for_sign(self):
        filepath = filedialog.askopenfilename(filetypes=[('All files', '*.*')])
        if filepath:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = f.read()
            self.sign_input_text.delete('0.0', 'end')
            self.sign_input_text.insert('0.0', data)
            messagebox.showinfo('Éxito', '✅ Archivo cargado correctamente.')

    def sign_message(self):
        if not self.private_key:
            messagebox.showwarning('Atención', '❌ No hay clave privada cargada.')
            return
        data = self.sign_input_text.get('0.0', 'end').strip().encode('utf-8')
        if not data:
            messagebox.showwarning('Atención', '❌ No hay mensaje para firmar.')
            return
        signature = rsa_sign(self.private_key, data)
        self.signature_text.delete('0.0', 'end')
        self.signature_text.insert('0.0', base64.b64encode(signature).decode('utf-8'))
        messagebox.showinfo('Éxito', '✅ Mensaje firmado correctamente.')

    def verify_signature(self):
        if not self.public_key:
            messagebox.showwarning('Atención', '❌ No hay clave pública cargada.')
            return
        try:
            data = self.sign_input_text.get('0.0', 'end').strip().encode('utf-8')
            signature = base64.b64decode(self.signature_text.get('0.0', 'end').strip().encode('utf-8'))
            valid = rsa_verify(self.public_key, data, signature)
            if valid:
                messagebox.showinfo('Verificación',
                                    '✅ ✅ FIRMA VÁLIDA\nEl mensaje es auténtico y no ha sido modificado.')
            else:
                messagebox.showerror('Verificación', '❌ ❌ FIRMA NO VÁLIDA\nEl mensaje puede haber sido alterado.')
        except Exception as e:
            messagebox.showerror('Error', f'❌ Error en verificación: {str(e)}')


# -----------------
# Main
# -----------------
if __name__ == '__main__':
    app = RSAApp()
    app.mainloop()