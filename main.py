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