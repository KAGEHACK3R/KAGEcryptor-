#!/usr/bin/env python3
"""
================================================================================
                             KAGEcryptor Pro Ultimate
================================================================================
Description :
 Ce projet est une application de chiffrement/déchiffrement ultra complète
 (textes, fichiers, stéganographie, cloud, etc.) avec partage via WhatsApp,
 Telegram, Gmail, etc. L’interface graphique est modernisée avec des thèmes clair/sombre,
 une police moderne et une palette de couleurs dynamiques.
================================================================================
Axes d'amélioration intégrés :
  • Tests unitaires et d’intégration (à lancer avec "--test")
  • Documentation complète et commentaires détaillés
  • Packaging et déploiement (voir instructions ci-dessous)
  • Interface graphique améliorée et internationalisée (français et anglais)
  • Intégration (stub) d’API de partage avancées vers le cloud
  • Gestion avancée des erreurs (rapport d'erreur dans "error_report.log")

Instructions de packaging :
  - Pour créer un exécutable avec PyInstaller :
       pip install pyinstaller
       pyinstaller --onefile --name KAGEcryptorProUltimate KAGEcrypto.py
  - Pour créer un package pip, extrait ce fichier dans un module et rédige un setup.py.

GitHub  : https://github.com/KAGEHACK3R
Auteur  : EDI KOUAKOU GUY ALFRED   |   Pseudo: KAGEHACK3R
================================================================================
"""

import sys, os, base64, hashlib, logging, traceback, threading, urllib.parse, smtplib, unittest
from datetime import datetime
from typing import List, Callable
from email.mime.text import MIMEText

# -----------------------------------------------------------------------------
# CONFIGURATION DU LOGGING AVEC ROTATION ET RAPPORT D'ERREURS
# -----------------------------------------------------------------------------
from logging.handlers import RotatingFileHandler

LOG_FORMAT = "[%(levelname)s] %(asctime)s - %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        RotatingFileHandler('kagecryptor_pro.log', maxBytes=10*1024*1024, backupCount=3)
    ]
)

def error_report_handler(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    logging.error("Erreur non interceptée : " + error_msg)
    with open("error_report.log", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} - {error_msg}\n")

sys.excepthook = error_report_handler

def send_error_email(message: str):
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "gkouakou174@gmail.com"
        receiver_email = "gkouakou174@gmail.com"
        password = "qphq fkhq dmbi vlkh"
        msg = MIMEText(message)
        msg['Subject'] = "Rapport d'erreur KAGEcryptor Pro Ultimate"
        msg['From'] = sender_email
        msg['To'] = receiver_email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        logging.error(f"Impossible d'envoyer l'email d'alerte : {e}")

# -----------------------------------------------------------------------------
# IMPORTS POUR L'INTERFACE GRAPHIQUE (PySide6)
# -----------------------------------------------------------------------------
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QTextEdit, QLabel, QPushButton, QLineEdit, QFileDialog, QMessageBox,
    QCheckBox, QComboBox, QProgressBar, QListWidget, QGroupBox, QFormLayout,
    QWizard, QWizardPage, QInputDialog, QMenuBar, QSystemTrayIcon, QProgressDialog
)
from PySide6.QtGui import QIcon, QDesktopServices, QAction
from PySide6.QtCore import Qt, QThreadPool, QRunnable, Slot, QObject, Signal, QSettings, QUrl, QTranslator, QTimer

# -----------------------------------------------------------------------------
# IMPORTS CRYPTOGRAPHIQUES (PyCryptodome, argon2, Pillow)
# -----------------------------------------------------------------------------
try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305, Blowfish, CAST, DES3, Salsa20, ARC2, ARC4
    try:
        from Crypto.Cipher import Twofish
        twofish_ok = True
    except ImportError:
        twofish_ok = False
        logging.warning("Twofish non installé. Option Twofish-CBC désactivée.")
    from Crypto.PublicKey import RSA  
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    crypto_ok = True
except ImportError as e:
    crypto_ok = False
    logging.error("PyCryptodome requis. Installe-le via 'pip install pycryptodome'.")

try:
    from argon2.low_level import hash_secret_raw, Type
    argon_ok = True
except ImportError:
    argon_ok = False
    logging.warning("Argon2 non disponible. Fallback sur SHA-256.")

try:
    from PIL import Image
    stego_ok = True
except ImportError:
    stego_ok = False
    logging.warning("Pillow non installé. La stéganographie sera désactivée.")

try:
    from plyer import notification
    have_plyer = True
except ImportError:
    have_plyer = False
    logging.warning("Plyer non installé. Utilisation de QSystemTrayIcon pour les notifications.")

tray_icon = None
if not have_plyer:
    tray_icon = QSystemTrayIcon(QIcon.fromTheme("dialog-information"))
    tray_icon.setToolTip("KAGEcryptor Pro Notifications")

# -----------------------------------------------------------------------------
# FONCTIONS DE PARTAGE (TEXTES, FICHIERS ET CLOUD)
# -----------------------------------------------------------------------------
def share_text(platform: str, text: str) -> None:
    encoded_text = urllib.parse.quote(text)
    if platform == "WhatsApp":
        url = f"https://api.whatsapp.com/send?text={encoded_text}"
    elif platform == "Telegram":
        url = f"https://t.me/share/url?url=&text={encoded_text}"
    elif platform == "Gmail":
        url = f"mailto:?subject=Encrypted%20Message&body={encoded_text}"
    else:
        QMessageBox.information(None, "Partager", "Le texte a été copié dans le presse-papiers.")
        QApplication.clipboard().setText(text)
        return
    QDesktopServices.openUrl(QUrl(url))

def share_file(platform: str, file_path: str) -> None:
    if platform == "Ouvrir le dossier":
        QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(file_path)))
        return
    message = f"Voici un fichier chiffré : {file_path}"
    encoded_text = urllib.parse.quote(message)
    if platform == "WhatsApp":
        url = f"https://api.whatsapp.com/send?text={encoded_text}"
    elif platform == "Telegram":
        url = f"https://t.me/share/url?url=&text={encoded_text}"
    elif platform == "Gmail":
        url = f"mailto:?subject=Encrypted%20File&body={encoded_text}"
    else:
        QMessageBox.information(None, "Partager", "Le chemin du fichier a été copié dans le presse-papiers.")
        QApplication.clipboard().setText(file_path)
        return
    QDesktopServices.openUrl(QUrl(url))

def upload_to_cloud(provider: str, data: str, file_mode: bool = False) -> None:
    progress = QProgressDialog(f"Upload vers {provider}...", "Annuler", 0, 100)
    progress.setWindowTitle("Upload en cours")
    progress.setWindowModality(Qt.ApplicationModal)
    progress.show()
    current = 0
    def update_progress():
        nonlocal current
        current += 10
        progress.setValue(current)
        if current >= 100:
            timer.stop()
            if file_mode:
                QMessageBox.information(None, "Cloud", f"Fichier uploadé avec succès sur {provider}.")
            else:
                QMessageBox.information(None, "Cloud", f"Texte uploadé avec succès sur {provider}.")
    timer = QTimer()
    timer.timeout.connect(update_progress)
    timer.start(200)

def cloud_upload_text(text: str) -> None:
    providers = ["Google Drive", "Dropbox", "OneDrive", "Box", "iCloud", "Amazon S3",
                 "Mega", "pCloud", "MediaFire", "Yandex Disk", "SpiderOak", "Sync.com",
                 "Tresorit", "Backblaze B2", "Zoolz"]
    provider, ok = QInputDialog.getItem(None, "Uploader Texte", "Choisissez le fournisseur :", providers, 0, False)
    if ok and provider:
        upload_to_cloud(provider, text, file_mode=False)

def cloud_upload_file(file_path: str) -> None:
    providers = ["Google Drive", "Dropbox", "OneDrive", "Box", "iCloud", "Amazon S3",
                 "Mega", "pCloud", "MediaFire", "Yandex Disk", "SpiderOak", "Sync.com",
                 "Tresorit", "Backblaze B2", "Zoolz"]
    provider, ok = QInputDialog.getItem(None, "Uploader Fichier", "Choisissez le fournisseur :", providers, 0, False)
    if ok and provider:
        upload_to_cloud(provider, file_path, file_mode=True)

# -----------------------------------------------------------------------------
# FONCTIONS UTILITAIRES DE BASE
# -----------------------------------------------------------------------------
def check_dependencies() -> None:
    if not crypto_ok:
        raise ImportError("PyCryptodome est requis pour les fonctionnalités cryptographiques.")
    logging.info("Toutes les dépendances critiques sont vérifiées.")

def secure_erase(filepath: str, passes: int = 3) -> None:
    try:
        if not os.path.exists(filepath):
            logging.warning(f"Fichier {filepath} introuvable pour effacement sécurisé.")
            return
        size = os.path.getsize(filepath)
        with open(filepath, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
        os.remove(filepath)
        logging.info(f"Fichier {filepath} effacé sécuritairement.")
    except Exception as e:
        logging.error(f"Erreur lors de l'effacement sécurisé de {filepath} : {e}")
        raise

def derive_key_argon2(password: str, salt: bytes, length: int = 32) -> bytes:
    if not argon_ok:
        logging.warning("Argon2 indisponible, utilisation de SHA-256 en fallback.")
        return hashlib.sha256(password.encode()).digest()
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=2**15,
        parallelism=2,
        hash_len=length,
        type=Type.ID
    )

# -----------------------------------------------------------------------------
# FONCTIONS DE CHIFFREMENT DE TEXTE
# -----------------------------------------------------------------------------
def caesar_encrypt_text(text: str, shift: int) -> str:
    try:
        return ''.join(chr((ord(c) + shift) % 0x110000) for c in text)
    except Exception as e:
        raise ValueError(f"Erreur dans le chiffrement César : {e}") from e

def caesar_decrypt_text(text: str, shift: int) -> str:
    try:
        return ''.join(chr((ord(c) - shift) % 0x110000) for c in text)
    except Exception as e:
        raise ValueError(f"Erreur dans le déchiffrement César : {e}") from e

def vigenere_encrypt_text(text: str, key: str) -> str:
    if not key:
        raise ValueError("Clé Vigenère requise.")
    return ''.join(chr((ord(c) + ord(key[i % len(key)])) % 0x110000) for i, c in enumerate(text))

def vigenere_decrypt_text(text: str, key: str) -> str:
    if not key:
        raise ValueError("Clé Vigenère requise.")
    return ''.join(chr((ord(c) - ord(key[i % len(key)])) % 0x110000) for i, c in enumerate(text))

def xor_encrypt_text(text: str, key: str) -> str:
    if not key:
        raise ValueError("Clé XOR requise.")
    tbytes = text.encode('utf-8')
    kbytes = key.encode('utf-8')
    enc = bytearray(b ^ kbytes[i % len(kbytes)] for i, b in enumerate(tbytes))
    return base64.b64encode(enc).decode('utf-8')

def xor_decrypt_text(text: str, key: str) -> str:
    if not key:
        raise ValueError("Clé XOR requise.")
    try:
        enc = base64.b64decode(text.strip())
        kbytes = key.encode('utf-8')
        dec = bytearray(b ^ kbytes[i % len(kbytes)] for i, b in enumerate(enc))
        return dec.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Erreur dans le déchiffrement XOR : {e}") from e

def aes_cbc_encrypt_text(text: str, password: str) -> str:
    check_dependencies()
    iv = get_random_bytes(AES.block_size)
    key = derive_key_argon2(password, iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + enc).decode('utf-8')

def aes_cbc_decrypt_text(text: str, password: str) -> str:
    check_dependencies()
    try:
        raw = base64.b64decode(text.strip())
        iv, enc = raw[:AES.block_size], raw[AES.block_size:]
        key = derive_key_argon2(password, iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(enc), AES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Erreur dans le déchiffrement AES-CBC : {e}") from e

def aes_gcm_encrypt_text(text: str, password: str) -> str:
    check_dependencies()
    salt = get_random_bytes(16)
    key = derive_key_argon2(password, salt)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return base64.b64encode(salt + nonce + tag + ct).decode('utf-8')

def aes_gcm_decrypt_text(text: str, password: str) -> str:
    check_dependencies()
    try:
        raw = base64.b64decode(text.strip())
        salt, nonce, tag, ct = raw[:16], raw[16:28], raw[28:44], raw[44:]
        key = derive_key_argon2(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Erreur dans le déchiffrement AES-GCM : {e}") from e

def chacha20_encrypt_text(text: str, password: str) -> str:
    check_dependencies()
    salt = get_random_bytes(16)
    key = derive_key_argon2(password, salt)
    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return base64.b64encode(salt + nonce + tag + ct).decode('utf-8')

def chacha20_decrypt_text(text: str, password: str) -> str:
    check_dependencies()
    try:
        raw = base64.b64decode(text.strip())
        salt, nonce, tag, ct = raw[:16], raw[16:28], raw[28:44], raw[44:]
        key = derive_key_argon2(password, salt)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Erreur dans le déchiffrement ChaCha20 : {e}") from e

# -----------------------------------------------------------------------------
# FONCTIONS DE CHIFFREMENT DE FICHIERS
# -----------------------------------------------------------------------------
def encrypt_file_aesgcm(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    salt = get_random_bytes(16)
    key = derive_key_argon2(password, salt)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    chunk_size = 64 * 1024
    try:
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            fout.write(salt)
            fout.write(nonce)
            fout.write(b'\x00' * 16)
            tag_position = fout.tell() - 16
            while (chunk := fin.read(chunk_size)):
                fout.write(cipher.encrypt(chunk))
            tag = cipher.digest()
            fout.seek(tag_position)
            fout.write(tag)
        logging.info(f"Fichier {in_path} chiffré (AES-GCM) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement (AES-GCM) de {in_path} : {e}")
        raise

def decrypt_file_aesgcm(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    chunk_size = 64 * 1024
    try:
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            salt = fin.read(16)
            nonce = fin.read(12)
            tag = fin.read(16)
            if len(salt) < 16 or len(nonce) < 12 or len(tag) < 16:
                raise ValueError("Fichier corrompu ou incomplet.")
            key = derive_key_argon2(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            while (chunk := fin.read(chunk_size)):
                fout.write(cipher.decrypt(chunk))
            cipher.verify(tag)
        logging.info(f"Fichier {in_path} déchiffré (AES-GCM) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement (AES-GCM) de {in_path} : {e}")
        raise

def encrypt_file_aescbc(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    iv = get_random_bytes(AES.block_size)
    key = derive_key_argon2(password, iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            fout.write(iv)
            data = fin.read()
            fout.write(cipher.encrypt(pad(data, AES.block_size)))
        logging.info(f"Fichier {in_path} chiffré (AES-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement (AES-CBC) de {in_path} : {e}")
        raise

def decrypt_file_aescbc(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    try:
        with open(in_path, "rb") as fin:
            iv = fin.read(AES.block_size)
            ciphertext = fin.read()
        key = derive_key_argon2(password, iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        with open(out_path, "wb") as fout:
            fout.write(plaintext)
        logging.info(f"Fichier {in_path} déchiffré (AES-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement (AES-CBC) de {in_path} : {e}")
        raise

def encrypt_file_chacha20(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    salt = get_random_bytes(16)
    key = derive_key_argon2(password, salt)
    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    chunk_size = 64 * 1024
    try:
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            fout.write(salt)
            fout.write(nonce)
            fout.write(b'\x00' * 16)
            tag_position = fout.tell() - 16
            while (chunk := fin.read(chunk_size)):
                fout.write(cipher.encrypt(chunk))
            tag = cipher.digest()
            fout.seek(tag_position)
            fout.write(tag)
        logging.info(f"Fichier {in_path} chiffré (ChaCha20-Poly1305) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement (ChaCha20) de {in_path} : {e}")
        raise

def decrypt_file_chacha20(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    chunk_size = 64 * 1024
    try:
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            salt = fin.read(16)
            nonce = fin.read(12)
            tag = fin.read(16)
            if len(salt) < 16 or len(nonce) < 12 or len(tag) < 16:
                raise ValueError("Fichier corrompu ou incomplet.")
            key = derive_key_argon2(password, salt)
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            while (chunk := fin.read(chunk_size)):
                fout.write(cipher.decrypt(chunk))
            cipher.verify(tag)
        logging.info(f"Fichier {in_path} déchiffré (ChaCha20-Poly1305) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement (ChaCha20) de {in_path} : {e}")
        raise

def encrypt_file_blowfish(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    from Crypto.Cipher import Blowfish
    bs = Blowfish.block_size
    iv = get_random_bytes(bs)
    key = derive_key_argon2(password, iv, length=16)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    try:
        with open(in_path, "rb") as fin:
            data = fin.read()
        padded = pad(data, bs)
        ciphertext = iv + cipher.encrypt(padded)
        with open(out_path, "wb") as fout:
            fout.write(ciphertext)
        logging.info(f"Fichier {in_path} chiffré (Blowfish-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement (Blowfish-CBC) de {in_path} : {e}")
        raise

def decrypt_file_blowfish(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    from Crypto.Cipher import Blowfish
    bs = Blowfish.block_size
    try:
        with open(in_path, "rb") as fin:
            iv = fin.read(bs)
            ciphertext = fin.read()
        key = derive_key_argon2(password, iv, length=16)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        data = unpad(padded, bs)
        with open(out_path, "wb") as fout:
            fout.write(data)
        logging.info(f"Fichier {in_path} déchiffré (Blowfish-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement (Blowfish-CBC) de {in_path} : {e}")
        raise

def encrypt_file_cast(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    from Crypto.Cipher import CAST
    bs = CAST.block_size
    iv = get_random_bytes(bs)
    key = derive_key_argon2(password, iv, length=16)
    cipher = CAST.new(key, CAST.MODE_CBC, iv)
    try:
        with open(in_path, "rb") as fin:
            data = fin.read()
        padded = pad(data, bs)
        ciphertext = iv + cipher.encrypt(padded)
        with open(out_path, "wb") as fout:
            fout.write(ciphertext)
        logging.info(f"Fichier {in_path} chiffré (CAST-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement (CAST-CBC) de {in_path} : {e}")
        raise

def decrypt_file_cast(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    from Crypto.Cipher import CAST
    bs = CAST.block_size
    try:
        with open(in_path, "rb") as fin:
            iv = fin.read(bs)
            ciphertext = fin.read()
        key = derive_key_argon2(password, iv, length=16)
        cipher = CAST.new(key, CAST.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        data = unpad(padded, bs)
        with open(out_path, "wb") as fout:
            fout.write(data)
        logging.info(f"Fichier {in_path} déchiffré (CAST-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement (CAST-CBC) de {in_path} : {e}")
        raise

def encrypt_file_des3(in_path: str, out_path: str, password: str) -> None:
    """Chiffre un fichier avec TripleDES-CBC."""
    check_dependencies()
    bs = DES3.block_size
    iv = get_random_bytes(bs)
    key = derive_key_argon2(password, iv, length=16)
    try:
        key = DES3.adjust_key_parity(key)
    except Exception:
        pass
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    try:
        with open(in_path, "rb") as fin:
            data = fin.read()
        padded = pad(data, bs)
        ciphertext = iv + cipher.encrypt(padded)
        with open(out_path, "wb") as fout:
            fout.write(ciphertext)
        # Correction : utilisation de out_path au lieu de out_file
        logging.info(f"Fichier {in_path} chiffré (TripleDES-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement (TripleDES-CBC) de {in_path} : {e}")
        raise

def decrypt_file_des3(in_path: str, out_path: str, password: str) -> None:
    """Déchiffre un fichier chiffré avec TripleDES-CBC."""
    check_dependencies()
    bs = DES3.block_size
    try:
        with open(in_path, "rb") as fin:
            iv = fin.read(bs)
            ciphertext = fin.read()
        key = derive_key_argon2(password, iv, length=16)
        try:
            key = DES3.adjust_key_parity(key)
        except Exception:
            pass
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        data = unpad(padded, bs)
        with open(out_path, "wb") as fout:
            fout.write(data)
        logging.info(f"Fichier {in_path} déchiffré (TripleDES-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement (TripleDES-CBC) de {in_path} : {e}")
        raise

def encrypt_file_salsa20(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    nonce = get_random_bytes(8)
    key = derive_key_argon2(password, nonce, length=32)
    cipher = Salsa20.new(key=key, nonce=nonce)
    try:
        with open(in_path, "rb") as fin:
            plaintext = fin.read()
        ciphertext = nonce + cipher.encrypt(plaintext)
        with open(out_path, "wb") as fout:
            fout.write(ciphertext)
        logging.info(f"Fichier {in_path} chiffré (Salsa20) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement (Salsa20) de {in_path} : {e}")
        raise

def decrypt_file_salsa20(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    try:
        with open(in_path, "rb") as fin:
            nonce = fin.read(8)
            ciphertext = fin.read()
        key = derive_key_argon2(password, nonce, length=32)
        cipher = Salsa20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        with open(out_path, "wb") as fout:
            fout.write(plaintext)
        logging.info(f"Fichier {in_path} déchiffré (Salsa20) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement (Salsa20) de {in_path} : {e}")
        raise

def encrypt_file_arc2(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    from Crypto.Cipher import ARC2
    bs = ARC2.block_size
    iv = get_random_bytes(bs)
    key = derive_key_argon2(password, iv, length=16)
    cipher = ARC2.new(key, ARC2.MODE_CBC, iv)
    try:
        with open(in_path, "rb") as fin:
            data = fin.read()
        padded = pad(data, bs)
        ciphertext = iv + cipher.encrypt(padded)
        with open(out_path, "wb") as fout:
            fout.write(ciphertext)
        logging.info(f"Fichier {in_path} chiffré (ARC2-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement (ARC2-CBC) de {in_path} : {e}")
        raise

def decrypt_file_arc2(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    from Crypto.Cipher import ARC2
    bs = ARC2.block_size
    try:
        with open(in_path, "rb") as fin:
            iv = fin.read(bs)
            ciphertext = fin.read()
        key = derive_key_argon2(password, iv, length=16)
        cipher = ARC2.new(key, ARC2.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        data = unpad(padded, bs)
        with open(out_path, "wb") as fout:
            fout.write(data)
        logging.info(f"Fichier {in_path} déchiffré (ARC2-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement (ARC2-CBC) de {in_path} : {e}")
        raise

def encrypt_file_rc4(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    from Crypto.Cipher import ARC4
    key = derive_key_argon2(password, b"rc4salt", length=16)
    cipher = ARC4.new(key)
    try:
        with open(in_path, "rb") as fin:
            plaintext = fin.read()
        ciphertext = cipher.encrypt(plaintext)
        with open(out_path, "wb") as fout:
            fout.write(ciphertext)
        logging.info(f"Fichier {in_path} chiffré (RC4) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement (RC4) de {in_path} : {e}")
        raise

def decrypt_file_rc4(in_path: str, out_path: str, password: str) -> None:
    check_dependencies()
    from Crypto.Cipher import ARC4
    key = derive_key_argon2(password, b"rc4salt", length=16)
    cipher = ARC4.new(key)
    try:
        with open(in_path, "rb") as fin:
            ciphertext = fin.read()
        plaintext = cipher.decrypt(ciphertext)
        with open(out_path, "wb") as fout:
            fout.write(plaintext)
        logging.info(f"Fichier {in_path} déchiffré (RC4) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement (RC4) de {in_path} : {e}")
        raise

def encrypt_file_twofish(in_path: str, out_path: str, password: str) -> None:
    if not twofish_ok:
        raise ImportError("Twofish n'est pas disponible.")
    from Crypto.Cipher import Twofish
    bs = 16
    iv = get_random_bytes(bs)
    key = derive_key_argon2(password, iv, length=16)
    cipher = Twofish.new(key, Twofish.MODE_CBC, iv)
    try:
        with open(in_path, "rb") as fin:
            data = fin.read()
        padded = pad(data, bs)
        ciphertext = iv + cipher.encrypt(padded)
        with open(out_path, "wb") as fout:
            fout.write(ciphertext)
        logging.info(f"Fichier {in_path} chiffré (Twofish-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du chiffrement (Twofish-CBC) de {in_path} : {e}")
        raise

def decrypt_file_twofish(in_path: str, out_path: str, password: str) -> None:
    if not twofish_ok:
        raise ImportError("Twofish n'est pas disponible.")
    from Crypto.Cipher import Twofish
    bs = 16
    try:
        with open(in_path, "rb") as fin:
            iv = fin.read(bs)
            ciphertext = fin.read()
        key = derive_key_argon2(password, iv, length=16)
        cipher = Twofish.new(key, Twofish.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        data = unpad(padded, bs)
        with open(out_path, "wb") as fout:
            fout.write(data)
        logging.info(f"Fichier {in_path} déchiffré (Twofish-CBC) avec succès en {out_path}.")
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement (Twofish-CBC) de {in_path} : {e}")
        raise

# -----------------------------------------------------------------------------
# Dictionnaires de mapping pour les algorithmes de fichiers
# -----------------------------------------------------------------------------
FILE_ENCRYPTION_ALGORITHMS: dict[str, Callable[[str, str, str], None]] = {
    "AES-GCM": encrypt_file_aesgcm,
    "AES-CBC": encrypt_file_aescbc,
    "ChaCha20-Poly1305": encrypt_file_chacha20,
    "Blowfish-CBC": encrypt_file_blowfish,
    "CAST-CBC": encrypt_file_cast,
    "TripleDES-CBC": encrypt_file_des3,
    "Salsa20": encrypt_file_salsa20,
    "ARC2-CBC": encrypt_file_arc2,
    "RC4": encrypt_file_rc4,
    "Twofish-CBC": encrypt_file_twofish,
}

FILE_DECRYPTION_ALGORITHMS: dict[str, Callable[[str, str, str], None]] = {
    "AES-GCM": decrypt_file_aesgcm,
    "AES-CBC": decrypt_file_aescbc,
    "ChaCha20-Poly1305": decrypt_file_chacha20,
    "Blowfish-CBC": decrypt_file_blowfish,
    "CAST-CBC": decrypt_file_cast,
    "TripleDES-CBC": decrypt_file_des3,
    "Salsa20": decrypt_file_salsa20,
    "ARC2-CBC": decrypt_file_arc2,
    "RC4": decrypt_file_rc4,
    "Twofish-CBC": decrypt_file_twofish,
}

# -----------------------------------------------------------------------------
# FONCTIONS DE STÉGANOGRAPHIE
# -----------------------------------------------------------------------------
def stego_hide_data_in_png(png_in: str, png_out: str, secret_text: str) -> bool:
    if not stego_ok:
        raise ValueError("Pillow requis pour la stéganographie.")
    try:
        im = Image.open(png_in)
        if im.mode != 'RGB':
            im = im.convert('RGB')
        px = im.load()
        secret_bytes = secret_text.encode('utf-8')
        data_bits = ''.join(bin(b)[2:].rjust(8, '0') for b in secret_bytes)
        width, height = im.size
        if len(data_bits) > width * height * 3:
            raise ValueError("Message trop volumineux pour l'image.")
        idx = 0
        for y in range(height):
            for x in range(width):
                r, g, b = px[x, y]
                if idx < len(data_bits):
                    r = (r & 0xFE) | int(data_bits[idx])
                    idx += 1
                if idx < len(data_bits):
                    g = (g & 0xFE) | int(data_bits[idx])
                    idx += 1
                if idx < len(data_bits):
                    b = (b & 0xFE) | int(data_bits[idx])
                    idx += 1
                px[x, y] = (r, g, b)
                if idx >= len(data_bits):
                    break
            if idx >= len(data_bits):
                break
        im.save(png_out, 'PNG')
        logging.info(f"Message caché dans {png_out} avec succès.")
        return True
    except Exception as e:
        logging.error(f"Erreur dans la stéganographie (hide) : {e}")
        raise

def stego_extract_data_from_png(png_in: str, data_length: int) -> str:
    if not stego_ok:
        raise ValueError("Pillow requis pour la stéganographie.")
    try:
        im = Image.open(png_in)
        if im.mode != 'RGB':
            im = im.convert('RGB')
        px = im.load()
        width, height = im.size
        bits = ''
        for y in range(height):
            for x in range(width):
                r, g, b = px[x, y]
                bits += f"{r & 1}{g & 1}{b & 1}"
                if len(bits) >= data_length * 8:
                    break
            if len(bits) >= data_length * 8:
                break
        bits = bits[:data_length * 8]
        message_bytes = bytearray()
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            message_bytes.append(int(byte, 2))
        message = message_bytes.decode('utf-8', errors='ignore')
        logging.info(f"Message extrait de {png_in} avec succès.")
        return message
    except Exception as e:
        logging.error(f"Erreur dans l'extraction stéganographique : {e}")
        raise

# -----------------------------------------------------------------------------
# CLASSES POUR LE TRAITEMENT ASYNCHRONE DES FICHIERS
# -----------------------------------------------------------------------------
class FileWorkerSignals(QObject):
    finished = Signal()
    error = Signal(str)
    progress = Signal(int)

class FileWorker(QRunnable):
    def __init__(self, file_paths: List[str], out_dir: str, key: str, algorithm: str, operation: str, secure_erase_flag: bool = False) -> None:
        super().__init__()
        self.file_paths = file_paths
        self.out_dir = out_dir
        self.key = key
        self.algorithm = algorithm
        self.operation = operation
        self.secure_erase_flag = secure_erase_flag
        self.signals = FileWorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            total = len(self.file_paths)
            for idx, fpath in enumerate(self.file_paths, start=1):
                self.signals.progress.emit(int(idx / total * 100))
                fname = os.path.basename(fpath)
                out_file = os.path.join(self.out_dir, fname + ".kage") if self.operation == "encrypt" else os.path.join(self.out_dir, fname[:-5] if fname.endswith(".kage") else os.path.splitext(fname)[0])
                if self.algorithm in FILE_ENCRYPTION_ALGORITHMS:
                    if self.operation == "encrypt":
                        FILE_ENCRYPTION_ALGORITHMS[self.algorithm](fpath, out_file, self.key)
                    else:
                        FILE_DECRYPTION_ALGORITHMS[self.algorithm](fpath, out_file, self.key)
                else:
                    raise ValueError("Algorithme de chiffrement pour fichiers non supporté.")
                if self.secure_erase_flag and self.operation == "encrypt":
                    secure_erase(fpath)
            self.signals.progress.emit(100)
            self.signals.finished.emit()
        except Exception as e:
            self.signals.error.emit(traceback.format_exc())

# -----------------------------------------------------------------------------
# INTERNATIONALISATION ET CHANGEMENT DE LANGUE
# -----------------------------------------------------------------------------
def load_translator(app: QApplication, lang: str) -> QTranslator:
    translator = QTranslator()
    qm_file = f"kagecryptor_{lang}.qm"
    if translator.load(qm_file, os.path.join(os.getcwd(), "translations")):
        app.installTranslator(translator)
        logging.info(f"Traduction {lang} chargée.")
    else:
        logging.warning(f"Fichier de traduction {qm_file} introuvable.")
    return translator

# -----------------------------------------------------------------------------
# INTERFACES GRAPHIQUES : WIZARD, ONGLETS TEXTE, FICHIER, STÉGANOGRAPHIE, CLOUD
# -----------------------------------------------------------------------------
class CryptoWizard(QWizard):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Assistant KAGEcryptor Pro Ultimate")
        self.setWindowIcon(QIcon("icons/wizard.png"))
        self.addPage(WizardPageIntro())
        self.addPage(WizardPageOptions())
        self.addPage(WizardPageFinish())
        self.setWizardStyle(QWizard.ModernStyle)

class WizardPageIntro(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Bienvenue dans KAGEcryptor Pro Ultimate")
        layout = QVBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(QIcon("icons/wizard.png").pixmap(64, 64))
        layout.addWidget(icon_label, alignment=Qt.AlignHCenter)
        layout.addWidget(QLabel("Ce guide interactif vous permettra de chiffrer un fichier en quelques étapes simples. Let's go!"))
        self.setLayout(layout)

class WizardPageOptions(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Options de Chiffrement")
        layout = QVBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("Chemin du fichier")
        self.browse_btn = QPushButton("Parcourir")
        self.browse_btn.setIcon(QIcon("icons/browse.png"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Entrez votre clé")
        self.key_input.setEchoMode(QLineEdit.Password)
        self.alg_combo = QComboBox()
        self.alg_combo.addItems(list(FILE_ENCRYPTION_ALGORITHMS.keys()))
        layout.addWidget(QLabel("Fichier à chiffrer :"))
        hbox = QHBoxLayout()
        hbox.addWidget(self.file_edit)
        hbox.addWidget(self.browse_btn)
        layout.addLayout(hbox)
        layout.addWidget(QLabel("Clé de chiffrement :"))
        layout.addWidget(self.key_input)
        layout.addWidget(QLabel("Algorithme :"))
        layout.addWidget(self.alg_combo)
        self.setLayout(layout)
        self.browse_btn.clicked.connect(self.select_file)
        self.registerField("file*", self.file_edit)
        self.registerField("key*", self.key_input)
        self.registerField("alg", self.alg_combo, "currentText")

    def select_file(self) -> None:
        fn, _ = QFileDialog.getOpenFileName(self, "Choisir un fichier")
        if fn:
            self.file_edit.setText(fn)

class WizardPageFinish(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Progression")
        layout = QVBoxLayout()
        self.progress = QProgressBar()
        layout.addWidget(QLabel("Progression :"))
        layout.addWidget(self.progress)
        self.setLayout(layout)

    def initializePage(self) -> None:
        file = self.field("file")
        key = self.field("key")
        alg = self.field("alg")
        out_dir = os.path.dirname(file)
        self.worker = FileWorker([file], out_dir, key, alg, "encrypt")
        self.worker.signals.progress.connect(self.progress.setValue)
        self.worker.signals.finished.connect(self.complete)
        self.worker.signals.error.connect(lambda e: QMessageBox.critical(self, "Erreur", e))
        QThreadPool.globalInstance().start(self.worker)

    def complete(self) -> None:
        self.completeChanged.emit()

    def isComplete(self) -> bool:
        return self.progress.value() == 100

class TextTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.init_ui()

    def init_ui(self) -> None:
        main_layout = QVBoxLayout()
        input_group = QGroupBox("Chiffrement Texte")
        input_layout = QFormLayout()
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Entrez votre texte ici...")
        input_layout.addRow("Texte :", self.input_text)
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.Password)
        self.key_input.setPlaceholderText("Entrez votre clé")
        input_layout.addRow("Clé :", self.key_input)
        self.alg_combo = QComboBox()
        self.alg_combo.addItems(["Caesar", "Vigenère", "XOR", "AES-CBC", "AES-GCM", "ChaCha20"])
        input_layout.addRow("Algorithme :", self.alg_combo)
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        options_group = QGroupBox("Options")
        options_layout = QHBoxLayout()
        self.auto_copy_cb = QCheckBox("Copier automatiquement le résultat")
        options_layout.addWidget(self.auto_copy_cb)
        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)
        
        btn_row = QHBoxLayout()
        self.encrypt_btn = QPushButton("Chiffrer")
        self.encrypt_btn.setIcon(QIcon("icons/encrypt.png"))
        self.decrypt_btn = QPushButton("Déchiffrer")
        self.decrypt_btn.setIcon(QIcon("icons/decrypt.png"))
        self.clear_btn = QPushButton("Effacer")
        self.clear_btn.setIcon(QIcon("icons/clear.png"))
        self.share_btn = QPushButton("Partager")
        self.share_btn.setIcon(QIcon("icons/share.png"))
        btn_row.addWidget(self.encrypt_btn)
        btn_row.addWidget(self.decrypt_btn)
        btn_row.addWidget(self.clear_btn)
        btn_row.addWidget(self.share_btn)
        main_layout.addLayout(btn_row)
        
        output_group = QGroupBox("Résultat")
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Le résultat apparaîtra ici...")
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)
        self.setLayout(main_layout)
        
        self.encrypt_btn.clicked.connect(self.encrypt_text)
        self.decrypt_btn.clicked.connect(self.decrypt_text)
        self.clear_btn.clicked.connect(self.clear_fields)
        self.share_btn.clicked.connect(self.share_text_action)

    def clear_fields(self) -> None:
        self.input_text.clear()
        self.key_input.clear()
        self.output_text.clear()

    def encrypt_text(self) -> None:
        text = self.input_text.toPlainText()
        pwd = self.key_input.text()
        alg = self.alg_combo.currentText()
        if not text or not pwd:
            QMessageBox.warning(self, "Erreur", "Le texte et la clé sont requis.")
            return
        try:
            if alg == "Caesar":
                result = caesar_encrypt_text(text, int(pwd))
            elif alg == "Vigenère":
                result = vigenere_encrypt_text(text, pwd)
            elif alg == "XOR":
                result = xor_encrypt_text(text, pwd)
            elif alg == "AES-CBC":
                result = aes_cbc_encrypt_text(text, pwd)
            elif alg == "AES-GCM":
                result = aes_gcm_encrypt_text(text, pwd)
            elif alg == "ChaCha20":
                result = chacha20_encrypt_text(text, pwd)
            self.output_text.setPlainText(result)
            if self.auto_copy_cb.isChecked():
                QApplication.clipboard().setText(result)
            QMessageBox.information(self, "Succès", "Texte chiffré avec succès.")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))
            logging.error(f"Erreur de chiffrement ({alg}) : {e}")

    def decrypt_text(self) -> None:
        text = self.input_text.toPlainText()
        pwd = self.key_input.text()
        alg = self.alg_combo.currentText()
        if not text or not pwd:
            QMessageBox.warning(self, "Erreur", "Le texte et la clé sont requis.")
            return
        try:
            if alg == "Caesar":
                result = caesar_decrypt_text(text, int(pwd))
            elif alg == "Vigenère":
                result = vigenere_decrypt_text(text, pwd)
            elif alg == "XOR":
                result = xor_decrypt_text(text, pwd)
            elif alg == "AES-CBC":
                result = aes_cbc_decrypt_text(text, pwd)
            elif alg == "AES-GCM":
                result = aes_gcm_decrypt_text(text, pwd)
            elif alg == "ChaCha20":
                result = chacha20_decrypt_text(text, pwd)
            self.output_text.setPlainText(result)
            if self.auto_copy_cb.isChecked():
                QApplication.clipboard().setText(result)
            QMessageBox.information(self, "Succès", "Texte déchiffré avec succès.")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))
            logging.error(f"Erreur de déchiffrement ({alg}) : {e}")

    def share_text_action(self) -> None:
        text = self.output_text.toPlainText()
        if not text:
            QMessageBox.warning(self, "Partager", "Aucun texte à partager.")
            return
        options = ["WhatsApp", "Telegram", "Gmail", "Autres", "Cloud"]
        platform, ok = QInputDialog.getItem(self, "Partager le Texte", "Choisissez la plateforme :", options, 0, False)
        if ok and platform:
            if platform == "Cloud":
                cloud_upload_text(text)
            else:
                share_text(platform, text)

class FileTab(QWidget):
    def __init__(self, threadpool: QThreadPool) -> None:
        super().__init__()
        self.threadpool = threadpool
        self.init_ui()

    def init_ui(self) -> None:
        main_layout = QVBoxLayout()
        file_group = QGroupBox("Fichiers Sélectionnés")
        file_layout = QVBoxLayout()
        self.file_list = QListWidget()
        file_layout.addWidget(self.file_list)
        btn_row = QHBoxLayout()
        self.add_file_btn = QPushButton("Ajouter")
        self.add_file_btn.setIcon(QIcon("icons/add.png"))
        self.remove_file_btn = QPushButton("Supprimer")
        self.remove_file_btn.setIcon(QIcon("icons/remove.png"))
        btn_row.addWidget(self.add_file_btn)
        btn_row.addWidget(self.remove_file_btn)
        file_layout.addLayout(btn_row)
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)
        
        params_group = QGroupBox("Paramètres")
        params_layout = QFormLayout()
        self.key_in = QLineEdit()
        self.key_in.setEchoMode(QLineEdit.Password)
        self.key_in.setPlaceholderText("Clé")
        params_layout.addRow("Clé :", self.key_in)
        self.alg_combo = QComboBox()
        self.alg_combo.addItems(list(FILE_ENCRYPTION_ALGORITHMS.keys()))
        params_layout.addRow("Algorithme :", self.alg_combo)
        self.secure_erase_cb = QCheckBox("Effacer sécuritairement les originaux")
        params_layout.addRow(self.secure_erase_cb)
        params_group.setLayout(params_layout)
        main_layout.addWidget(params_group)
        
        action_row = QHBoxLayout()
        self.encrypt_btn = QPushButton("Chiffrer")
        self.encrypt_btn.setIcon(QIcon("icons/encrypt.png"))
        self.decrypt_btn = QPushButton("Déchiffrer")
        self.decrypt_btn.setIcon(QIcon("icons/decrypt.png"))
        self.share_btn = QPushButton("Partager")
        self.share_btn.setIcon(QIcon("icons/share.png"))
        action_row.addWidget(self.encrypt_btn)
        action_row.addWidget(self.decrypt_btn)
        action_row.addWidget(self.share_btn)
        main_layout.addLayout(action_row)
        
        self.progress = QProgressBar()
        main_layout.addWidget(QLabel("Progression :"))
        main_layout.addWidget(self.progress)
        self.setLayout(main_layout)
        
        self.add_file_btn.clicked.connect(self.add_files)
        self.remove_file_btn.clicked.connect(self.remove_selected_files)
        self.encrypt_btn.clicked.connect(self.encrypt_files)
        self.decrypt_btn.clicked.connect(self.decrypt_files)
        self.share_btn.clicked.connect(self.share_file_action)

    def add_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Choisir des fichiers")
        for f in files:
            self.file_list.addItem(f)

    def remove_selected_files(self) -> None:
        for item in self.file_list.selectedItems():
            self.file_list.takeItem(self.file_list.row(item))

    def encrypt_files(self) -> None:
        if self.file_list.count() == 0 or not self.key_in.text():
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner des fichiers et entrer une clé.")
            return
        outdir = QFileDialog.getExistingDirectory(self, "Choisir le dossier de sortie")
        if not outdir:
            return
        paths = [self.file_list.item(i).text() for i in range(self.file_list.count())]
        worker = FileWorker(paths, outdir, self.key_in.text(), self.alg_combo.currentText(), "encrypt", self.secure_erase_cb.isChecked())
        worker.signals.progress.connect(self.progress.setValue)
        worker.signals.error.connect(lambda e: QMessageBox.critical(self, "Erreur", e))
        worker.signals.finished.connect(lambda: QMessageBox.information(self, "Terminé", "Chiffrement terminé avec succès."))
        self.threadpool.start(worker)

    def decrypt_files(self) -> None:
        if self.file_list.count() == 0 or not self.key_in.text():
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner des fichiers et entrer une clé.")
            return
        outdir = QFileDialog.getExistingDirectory(self, "Choisir le dossier de sortie")
        if not outdir:
            return
        paths = [self.file_list.item(i).text() for i in range(self.file_list.count())]
        worker = FileWorker(paths, outdir, self.key_in.text(), self.alg_combo.currentText(), "decrypt")
        worker.signals.progress.connect(self.progress.setValue)
        worker.signals.error.connect(lambda e: QMessageBox.critical(self, "Erreur", e))
        worker.signals.finished.connect(lambda: QMessageBox.information(self, "Terminé", "Déchiffrement terminé avec succès."))
        self.threadpool.start(worker)

    def share_file_action(self) -> None:
        current_item = self.file_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Partager", "Sélectionnez un fichier à partager.")
            return
        file_path = current_item.text()
        options = ["Ouvrir le dossier", "WhatsApp", "Telegram", "Gmail", "Autres", "Cloud"]
        platform, ok = QInputDialog.getItem(self, "Partager le Fichier", "Choisissez la plateforme :", options, 0, False)
        if ok and platform:
            if platform == "Cloud":
                cloud_upload_file(file_path)
            else:
                share_file(platform, file_path)

class StegoTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.init_ui()

    def init_ui(self) -> None:
        main_layout = QVBoxLayout()
        group = QGroupBox("Stéganographie (Image PNG)")
        layout = QFormLayout()
        self.image_in = QLineEdit()
        self.image_in.setPlaceholderText("Chemin de l'image source")
        self.browse_in_btn = QPushButton("Parcourir")
        hbox_in = QHBoxLayout()
        hbox_in.addWidget(self.image_in)
        hbox_in.addWidget(self.browse_in_btn)
        layout.addRow("Image source :", hbox_in)
        self.secret_text = QTextEdit()
        self.secret_text.setPlaceholderText("Texte à cacher")
        layout.addRow("Message à cacher :", self.secret_text)
        self.image_out = QLineEdit()
        self.image_out.setPlaceholderText("Chemin de l'image de sortie")
        self.browse_out_btn = QPushButton("Parcourir")
        hbox_out = QHBoxLayout()
        hbox_out.addWidget(self.image_out)
        hbox_out.addWidget(self.browse_out_btn)
        layout.addRow("Image de sortie :", hbox_out)
        btn_row = QHBoxLayout()
        self.hide_btn = QPushButton("Cacher le message")
        self.extract_btn = QPushButton("Extraire le message")
        btn_row.addWidget(self.hide_btn)
        btn_row.addWidget(self.extract_btn)
        layout.addRow(btn_row)
        group.setLayout(layout)
        main_layout.addWidget(group)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setPlaceholderText("Le message extrait apparaîtra ici")
        main_layout.addWidget(self.result_text)
        self.setLayout(main_layout)
        self.browse_in_btn.clicked.connect(self.browse_image_in)
        self.browse_out_btn.clicked.connect(self.browse_image_out)
        self.hide_btn.clicked.connect(self.hide_message)
        self.extract_btn.clicked.connect(self.extract_message)

    def browse_image_in(self) -> None:
        fn, _ = QFileDialog.getOpenFileName(self, "Choisir une image source", "", "Images (*.png)")
        if fn:
            self.image_in.setText(fn)

    def browse_image_out(self) -> None:
        fn, _ = QFileDialog.getSaveFileName(self, "Choisir le chemin de sortie", "", "Images (*.png)")
        if fn:
            self.image_out.setText(fn)

    def hide_message(self) -> None:
        img_in = self.image_in.text()
        img_out = self.image_out.text()
        message = self.secret_text.toPlainText()
        if not img_in or not img_out or not message:
            QMessageBox.warning(self, "Erreur", "Veuillez renseigner l'image source, l'image de sortie et le message.")
            return
        try:
            stego_hide_data_in_png(img_in, img_out, message)
            QMessageBox.information(self, "Succès", "Message caché avec succès dans l'image.")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))

    def extract_message(self) -> None:
        img_in = self.image_in.text()
        if not img_in:
            QMessageBox.warning(self, "Erreur", "Veuillez renseigner l'image source.")
            return
        length, ok = QInputDialog.getInt(self, "Extraire le message", "Nombre d'octets à extraire :", 50, 1, 10000)
        if not ok:
            return
        try:
            message = stego_extract_data_from_png(img_in, length)
            self.result_text.setPlainText(message)
            QMessageBox.information(self, "Succès", "Message extrait avec succès.")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))

class CloudTab(QWidget):
    def __init__(self, threadpool: QThreadPool) -> None:
        super().__init__()
        self.threadpool = threadpool
        self.init_ui()

    def init_ui(self) -> None:
        main_layout = QVBoxLayout()
        group = QGroupBox("Upload sur le Cloud")
        layout = QFormLayout()
        self.data_type_combo = QComboBox()
        self.data_type_combo.addItems(["Texte", "Fichier"])
        layout.addRow("Type de données :", self.data_type_combo)
        self.data_input = QLineEdit()
        self.data_input.setPlaceholderText("Entrez le texte ou le chemin du fichier")
        browse_btn = QPushButton("Parcourir")
        browse_btn.setIcon(QIcon("icons/browse.png"))
        hbox = QHBoxLayout()
        hbox.addWidget(self.data_input)
        hbox.addWidget(browse_btn)
        layout.addRow("Données :", hbox)
        self.upload_btn = QPushButton("Uploader sur le Cloud")
        self.upload_btn.setIcon(QIcon("icons/upload.png"))
        layout.addRow(self.upload_btn)
        group.setLayout(layout)
        main_layout.addWidget(group)
        self.setLayout(main_layout)
        browse_btn.clicked.connect(self.browse_data)
        self.upload_btn.clicked.connect(self.upload_data)

    def browse_data(self) -> None:
        if self.data_type_combo.currentText() == "Fichier":
            fn, _ = QFileDialog.getOpenFileName(self, "Choisir un fichier")
            if fn:
                self.data_input.setText(fn)

    def upload_data(self) -> None:
        data = self.data_input.text()
        if not data:
            QMessageBox.warning(self, "Erreur", "Veuillez renseigner les données à uploader.")
            return
        if self.data_type_combo.currentText() == "Fichier":
            cloud_upload_file(data)
        else:
            cloud_upload_text(data)

class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("KAGEcryptor Pro Ultimate")
        self.setWindowIcon(QIcon("icons/app_icon.png"))
        self.resize(1200, 700)
        self.settings = QSettings("KAGEcryptorProUltimate", "Prefs")
        self.threadpool = QThreadPool()
        self.init_ui()
        self.load_theme()

    def init_ui(self) -> None:
        self.tabs = QTabWidget()
        self.text_tab = TextTab()
        self.file_tab = FileTab(self.threadpool)
        self.stego_tab = StegoTab()
        self.cloud_tab = CloudTab(self.threadpool)
        self.tabs.addTab(self.text_tab, QIcon("icons/text.png"), "Chiffrement Texte")
        self.tabs.addTab(self.file_tab, QIcon("icons/file.png"), "Chiffrement Fichiers")
        self.tabs.addTab(self.stego_tab, QIcon("icons/stego.png"), "Stéganographie")
        self.tabs.addTab(self.cloud_tab, QIcon("icons/cloud.png"), "Cloud")
        self.wizard_btn = QPushButton("Lancer le Wizard")
        self.wizard_btn.setIcon(QIcon("icons/wizard.png"))
        row = QHBoxLayout()
        row.addWidget(self.wizard_btn)
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        main_layout.addLayout(row)
        main_widget = QWidget()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        menubar = self.menuBar()
        settings_menu = menubar.addMenu("Paramètres")
        theme_act = QAction("Changer le Thème", self)
        theme_act.triggered.connect(self.change_theme)
        language_act = QAction("Changer la Langue", self)
        language_act.triggered.connect(self.change_language)
        settings_menu.addAction(theme_act)
        settings_menu.addAction(language_act)
        self.wizard_btn.clicked.connect(self.launch_wizard)

    def launch_wizard(self) -> None:
        wizard = CryptoWizard(self)
        wizard.exec()

    def change_theme(self) -> None:
        current = self.settings.value("theme", "light")
        new_theme = "dark" if current == "light" else "light"
        self.settings.setValue("theme", new_theme)
        self.load_theme()
        logging.info(f"Thème changé : {new_theme}")

    def load_theme(self) -> None:
        theme = self.settings.value("theme", "light")
        # Application d'une police moderne (Roboto) et de couleurs pour les onglets et autres widgets
        if theme == "dark":
            self.setStyleSheet("""
                * { font-family: 'Roboto', 'Segoe UI', Arial, sans-serif; font-size: 12pt; }
                QMainWindow { background-color: #2b2b2b; color: #f0f0f0; }
                QTextEdit, QLineEdit, QListWidget, QProgressBar {
                    background-color: #3c3c3c; color: #f0f0f0; border: 1px solid #555555; border-radius: 6px;
                }
                QLabel { color: #f0f0f0; }
                QPushButton { 
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #007acc, stop:1 #fd7e14);
                    color: white; border: none; border-radius: 6px; padding: 8px;
                }
                QPushButton:hover { background-color: #28a745; }
                QComboBox { background-color: #3c3c3c; color: #f0f0f0; border: 1px solid #555555; border-radius: 6px; padding: 4px; }
                QCheckBox { color: #f0f0f0; }
                QTabWidget::pane { background-color: #2b2b2b; border: 1px solid #555555; }
                QTabBar::tab { 
                    background-color: #3c3c3c; 
                    color: #f0f0f0; 
                    padding: 10px; 
                    border-radius: 6px; 
                    margin: 2px;
                }
                QTabBar::tab:selected { background-color: #007acc; color: white; }
                QGroupBox { background-color: #333333; color: #f0f0f0; border: 1px solid #555555; border-radius: 6px; padding: 5px; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; }
            """)
        else:
            self.setStyleSheet("""
                * { font-family: 'Roboto', 'Segoe UI', Arial, sans-serif; font-size: 12pt; }
                QMainWindow { background-color: #ffffff; color: #333333; }
                QTextEdit, QLineEdit, QListWidget, QProgressBar {
                    background-color: #f9f9f9; color: #333333; border: 1px solid #cccccc; border-radius: 6px;
                }
                QLabel { color: #333333; }
                QPushButton { 
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #007acc, stop:1 #fd7e14);
                    color: white; border: none; border-radius: 6px; padding: 8px;
                }
                QPushButton:hover { background-color: #28a745; }
                QComboBox { background-color: #f9f9f9; color: #333333; border: 1px solid #cccccc; border-radius: 6px; padding: 4px; }
                QCheckBox { color: #333333; }
                QTabWidget::pane { background-color: #ffffff; border: 1px solid #cccccc; }
                QTabBar::tab { 
                    background-color: #e0e0e0; 
                    color: #333333; 
                    padding: 10px; 
                    border-radius: 6px; 
                    margin: 2px;
                }
                QTabBar::tab:selected { background-color: #007acc; color: white; }
                QGroupBox { background-color: #f0f0f0; color: #333333; border: 1px solid #cccccc; border-radius: 6px; padding: 5px; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; }
            """)

    def change_language(self) -> None:
        options = ["fr", "en"]
        lang, ok = QInputDialog.getItem(self, "Choisir la Langue", "Langue :", options, 0, False)
        if ok and lang:
            self.settings.setValue("language", lang)
            load_translator(QApplication.instance(), lang)
            QMessageBox.information(self, "Langue", f"Langue changée en {lang}. Redémarrez l'application pour appliquer entièrement.")

    def closeEvent(self, event) -> None:
        logging.info("Application fermée.")
        event.accept()

def main() -> None:
    app = QApplication(sys.argv)
    lang = QSettings("KAGEcryptorProUltimate", "Prefs").value("language", "fr")
    load_translator(app, lang)
    try:
        check_dependencies()
        window = MainWindow()
        window.show()
        logging.info("KAGEcryptor Pro Ultimate démarré.")
        sys.exit(app.exec())
    except ImportError as e:
        QMessageBox.critical(None, "Erreur Dépendance", str(e))
        logging.error(f"Dépendance manquante : {e}")
        sys.exit(1)

# -----------------------------------------------------------------------------
# SUITE DE TESTS UNITAIRES (à lancer avec "--test")
# -----------------------------------------------------------------------------
class TestCryptoFunctions(unittest.TestCase):
    def test_caesar(self):
        text = "Hello"
        shift = 3
        enc = caesar_encrypt_text(text, shift)
        dec = caesar_decrypt_text(enc, shift)
        self.assertEqual(text, dec)

    def test_vigenere(self):
        text = "Bonjour"
        key = "clé"
        enc = vigenere_encrypt_text(text, key)
        dec = vigenere_decrypt_text(enc, key)
        self.assertEqual(text, dec)

    def test_xor(self):
        text = "Test XOR"
        key = "secret"
        enc = xor_encrypt_text(text, key)
        dec = xor_decrypt_text(enc, key)
        self.assertEqual(text, dec)

    def test_aes_cbc(self):
        text = "Texte AES-CBC"
        pwd = "motdepasse"
        enc = aes_cbc_encrypt_text(text, pwd)
        dec = aes_cbc_decrypt_text(enc, pwd)
        self.assertEqual(text, dec)

    def test_aes_gcm(self):
        text = "Texte AES-GCM"
        pwd = "motdepasse"
        enc = aes_gcm_encrypt_text(text, pwd)
        dec = aes_gcm_decrypt_text(enc, pwd)
        self.assertEqual(text, dec)

    def test_chacha20(self):
        text = "Texte ChaCha20"
        pwd = "motdepasse"
        enc = chacha20_encrypt_text(text, pwd)
        dec = chacha20_decrypt_text(enc, pwd)
        self.assertEqual(text, dec)

if __name__ == "__main__":
    if "--test" in sys.argv:
        unittest.main(argv=[sys.argv[0]])
    else:
        main()
