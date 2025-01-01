# secure_ticket.py
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import json
import qrcode
from dataclasses import dataclass
from typing import Dict, Tuple
import logging

# Thiết lập logging cho admin
logging.basicConfig(level=logging.INFO)
admin_logger = logging.getLogger('admin_logger')


class AdminLogger:
    @staticmethod
    def log_encryption_steps(original_data: dict, encrypted_data: str, step_name: str):
        admin_logger.info(f"\n{'=' * 50}")
        admin_logger.info(f"ADMIN VIEW - {step_name}")
        admin_logger.info("Original Data:")
        admin_logger.info(json.dumps(original_data, indent=2, ensure_ascii=False))
        admin_logger.info("\nEncrypted Data (Base64):")
        admin_logger.info(encrypted_data)
        admin_logger.info(f"{'=' * 50}\n")


class AdvancedEncryption:
    def __init__(self):
        self.key = os.urandom(32)
        self.server_key = os.urandom(32)

    def encrypt_text(self, text: str) -> Tuple[bytes, bytes]:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        padded_text = self._pad(text.encode())
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()

        # Log raw ciphertext for admin
        admin_logger.info(f"\nRaw Ciphertext (Hex):")
        admin_logger.info(ciphertext.hex())

        return ciphertext, iv

    def decrypt_text(self, ciphertext: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        padded_text = decryptor.update(ciphertext) + decryptor.finalize()
        return self._unpad(padded_text).decode()

    def _pad(self, data: bytes) -> bytes:
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _unpad(self, data: bytes) -> bytes:
        padding_length = data[-1]
        return data[:-padding_length]

@dataclass
class TicketInfo:
    full_name: str
    birth_date: str
    id_number: str
    address: str
    departure_time: str
    ticket_class: str
    seat_number: str
    departure_station: str
    arrival_station: str

class SecureTicketSystem:
    def __init__(self):
        self.encryption = AdvancedEncryption()
        self.admin_logger = AdminLogger()

    def create_secure_ticket(self, ticket_info: TicketInfo) -> Dict[str, str]:
        # Tạo dữ liệu công khai và riêng tư
        public_data = {
            "full_name": ticket_info.full_name,
            "birth_date": ticket_info.birth_date,
            "ticket_class": ticket_info.ticket_class,
            "departure_time": ticket_info.departure_time,
            "seat_number": ticket_info.seat_number,
            "arrival_station": ticket_info.arrival_station
        }

        private_data = {
            "id_number": ticket_info.id_number,
            "address": ticket_info.address,
            "departure_station": ticket_info.departure_station
        }

        # Log original data
        admin_logger.info("\n=== ADMIN VIEW - Original Ticket Data ===")
        admin_logger.info("Public Data:")
        admin_logger.info(json.dumps(public_data, indent=2, ensure_ascii=False))
        admin_logger.info("\nPrivate Data:")
        admin_logger.info(json.dumps(private_data, indent=2, ensure_ascii=False))

        # Chuyển đổi thành JSON
        public_json = json.dumps(public_data)
        private_json = json.dumps(private_data)

        # Mã hóa
        public_ciphertext, public_iv = self.encryption.encrypt_text(public_json)
        private_ciphertext, private_iv = self.encryption.encrypt_text(private_json)

        # Kết hợp IV và ciphertext
        public_encrypted = base64.b64encode(public_iv + public_ciphertext).decode()
        private_encrypted = base64.b64encode(private_iv + private_ciphertext).decode()

        # Log encrypted data
        self.admin_logger.log_encryption_steps(
            public_data,
            public_encrypted,
            "Public Ticket Data Encryption"
        )
        self.admin_logger.log_encryption_steps(
            private_data,
            private_encrypted,
            "Private Ticket Data Encryption"
        )

        # Tạo QR code
        qr_code = self.generate_qr_code(public_encrypted)

        return {
            "server_data": private_encrypted,
            "public_data": public_encrypted,
            "qr_code": qr_code
        }

    def generate_qr_code(self, encrypted_data: str) -> str:
        admin_logger.info("\n=== ADMIN VIEW - QR Code Data ===")
        admin_logger.info(f"Encrypted data being encoded in QR:")
        admin_logger.info(encrypted_data)

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(encrypted_data)
        qr.make(fit=True)

        qr_image = qr.make_image(fill_color="black", back_color="white")
        qr_path = "user_ticket.png"
        qr_image.save(qr_path)
        return qr_path

    def decrypt_ticket_data(self, encrypted_data: str) -> Dict:
        try:
            admin_logger.info("\n=== ADMIN VIEW - Decryption Process ===")
            admin_logger.info(f"Attempting to decrypt data:")
            admin_logger.info(encrypted_data)

            combined_data = base64.b64decode(encrypted_data)
            iv = combined_data[:16]
            ciphertext = combined_data[16:]

            decrypted_text = self.encryption.decrypt_text(ciphertext, iv)
            decrypted_data = json.loads(decrypted_text)

            admin_logger.info("\nDecrypted result:")
            admin_logger.info(json.dumps(decrypted_data, indent=2, ensure_ascii=False))

            return decrypted_data
        except Exception as e:
            admin_logger.error(f"Decryption error: {str(e)}")
            return None

    def verify_ticket(self, qr_data: str, server_data: str) -> bool:
        try:
            admin_logger.info("\n=== ADMIN VIEW - Ticket Verification ===")
            public_ticket = self.decrypt_ticket_data(qr_data)
            private_ticket = self.decrypt_ticket_data(server_data)

            is_valid = public_ticket is not None and private_ticket is not None
            admin_logger.info(f"\nTicket validation result: {'Valid' if is_valid else 'Invalid'}")

            return is_valid
        except Exception as e:
            admin_logger.error(f"Verification error: {str(e)}")
            return False