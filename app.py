import os
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import json
import secrets
import tempfile
import logging

# Cấu hình logging để dễ dàng gỡ lỗi
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Cấu hình thư mục tải lên an toàn
# Sử dụng thư mục tạm thời để tránh lưu trữ vĩnh viễn trên server
UPLOAD_FOLDER = tempfile.gettempdir()
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Giới hạn kích thước file 16MB

# Đảm bảo thư mục tải lên tồn tại
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    logging.info(f"Created temporary upload directory: {UPLOAD_FOLDER}")

# --- Hàm hỗ trợ chung ---
def save_temp_file(file_storage):
    """
    Lưu file tạm thời vào thư mục UPLOAD_FOLDER và trả về đường dẫn an toàn.
    """
    if file_storage and file_storage.filename:
        filename = secure_filename(file_storage.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file_storage.save(filepath)
        logging.info(f"File saved temporarily to: {filepath}")
        return filepath
    return None

def load_private_key_from_pem_string(pem_data_str, password=None):
    """
    Tải khóa riêng từ chuỗi PEM.
    """
    try:
        private_key = serialization.load_pem_private_key(
            pem_data_str.encode('utf-8'),
            password=password.encode('utf-8') if password else None,
            backend=default_backend()
        )
        logging.info("Private key loaded successfully.")
        return private_key
    except ValueError as e:
        logging.error(f"Error loading private key: {e}")
        raise ValueError("Invalid private key or incorrect password.")
    except Exception as e:
        logging.error(f"Unexpected error loading private key: {e}")
        raise ValueError("Failed to load private key due to an unexpected error.")

def load_public_key_from_pem_string(pem_data_str):
    """
    Tải khóa công khai từ chuỗi PEM.
    """
    try:
        public_key = serialization.load_pem_public_key(
            pem_data_str.encode('utf-8'),
            backend=default_backend()
        )
        logging.info("Public key loaded successfully.")
        return public_key
    except ValueError as e:
        logging.error(f"Error loading public key: {e}")
        raise ValueError("Invalid public key format.")
    except Exception as e:
        logging.error(f"Unexpected error loading public key: {e}")
        raise ValueError("Failed to load public key due to an unexpected error.")

# --- API Endpoints ---

@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    """
    Tạo cặp khóa RSA mới (khóa riêng và khóa công khai).
    Khóa riêng có thể được bảo vệ bằng mật khẩu.
    """
    try:
        data = request.get_json()
        password = data.get('password') # Mật khẩu để mã hóa khóa riêng

        # Tạo khóa riêng RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537, # Giá trị công khai tiêu chuẩn
            key_size=2048,        # Kích thước khóa 2048 bit, an toàn cho hầu hết các trường hợp
            backend=default_backend()
        )

        # Tạo khóa công khai từ khóa riêng
        public_key = private_key.public_key()

        # Mã hóa khóa riêng thành chuỗi PEM
        # Sử dụng PKCS8 để bảo vệ khóa riêng bằng mật khẩu nếu có
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        ).decode('utf-8')

        # Mã hóa khóa công khai thành chuỗi PEM
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        logging.info("RSA key pair generated successfully.")
        return jsonify({
            "private_key": private_pem,
            "public_key": public_pem
        })
    except Exception as e:
        logging.error(f"Error generating keys: {e}", exc_info=True)
        return jsonify({"error": "Failed to generate keys", "details": str(e)}), 500

@app.route('/api/upload-and-sign', methods=['POST'])
def upload_and_sign():
    """
    Endpoint để tải lên file và ký số file đó bằng khóa riêng được cung cấp.
    Trả về file gốc cùng với chữ ký số dưới dạng Base64.
    """
    if 'file' not in request.files:
        logging.warning("No file part in request for signing.")
        return jsonify({"error": "No file part"}), 400
    if 'private_key' not in request.form:
        logging.warning("No private key provided for signing.")
        return jsonify({"error": "Private key is missing"}), 400

    file = request.files['file']
    private_key_pem = request.form['private_key']
    private_key_password = request.form.get('private_key_password') # Có thể có hoặc không

    if file.filename == '':
        logging.warning("No selected file for signing.")
        return jsonify({"error": "No selected file"}), 400

    filepath = None
    try:
        # Lưu file tạm thời
        filepath = save_temp_file(file)
        if not filepath:
            logging.error("Failed to save temporary file for signing.")
            return jsonify({"error": "Failed to save file"}), 500

        with open(filepath, 'rb') as f:
            file_data = f.read()

        # Tải khóa riêng
        private_key = load_private_key_from_pem_string(private_key_pem, private_key_password)

        # Tạo hàm băm của file (SHA256)
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(file_data)
        digest = hasher.finalize()

        # Ký hàm băm bằng khóa riêng RSA
        signature = private_key.sign(
            digest,
            padding.PSS( # PSS (Probabilistic Signature Scheme) là lược đồ đệm được khuyến nghị
                mgf=padding.MGF1(hashes.SHA256()), # MGF1 với SHA256
                salt_length=padding.PSS.MAX_LENGTH # Chiều dài salt tối đa
            ),
            hashes.SHA256() # Hàm băm được sử dụng
        )

        logging.info(f"File '{file.filename}' signed successfully.")

        # Trả về tên file gốc và chữ ký Base64
        return jsonify({
            "original_filename": file.filename,
            "signature": base64.b64encode(signature).decode('utf-8')
        })

    except ValueError as e:
        logging.error(f"Signing failed: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.error(f"Unexpected error during signing: {e}", exc_info=True)
        return jsonify({"error": "Failed to sign file due to an unexpected error", "details": str(e)}), 500
    finally:
        # Xóa file tạm thời sau khi xử lý xong
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
            logging.info(f"Temporary file '{filepath}' removed.")

@app.route('/api/verify-signature', methods=['POST'])
def verify_signature():
    """
    Endpoint để xác minh chữ ký số của một file.
    Cần file gốc, chữ ký số (Base64), và khóa công khai của người ký.
    """
    if 'file' not in request.files:
        logging.warning("No file part in request for verification.")
        return jsonify({"error": "No file part"}), 400
    if 'signature' not in request.form:
        logging.warning("No signature provided for verification.")
        return jsonify({"error": "Signature is missing"}), 400
    if 'public_key' not in request.form:
        logging.warning("No public key provided for verification.")
        return jsonify({"error": "Public key is missing"}), 400

    file = request.files['file']
    signature_b64 = request.form['signature']
    public_key_pem = request.form['public_key']

    if file.filename == '':
        logging.warning("No selected file for verification.")
        return jsonify({"error": "No selected file"}), 400

    filepath = None
    try:
        # Lưu file tạm thời
        filepath = save_temp_file(file)
        if not filepath:
            logging.error("Failed to save temporary file for verification.")
            return jsonify({"error": "Failed to save file"}), 500

        with open(filepath, 'rb') as f:
            file_data = f.read()

        # Giải mã chữ ký từ Base64
        signature = base64.b64decode(signature_b64)

        # Tải khóa công khai
        public_key = load_public_key_from_pem_string(public_key_pem)

        # Tạo hàm băm của file (SHA256)
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(file_data)
        digest = hasher.finalize()

        # Xác minh chữ ký
        try:
            public_key.verify(
                signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logging.info(f"Signature for file '{file.filename}' is VALID.")
            return jsonify({"status": "Signature VALID", "filename": file.filename})
        except Exception as e:
            logging.warning(f"Signature for file '{file.filename}' is INVALID: {e}")
            return jsonify({"status": "Signature INVALID", "details": str(e), "filename": file.filename})

    except ValueError as e:
        logging.error(f"Verification failed: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.error(f"Unexpected error during verification: {e}", exc_info=True)
        return jsonify({"error": "Failed to verify signature due to an unexpected error", "details": str(e)}), 500
    finally:
        # Xóa file tạm thời sau khi xử lý xong
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
            logging.info(f"Temporary file '{filepath}' removed.")

@app.route('/api/upload-and-encrypt', methods=['POST'])
def upload_and_encrypt():
    """
    Endpoint để tải lên file và mã hóa file đó bằng khóa công khai của người nhận.
    Sử dụng AES cho nội dung file và RSA để mã hóa khóa AES.
    Trả về file đã mã hóa và khóa AES đã mã hóa (Base64).
    """
    if 'file' not in request.files:
        logging.warning("No file part in request for encryption.")
        return jsonify({"error": "No file part"}), 400
    if 'recipient_public_key' not in request.form:
        logging.warning("No recipient public key provided for encryption.")
        return jsonify({"error": "Recipient public key is missing"}), 400

    file = request.files['file']
    recipient_public_key_pem = request.form['recipient_public_key']

    if file.filename == '':
        logging.warning("No selected file for encryption.")
        return jsonify({"error": "No selected file"}), 400

    filepath = None
    try:
        # Lưu file tạm thời
        filepath = save_temp_file(file)
        if not filepath:
            logging.error("Failed to save temporary file for encryption.")
            return jsonify({"error": "Failed to save file"}), 500

        with open(filepath, 'rb') as f:
            file_data = f.read()

        # Tải khóa công khai của người nhận
        recipient_public_key = load_public_key_from_pem_string(recipient_public_key_pem)

        # 1. Tạo khóa đối xứng ngẫu nhiên cho AES (khóa phiên)
        aes_key = secrets.token_bytes(32) # Khóa 256-bit cho AES-256
        logging.info("Generated AES session key.")

        # 2. Tạo IV (Initialization Vector) ngẫu nhiên cho AES
        iv = secrets.token_bytes(16) # IV 128-bit cho AES

        # 3. Mã hóa file bằng AES trong chế độ CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Đệm file data để phù hợp với khối AES (block size 16 bytes)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_file_data = encryptor.update(padded_data) + encryptor.finalize()
        logging.info("File encrypted with AES.")

        # 4. Mã hóa khóa AES và IV bằng khóa công khai RSA của người nhận
        # Gói khóa AES và IV lại thành một JSON string
        encrypted_session_data = json.dumps({
            "aes_key": base64.b64encode(aes_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8')
        }).encode('utf-8')

        # Mã hóa gói dữ liệu phiên bằng khóa công khai RSA của người nhận
        encrypted_session_key_and_iv = recipient_public_key.encrypt(
            encrypted_session_data,
            padding.OAEP( # OAEP (Optimal Asymmetric Encryption Padding) là lược đồ đệm được khuyến nghị
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logging.info("AES key and IV encrypted with recipient's public key.")

        # Trả về file đã mã hóa và khóa AES/IV đã mã hóa (Base64)
        return jsonify({
            "encrypted_file_data": base64.b64encode(encrypted_file_data).decode('utf-8'),
            "encrypted_session_key_and_iv": base64.b64encode(encrypted_session_key_and_iv).decode('utf-8'),
            "original_filename": file.filename # Giữ lại tên gốc để người nhận dễ xác định
        })

    except ValueError as e:
        logging.error(f"Encryption failed: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.error(f"Unexpected error during encryption: {e}", exc_info=True)
        return jsonify({"error": "Failed to encrypt file due to an unexpected error", "details": str(e)}), 500
    finally:
        # Xóa file tạm thời
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
            logging.info(f"Temporary file '{filepath}' removed.")

@app.route('/api/decrypt-file', methods=['POST'])
def decrypt_file():
    """
    Endpoint để giải mã file bằng khóa riêng của người nhận.
    Cần file đã mã hóa (Base64), khóa AES đã mã hóa (Base64), và khóa riêng của người nhận.
    Trả về file đã giải mã.
    """
    data = request.get_json() # Nhận dữ liệu JSON
    if not data:
        logging.warning("No JSON data provided for decryption.")
        return jsonify({"error": "Invalid request: No JSON data."}), 400

    encrypted_file_data_b64 = data.get('encrypted_file_data')
    encrypted_session_key_and_iv_b64 = data.get('encrypted_session_key_and_iv')
    recipient_private_key_pem = data.get('recipient_private_key')
    private_key_password = data.get('private_key_password') # Mật khẩu của khóa riêng

    if not all([encrypted_file_data_b64, encrypted_session_key_and_iv_b64, recipient_private_key_pem]):
        logging.warning("Missing data for decryption.")
        return jsonify({"error": "Missing encrypted file data, encrypted session key/IV, or recipient private key."}), 400

    try:
        # Giải mã các chuỗi Base64
        encrypted_file_data = base64.b64decode(encrypted_file_data_b64)
        encrypted_session_key_and_iv = base64.b64decode(encrypted_session_key_and_iv_b64)

        # Tải khóa riêng của người nhận
        recipient_private_key = load_private_key_from_pem_string(recipient_private_key_pem, private_key_password)

        # 1. Giải mã khóa AES và IV bằng khóa riêng RSA của người nhận
        decrypted_session_data_bytes = recipient_private_key.decrypt(
            encrypted_session_key_and_iv,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_session_data = json.loads(decrypted_session_data_bytes.decode('utf-8'))
        aes_key = base64.b64decode(decrypted_session_data['aes_key'])
        iv = base64.b64decode(decrypted_session_data['iv'])
        logging.info("AES key and IV decrypted successfully.")

        # 2. Giải mã file bằng AES trong chế độ CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

        # Bỏ đệm (unpad) file data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_file_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        logging.info("File decrypted with AES.")

        # Tạo file tạm thời chứa nội dung đã giải mã để gửi về client
        temp_decrypted_filepath = os.path.join(UPLOAD_FOLDER, f"decrypted_file_{secrets.token_hex(8)}")
        with open(temp_decrypted_filepath, 'wb') as f:
            f.write(decrypted_file_data)
        logging.info(f"Decrypted file saved temporarily to: {temp_decrypted_filepath}")

        # Gửi file đã giải mã về client
        # Flask sẽ tự động xóa file tạm thời này sau khi gửi (nếu được cấu hình đúng)
        response = send_file(temp_decrypted_filepath, as_attachment=True, download_name="decrypted_file.bin")
        # Đặt một hàm callback để xóa file sau khi phản hồi được gửi
        @response.call_on_close
        def cleanup_temp_file():
            if os.path.exists(temp_decrypted_filepath):
                os.remove(temp_decrypted_filepath)
                logging.info(f"Temporary decrypted file '{temp_decrypted_filepath}' removed after send.")
        return response

    except ValueError as e:
        logging.error(f"Decryption failed: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.error(f"Unexpected error during decryption: {e}", exc_info=True)
        return jsonify({"error": "Failed to decrypt file due to an unexpected error", "details": str(e)}), 500

@app.route('/')
def index():
    """
    Phục vụ file index.html tĩnh (frontend).
    """
    # Trong môi trường phát triển, bạn có thể phục vụ index.html trực tiếp
    # Trong môi trường production, Nginx/Apache sẽ xử lý static files
    return send_file('index.html')

if __name__ == '__main__':
    # Chạy ứng dụng Flask. Trong môi trường production, sử dụng Gunicorn/Nginx.
    logging.info("Starting Flask application...")
    # debug=True chỉ nên dùng cho phát triển, không dùng cho sản xuất
    app.run(debug=True, host='0.0.0.0', port=5000)
