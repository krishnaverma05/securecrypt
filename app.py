from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.hazmat.primitives import hashes, serialization 
import base64

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:5173/"}}) # Enable cross-origin requests from https://localhost:5173

# Generate RSA key pair
@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode('utf-8')
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')

    return jsonify({"publicKey": public_key, "privateKey": private_key})


# Encrypt message
# @app.route('/encrypt', methods=['POST'])
# def encrypt():
#     data = request.get_json()
#     plaintext = data.get("plaintext")
#     public_key = data.get("publicKey")

#     public_key_obj = crypto.load_publickey(crypto.FILETYPE_PEM, public_key.encode('utf-8'))
#     ciphertext = crypto.public_encrypt(
#         plaintext.encode('utf-8'),
#         public_key_obj,
#         crypto.PKCS1_OAEP_PADDING
#     )

#     encrypted_text = base64.b64encode(ciphertext).decode('utf-8')
#     return jsonify({"encryptedText": encrypted_text})

@app.route('/encrypt', methods=['POST'])
def encrypt(): 
    data = request.get_json() 
    plaintext = data.get("plaintext") 
    public_key = data.get("publicKey") 
        
    try:
        public_key_obj = serialization.load_pem_public_key(public_key.encode('utf-8')) 
        ciphertext = public_key_obj.encrypt( 
                                        plaintext.encode('utf-8'), 
                                        padding.OAEP( 
                                                     mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                                                     algorithm=hashes.SHA256(), 
                                                     label=None 
                                                     ) 
                                        ) 
        encrypted_text = base64.b64encode(ciphertext).decode('utf-8') 
        return jsonify({"encryptedText": encrypted_text})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Decrypt message
# @app.route('/decrypt', methods=['POST'])
# def decrypt():
#     data = request.get_json()
#     encrypted_text = base64.b64decode(data.get("encryptedText"))
#     private_key = data.get("privateKey")

#     private_key_obj = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key.encode('utf-8'))
#     plaintext = crypto.private_decrypt(
#         encrypted_text,
#         private_key_obj,
#         crypto.PKCS1_OAEP_PADDING
#     )

#     return jsonify({"decryptedText": plaintext.decode('utf-8')})


@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    encrypted_text = base64.b64decode(data.get("encryptedText"))
    private_key = data.get("privateKey")

    try:
        # Load the private key from PEM format
        private_key_obj = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=None  # Add a password if the private key is encrypted
        )

        # Decrypt the ciphertext
        plaintext = private_key_obj.decrypt(
            encrypted_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return jsonify({"decryptedText": plaintext.decode('utf-8')})

    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "_main_":
    app.run(debug=True)