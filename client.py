import socket
import threading
import json
import base64
import hashlib
import rsa
from Crypto.Cipher import AES, ChaCha20  # AES and ChaCha20 encryption modules
from Crypto.Random import get_random_bytes  # Generate random bytes for keys
from kivy.app import App  # Kivy core class for the app
from kivy.uix.boxlayout import BoxLayout  # Layout container for UI
from kivy.uix.label import Label  # Display text
from kivy.uix.spinner import Spinner  # Dropdown for encryption selection
from kivy.uix.textinput import TextInput  # User input field
from kivy.uix.button import Button  # Buttons for actions
from kivy.uix.scrollview import ScrollView  # Scrollable area for chat history
from Crypto.Util.Padding import pad, unpad  # For AES padding/unpadding
from kivy.clock import Clock  # Schedule UI updates
from kivy.properties import StringProperty  # Dynamic UI text properties
import time  # For timestamp formatting

# Server configuration
SERVER_HOST = "192.168.1.5"  # IP address of the chat server
SERVER_PORT = 5000            # Port the server is listening on

# Contact management (username -> public key)
contacts = {}  
contact_lock = threading.Lock()  # Thread-safe access to contacts dictionary

# Generate RSA keys for the client

(my_public_key, my_private_key) = rsa.newkeys(2048)  # 2048-bit RSA keys
my_public_pem = base64.b64encode(my_public_key.save_pkcs1()).decode()  # Encode public key for transmission
username = None  # User's chosen username
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket for communication



def encrypt_text(message, key, algorithm):
    """Encrypts a message using AES or ChaCha20 with a given symmetric key.
    Args:
        message (str): Plaintext message
        key (bytes): Symmetric encryption key
        algorithm (str): 'AES' or 'ChaCha20'
    Returns:
        str: Base64 encoded ciphertext with IV/nonce
    """
    if algorithm == "AES":
        cipher = AES.new(key, AES.MODE_CBC)  # AES in CBC mode
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))  # Pad message to block size
        return base64.b64encode(cipher.iv + ct_bytes).decode()  # Return IV + ciphertext (Base64)
    
    elif algorithm == "ChaCha20":
        cipher = ChaCha20.new(key=key)  # ChaCha20 stream cipher
        ct = cipher.encrypt(message.encode())
        return base64.b64encode(cipher.nonce + ct).decode()  # Return nonce + ciphertext (Base64)

def decrypt_text(enc_message, key, algorithm):
    """Decrypts a message using the symmetric key and algorithm.
    Args:
        enc_message (str): Base64 encoded ciphertext
        key (bytes): Symmetric decryption key
        algorithm (str): 'AES' or 'ChaCha20'
    Returns:
        str: Decrypted plaintext message
    """
    data = base64.b64decode(enc_message)
    if algorithm == "AES":
        iv = data[:16]  # Extract IV (AES block size is 16 bytes)
        ct = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode()  # Unpad and decode
    elif algorithm == "ChaCha20":
        nonce = data[:8]  # Extract nonce (ChaCha20 uses 8-byte nonce)
        ct = data[8:]
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.decrypt(ct).decode()

def encrypt_symmetric_key_for_recipient(sym_key, recipient_public_key):
    """Encrypts the symmetric key with the recipient's RSA public key.
    Args:
        sym_key (bytes): Symmetric encryption key (AES/ChaCha20)
        recipient_public_key (rsa.PublicKey): Recipient's RSA public key
    Returns:
        bytes: Encrypted symmetric key
    """
    return rsa.encrypt(sym_key, recipient_public_key)

def sign_message(plaintext):
    """Signs a message using the client's private RSA key for integrity.
    Args:
        plaintext (bytes): Plaintext message to sign
    Returns:
        bytes: RSA signature of the SHA-256 hash of the message
    """
    hash_val = hashlib.sha256(plaintext).digest()  # SHA-256 hash of plaintext
    return rsa.sign(hash_val, my_private_key, 'SHA-256')  # Sign the hash
    

class ChatLayout(BoxLayout):
    """Main chat UI layout containing chat history, user list, and message input."""
    chat_text = StringProperty("")  # Dynamic chat history text
    online_users = StringProperty("")  # List of online users

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'

        # Chat history display
        self.chat_scroll = ScrollView(size_hint=(1, 0.7))
        self.chat_label = Label(text="", markup=True, size_hint_y=None)
        self.chat_label.bind(texture_size=self.update_chat_height)
        self.chat_scroll.add_widget(self.chat_label)
        self.add_widget(self.chat_scroll)

        # Middle layout (users list + message input)
        mid_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.15))
        self.users_label = Label(text="Online Users:\n", size_hint=(0.3, 1))
        mid_layout.add_widget(self.users_label)

        right_layout = BoxLayout(orientation='vertical', size_hint=(0.7, 1))
        self.message_input = TextInput(hint_text="Type your message here...", multiline=False)
        right_layout.add_widget(self.message_input)

        # Lower layout (encryption method + send button)
        lower_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.4))
        self.spinner = Spinner(text="AES", values=["AES", "ChaCha20"], size_hint=(0.4, 1))
        lower_layout.add_widget(self.spinner)
        send_button = Button(text="Send", size_hint=(0.6, 1))
        send_button.bind(on_press=self.send_message)
        lower_layout.add_widget(send_button)
        right_layout.add_widget(lower_layout)
        mid_layout.add_widget(right_layout)
        self.add_widget(mid_layout)

    def update_chat_height(self, instance, size):
        """Updates the chat label height dynamically based on content size."""
        self.chat_label.height = size[1]

    def update_online_users(self):
        """Updates the online users list in the UI."""
        with contact_lock:
            users = sorted(contacts.keys())
        self.users_label.text = "Online Users:\n" + "\n".join(users)

    def append_chat(self, text):
        """Appends a message to the chat history with timestamp formatting."""
        self.chat_text += f"[{time.strftime('%H:%M')}] {text}\n"
        Clock.schedule_once(lambda dt: setattr(self.chat_label, 'text', self.chat_text))

    def send_message(self, instance):
        """Handles sending messages via the UI button."""
        text = self.message_input.text.strip()
        if not text:
            return
        self.append_chat(f"[You]: {text}")
        self.message_input.text = ""
        # Delay to ensure UI updates before processing
        Clock.schedule_once(lambda dt: self.process_send_message(text), 0.5)

    def process_send_message(self, text):
        """Processes message encryption and transmission."""
        encryption_method = self.spinner.text
        # AES/ChaCha20 require 32-byte keys (256-bit)
        sym_key = get_random_bytes(32) if encryption_method in ["AES", "ChaCha20"] else get_random_bytes(24)
        encrypted_message = encrypt_text(text, sym_key, encryption_method)



        # Encrypt symmetric key for each recipient
        recipients = {}
        with contact_lock:
            for user, pub in contacts.items():
                if user == username:
                    continue  # Skip self
                try:
                    enc_key = encrypt_symmetric_key_for_recipient(sym_key, pub)
                    recipients[user] = base64.b64encode(enc_key).decode()
                except Exception as e:
                    print(f"Error encrypting key for {user}: {e}")

                    

        # Sign the plaintext message
        signature = sign_message(text.encode())
        signature_b64 = base64.b64encode(signature).decode()

        # Build the message JSON
        full_message = {
            "type": "MESSAGE",
            "sender": username,
            "encryption_method": encryption_method,
            "recipients": recipients,
            "encrypted_message": encrypted_message,
            "signature": signature_b64
        }
        try:
            client_socket.sendall(json.dumps(full_message).encode())
        except Exception as e:
            self.append_chat("[System] Error sending message.")
            print("Send error:", e)

class ChatClientApp(App):
    """Main application class for the secure chat client."""

    def build(self):
        """Initialize the app UI."""
        self.title = "Secure Chat Client"
        self.layout = ChatLayout()
        return self.layout

    def on_start(self):
        """Show username prompt when the app starts."""
        self.show_username_prompt()

    def show_username_prompt(self, error=None):
        """Displays a username prompt dialog with optional error message."""
        from kivy.uix.popup import Popup
        from kivy.uix.textinput import TextInput
        from kivy.uix.button import Button
        from kivy.uix.boxlayout import BoxLayout

        content = BoxLayout(orientation='vertical')
        if error:
            content.add_widget(Label(text=f"Error: {error}"))

        username_input = TextInput(hint_text="Enter your username", multiline=False)
        content.add_widget(username_input)
        btn = Button(text="OK", size_hint=(1, 0.3))
        content.add_widget(btn)

        popup = Popup(title="Username", content=content, size_hint=(0.6, 0.4), auto_dismiss=False)
        btn.bind(on_press=lambda instance: self.set_username(username_input.text, popup))
        popup.open()

    def set_username(self, name, popup):
        """Sets the username and connects to the server."""
        global username
        if not name.strip():
            return
        username = name.strip()
        popup.dismiss()
        threading.Thread(target=self.connect_to_server, daemon=True).start()





    def connect_to_server(self):
        """Connects to the server and sends registration data."""
        try:
            client_socket.connect((SERVER_HOST, SERVER_PORT))
        except Exception as e:
            print("Connection error:", e)
            return

        # Send registration data (username + public key)
        reg = {"username": username, "public_key": my_public_pem}
        try:
            client_socket.sendall(json.dumps(reg).encode())
        except Exception as e:
            print("Registration send error:", e)
            return

        # Start listening for incoming messages
        threading.Thread(target=self.receive_messages, daemon=True).start()




    def receive_messages(self):
        """Handles incoming messages from the server."""
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                msg = json.loads(data.decode())

                if msg.get("type") == "welcome":
                    # Update contacts with existing users
                    with contact_lock:
                        for user in msg["users"]:
                            username_user = user["username"]
                            public_key_pem = user["public_key"]
                            public_key = rsa.PublicKey.load_pkcs1(base64.b64decode(public_key_pem))
                            contacts[username_user] = public_key
                    # Update UI
                    Clock.schedule_once(lambda dt: self.layout.update_online_users())
                    Clock.schedule_once(lambda dt: self.layout.append_chat("[System]: Connected successfully!"))

                elif msg.get("type") == "system":
                    action = msg.get("action")
                    if action == "join":
                        # New user joined
                        username_join = msg["username"]
                        public_key_pem = msg["public_key"]
                        public_key = rsa.PublicKey.load_pkcs1(base64.b64decode(public_key_pem))
                        with contact_lock:
                            contacts[username_join] = public_key
                        self.layout.append_chat(f"[System]: {username_join} has joined the chat.")
                    elif action == "leave":
                        # User left
                        username_leave = msg["username"]
                        with contact_lock:
                            if username_leave in contacts:
                                del contacts[username_leave]
                        self.layout.append_chat(f"[System]: {username_leave} has left the chat.")
                    # Update online users list
                    Clock.schedule_once(lambda dt: self.layout.update_online_users())

                elif msg.get("type") == "MESSAGE":
                    sender = msg.get("sender", "Unknown")
                    encryption_method = msg.get("encryption_method")
                    recipients = msg.get("recipients", {})
                    encrypted_message = msg.get("encrypted_message")
                    signature_b64 = msg.get("signature")

                    # Check if the message is addressed to us
                    if username not in recipients:
                        self.layout.append_chat(f"[System]: No symmetric key for you in message from {sender}")
                        continue

                    # Decrypt the symmetric key
                    try:
                        enc_sym_key = base64.b64decode(recipients[username])
                        sym_key = rsa.decrypt(enc_sym_key, my_private_key)
                    except Exception as e:
                        self.layout.append_chat(f"[System]: Error decrypting symmetric key from {sender}")
                        continue

                    # Decrypt the message
                    try:
                        decrypted_text = decrypt_text(encrypted_message, sym_key, encryption_method)
                    except Exception as e:
                        decrypted_text = "[Decryption Error]"

                    # Verify the signature
                    try:
                        signature = base64.b64decode(signature_b64)
                        hash_val = hashlib.sha256(decrypted_text.encode()).digest()
                        with contact_lock:
                            rsa.verify(hash_val, signature, contacts[sender])
                        sig_status = "✔️"
                    except Exception as e:
                        sig_status = "❌"

                    # Update chat display
                    self.layout.append_chat(f"{sender}: {decrypted_text} {sig_status}")

            except Exception as e:
                print("Receive error:", e)
                break

if __name__ == "__main__":
    app = ChatClientApp()
    app.run()