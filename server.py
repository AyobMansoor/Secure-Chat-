import socket
import threading
import json
import logging
import sys
from cryptography.hazmat.primitives import serialization

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

HOST = '192.168.1.5'  # Server IP address
PORT = 5000            # Server port
clients_lock = threading.Lock()  # Thread-safe access to clients dictionary
clients = {}  # {client_socket: {username: ..., public_key: ...}}
shutdown_event = threading.Event()  # Event to signal server shutdown

def broadcast(message, exclude_client=None):
    """Sends a message to all connected clients except the sender.
    Args:
        message (bytes): Message to send
        exclude_client (socket): Client to exclude from recipients
    """
    with clients_lock:
        for client in list(clients.keys()):
            if client != exclude_client:
                try:
                    client.sendall(message)
                except Exception as e:
                    logging.error(f"Error sending message: {e}")
                    remove_client(client)

def remove_client(client):
    """Removes a client from the server and broadcasts their departure.
    Args:
        client (socket): Client socket to remove
    """
    with clients_lock:
        if client in clients:
            username = clients[client]["username"]
            del clients[client]
            # Broadcast leave event
            system_msg = {
                "type": "system",
                "action": "leave",
                "username": username
            }
            broadcast(json.dumps(system_msg).encode())

def handle_client(client):
    """Handles client registration and message processing.
    Args:
        client (socket): Client socket connection
    """
    try:
        # Receive registration data (username + public key)
        registration_data = client.recv(4096).decode()
        data = json.loads(registration_data)
        
        if "username" not in data or "public_key" not in data:
            client.close()
            return

        username = data["username"]
        public_key_pem = data["public_key"]

        # Check for duplicate usernames
        with clients_lock:
            for c in list(clients.values()):
                if c["username"] == username:
                    error_msg = json.dumps({"error": "Username already taken"}).encode()
                    client.sendall(error_msg)
                    client.close()
                    return

            clients[client] = {"username": username, "public_key": public_key_pem}

        # Send welcome message with existing users
        existing_users = []
        with clients_lock:
            for c in list(clients.keys()):
                if c != client:
                    existing_users.append({
                        "username": clients[c]["username"],
                        "public_key": clients[c]["public_key"]
                    })
        welcome_msg = json.dumps({"type": "welcome", "users": existing_users}).encode()
        client.sendall(welcome_msg)

        # Broadcast join event to other clients
        join_msg = json.dumps({
            "type": "system",
            "action": "join",
            "username": username,
            "public_key": public_key_pem
        }).encode()
        broadcast(join_msg, exclude_client=client)

        # Process client messages
        while not shutdown_event.is_set():
            msg = client.recv(4096)
            if not msg:
                break
            message = json.loads(msg.decode())
            if "text" in message and message["text"].strip().lower() == "close":
                shutdown_server()
            else:
                broadcast(msg, exclude_client=client)

    except Exception as e:
        logging.error(f"Error handling client: {e}")
    finally:
        remove_client(client)

def shutdown_server():
    """Gracefully shuts down the server and closes all connections."""
    shutdown_event.set()
    with clients_lock:
        for client in list(clients.keys()):
            client.close()
        clients.clear()
    logging.info("Server shutdown complete.")
    sys.exit(0)

def start_server():
    """Starts the chat server and begins accepting connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    logging.info(f"Server started on {HOST}:{PORT}")

    while not shutdown_event.is_set():
        try:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client,), daemon=True).start()
        except Exception as e:
            logging.error(f"Error accepting connection: {e}")

if __name__ == "__main__":
    start_server()