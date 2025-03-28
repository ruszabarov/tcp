import os
import random
import string
from transport import TransportSocket, ReadMode

def generate_random_data(size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def client_main():
    client_socket = TransportSocket()
    client_socket.socket(sock_type="TCP_INITIATOR", port=54321, server_ip="127.0.0.1")

    file_name = "alice.txt"
    with open(file_name, "rb") as f:
        file_data = f.read()
        print(f"Client: Sending file '{file_name}' to the server...")
        client_socket.send(file_data)

    random_data = generate_random_data(128)
    print(f"Client: Sending randomly generated data to the server...")
    client_socket.send(random_data)

    print("Client: Waiting to receive data from the server...")
    buf = [b""]
    client_socket.recv(buf, 1024, flags=ReadMode.NO_FLAG)
    print(f"Client: Received data from server:\n{buf[0].decode()}")

    client_socket.close()

if __name__ == "__main__":
    client_main()

