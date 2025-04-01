import os
import random
import string
from transport import TransportSocket, ReadMode
import time
def generate_random_data(size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def server_main():
    server_socket = TransportSocket()
    server_socket.socket(sock_type="TCP_LISTENER", port=54321)

    print("Server: Waiting to receive data from the client...")
    buf = [b""]
    server_socket.recv(buf, 1024, flags=ReadMode.NO_FLAG)
    print(f"Server: Received data from client:\n{buf[0].decode()}")

    time.sleep(10000)

    server_socket.close()

if __name__ == "__main__":
    server_main()

