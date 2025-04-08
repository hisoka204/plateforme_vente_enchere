import socket
import pickle
from Crypto.Cipher import AES
import threading

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 6589

PROXY_HOST = '127.0.0.1'
PROXY_PORT = 6588

def handle_client(client_socket):
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
      server_socket.connect((SERVER_HOST, SERVER_PORT))
      while True:
        request = client_socket.recv(4096)
        if len(request) == 0:
          break
        req = pickle.loads(request)
        print(f"Client -> Proxy:\n{req}")
        server_socket.sendall(request)
        response = server_socket.recv(4096)
        res = pickle.loads(response)
        print(f"Server -> Proxy:\n{res}")
        client_socket.sendall(response)
  except Exception as e:
    print(f"Error: {e}")
  finally:
    client_socket.close()

def start_proxy():
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
    proxy_socket.bind((PROXY_HOST, PROXY_PORT))
    proxy_socket.listen(5)
    print(f"Proxy server running on {PROXY_HOST}:{PROXY_PORT}")
    while True:
      client_socket, client_address = proxy_socket.accept()
      print(f"Accepted connection from {client_address}")
      client_thread = threading.Thread(target=handle_client, args=(client_socket,))
      client_thread.start()

if __name__ == '__main__':
  start_proxy()
