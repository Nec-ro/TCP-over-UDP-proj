import threading
from socket_tcp.server import TCPServer

'''
def handle_client(conn):
    print(f"[THREAD] Handling connection from {conn.client_addr}")
    while True:
        try:
            data = conn.recv()
            if not data:
                break
            print(f"[RECV] {data.decode()} from {conn.client_addr}")
            conn.send(b"Echo: " + data)
        except Exception as e:
            print(f"[ERR] {e}")
            break
    conn.close()
    print(f"[CLOSE] Connection with {conn.client_addr} closed")
'''
if __name__ == '__main__':
    server = TCPServer(port=9000)
    while True:
        #conn = server._hand_data()
        conn = server.accept()
        print(f"[NEW CONNECTION] {conn.client_addr}")
        # هندل کردن هر اتصال در یک ترد
        # threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
    '''
    '''
