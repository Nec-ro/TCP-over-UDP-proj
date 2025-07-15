from socket_tcp.client import TCPClient

def run():
    username = input("Choose your username: ").strip()
    client = TCPClient()
    conn = None
    if username:
        conn = client.connectNlog("127.0.0.1", 9000, username)
    else: 
        conn = client.connect("127.0.0.1", 9000)

    if not conn:
        print("[X] Connection failed")
        return

    print("[✓] Connected. You can now send messages.")
    while True:
        msg = input("> ").strip()
        if msg.lower() in {"exit", "quit"}:
            break
        if msg:
            conn.send(msg.encode())

if __name__ == "__main__":
    run()
