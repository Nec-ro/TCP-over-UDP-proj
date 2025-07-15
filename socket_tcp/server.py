from datetime import datetime
from utils.dh import generate_dh_keypair, compute_shared_key
from socket_tcp.packet import Packet
from socket_tcp.connection import Connection
import threading
import random
import socket
import time

class TCPServer:
    def __init__(self, host='0.0.0.0', port=9000):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.socket.settimeout(1.0)

        self.connections = {}  # {addr: (conn, last_active)}
        self.pending_handshakes = {}  # {addr: handshake_data}
        self.usernames = {}  # {username: addr}
        self.lock = threading.Lock()
        
        self._log(f"Server bound on {host}:{port}")

    def _log(self, message):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        print(f"{timestamp} {message}")

    def start(self):
        server_thread = threading.Thread(
            target=self._listen_loop,
            daemon=True
        )
        server_thread.start()
        self._log("Server listening thread started")

    def _listen_loop(self):
        last_cleanup = time.time()
        while True:
            try:
                data, addr = self.socket.recvfrom(4096)
                packet = Packet.decode(data)
                self._log(f"Packet recieved from {addr}: {packet.__repr__()}")

                if packet.is_syn() and addr not in self.connections:
                    conn = self.accept(addr, packet)
                    if conn:
                        self._handle_new_connection(conn)
                elif addr in self.connections:
                    conn, _ = self.connections[addr]
                    conn.handle_packet(packet)

            except socket.timeout:
                now = time.time()
                if now - last_cleanup > 5:
                    self._cleanup_expired_handshakes()
                    self._cleanup_inactive_connections()
                    last_cleanup = now

            except Exception as e:
                self._log(f"SERVER ERROR: {str(e)}")
                time.sleep(1)

    def _handle_new_connection(self, conn: Connection):
        self._log(f"New connection from {conn.target_addr} - Username: {conn.username}")
        client_thread = threading.Thread(
            target=self._handle_client,
            args=(conn,),
            daemon=True
        )
        client_thread.start()

    #def accept(self) -> Connection | None:
    def accept(self, addr, packet: Packet) -> Connection | None:
        try:
            #data, addr = self.socket.recvfrom(4096)
            #packet = Packet.decode(data)
            #self._log(f"Packet recieved from {addr}: {packet.__repr__()}")
            
            if addr in self.connections or not packet.is_syn():
                return None
                
            if not packet.is_ack():
                return self._handle_syn(packet, addr)
            else:
                return self._handle_ack(packet, addr)

        except Exception as e:
            self._log(f"HANDSHAKE ERROR: {str(e)}")
            return None

    def _handle_syn(self, packet: Packet, addr):
        try:
            payload = packet.payload.decode()
            if not all(x in payload for x in ["#USERNAME:", "|DHKEY:"]):
                self._log(f"Invalid SYN payload from {addr}")
                return None
                
            username, A = self._parse_syn_payload(payload)
            if not username or not A:
                return None
                
            with self.lock:
                if username in self.usernames:
                    self._log(f"Username already taken: {username}")
                    return None
                    
            b, B = generate_dh_keypair()
            shared_key = compute_shared_key(A, b)
            server_seq = random.getrandbits(32)
            syn_ack = Packet(
                src_port=self.port,
                dst_port=packet.src_port,
                seq_num=server_seq,
                ack_num=packet.seq_num + 1,
                flags=Packet.FLAG_SYN | Packet.FLAG_ACK,
                payload=f"DHREPLY:{hex(B)}".encode()
            )
            self.socket.sendto(syn_ack.encode(), addr)
            self._log(f"Syn-ack packet sent to {addr}: {syn_ack.__repr__()}")

            #server_seq += 1
            self.pending_handshakes[addr] = {
                'syn_packet': packet,
                'timestamp': time.time(),
                'seq_num': server_seq,
                'ack_num': packet.seq_num + 1,
                'username': username,
                'shared_key': shared_key
            }
            
            self._cleanup_expired_handshakes()
        except Exception as e:
            self._log(f"SYN HANDLER ERROR: {str(e)}")
            return None

    def _parse_syn_payload(self, payload):
        try:
            username_part, dh_part = payload.split("|", 1)
            username = username_part.split(":", 1)[1]
            A = int(dh_part.split(":", 1)[1], 16)
            return username, A
        except Exception as e:
            self._log(f"SYN payload parsing error: {str(e)}")
            return None, None

    def _handle_ack(self, packet: Packet, addr):
        pending = self.pending_handshakes.get(addr)
        if not pending:
            self._log(f"Orphan ACK from {addr}")
            return None
            
        if packet.ack_num != pending['seq_num'] + 1:
            self._log(f"Invalid ACK num from {addr}")
            return None
        
        conn = Connection(
            udp_socket=self.socket,
            target_addr=addr,
            this_addr= (self.host, self.port),
            initial_seq=pending['seq_num'] + 1,
            initial_ack=pending['ack_num'] + 1,
            username= pending['username'],
            shared_key=pending['shared_key']
        )
        print(f"Connection created for {addr} with initial_recv_seq={pending['syn_packet'].seq_num + 1}")
        
        with self.lock:
            self.connections[addr] = (conn, time.time())
            if conn.username:
                self.usernames[conn.username] = addr
                
        del self.pending_handshakes[addr]
        return conn

    def _cleanup_expired_handshakes(self, timeout=5):
        """پاک‌سازی handshakeهای منقضی شده"""
        now = time.time()
        expired = [
            addr for addr, hs in self.pending_handshakes.items()
            if now - hs['timestamp'] > timeout
        ]
        
        for addr in expired:
            self._log(f"Handshake timeout for {addr}")
            del self.pending_handshakes[addr]

    def _cleanup_inactive_connections(self, timeout=300):
        """پاک‌سازی اتصالات غیرفعال"""
        now = time.time()
        with self.lock:
            inactive = [
                addr for addr, (conn, last_active) in self.connections.items()
                if now - last_active > timeout
            ]
            
            for addr in inactive:
                conn = self.connections[addr][0]
                self._log(f"Connection timeout for {addr} - User: {conn.username}")
                if conn.username in self.usernames:
                    del self.usernames[conn.username]
                del self.connections[addr]

    def _handle_client(self, conn: Connection):
        #print("the loop is looping :D") # this doesn't work
        try:
            while not conn.closed:
                try:
                    message = conn.recv(timeout=1.0)
                    if message:
                        self._log(f"Received message from {conn.username}: {message.decode()}")
                        payload = f"#USERNAME:{conn.username}|Message:{message.decode()}".encode('utf-8')                        
                        self._broadcast_message(conn, payload)
                except TimeoutError:
                    continue
                except Exception as e:
                    self._log(f"Error receiving message: {str(e)}")
                    break
        except Exception as e:
            self._log(f"Client handler error: {str(e)}")
        finally:
            conn.close()
            self._remove_connection(conn)

    def _broadcast_message(self, sender_conn: Connection, message: bytes):
        with self.lock:
            for addr, (conn, _) in self.connections.items():
                if conn != sender_conn and not conn.closed:
                    try:
                        conn.send(message)
                        self._log(f"Sent message to {conn.username}")
                    except Exception as e:
                        self._log(f"Error sending to {conn.username}: {str(e)}")

    def _remove_connection(self, conn: Connection):
        with self.lock:
            if conn.target_addr in self.connections:
                del self.connections[conn.target_addr]
            if conn.username in self.usernames:
                del self.usernames[conn.username]
        self._log(f"Removed connection: {conn.username}")

if __name__ == '__main__':
    server = TCPServer(port=9000)
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nServer shutting down...")
