from utils.dh import generate_dh_keypair, compute_shared_key
from socket_tcp.connection import Connection
from socket_tcp.packet import Packet
from datetime import datetime
import threading
import socket
import random
import time

MAX_RETRIES = 5
RETRY_TIMEOUT = 2.0

class TCPClient:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_addr = None
        self.connection = None
        self.username = None

    def _log(self, message):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        print(f"{timestamp} {message}")

    def connect(self, host: str, port: int, username: str) -> Connection | None:
        self.server_addr = (host, port)
        self.username = username
        
        client_port = random.randint(20000, 60000)
        self.socket.bind(('0.0.0.0', client_port))
        
        a, A = generate_dh_keypair()
        client_seq = random.getrandbits(32)
        
        payload = f"#USERNAME:{username}|DHKEY:{hex(A)}".encode('utf-8')
        
        syn_packet = Packet(
            src_port=client_port,
            dst_port=port,
            seq_num=client_seq,
            ack_num=0,
            flags=Packet.FLAG_SYN,
            payload=payload
        )

        for attempt in range(MAX_RETRIES):
            self._log(f"Attempt {attempt+1}: Connecting to {host}:{port} as '{username}'")
            self.socket.sendto(syn_packet.encode(), self.server_addr)
            self._log(f"Syn packet sent to {self.server_addr}: {syn_packet.__repr__()}")
            
            try:
                self.socket.settimeout(RETRY_TIMEOUT)
                data, addr = self.socket.recvfrom(4096)
                packet = Packet.decode(data)
                
                if (packet.is_syn() and packet.is_ack() and 
                    packet.ack_num == client_seq + 1 and 
                    addr == self.server_addr):
                    self._log(f"Packet recieved from {addr}: {packet.__repr__()}")

                    if not packet.payload:
                        self._log("No DH reply in SYN-ACK")
                        continue
                        
                    try:
                        dh_reply = packet.payload.decode()
                        B = int(dh_reply.split(":")[1], 16)
                        shared_key = compute_shared_key(B, a)
                    except (ValueError, IndexError) as e:
                        self._log(f"Invalid DH reply format: {e}")
                        continue
                    
                    client_seq += 1
                    ack_packet = Packet(
                        src_port=client_port,
                        dst_port=port,
                        seq_num=client_seq,
                        ack_num=packet.seq_num + 1,
                        flags=Packet.FLAG_SYN|Packet.FLAG_ACK
                    )
                    self.socket.sendto(ack_packet.encode(), self.server_addr)
                    self._log(f"Last handshake ack packet sent to {addr}: {ack_packet.__repr__()}")

                    client_seq += 1
                    self.connection = Connection(
                        udp_socket=self.socket,
                        target_addr=self.server_addr,
                        this_addr= ('0.0.0.0', client_port),
                        initial_seq=client_seq,
                        initial_ack=packet.seq_num + 1,
                        username= username,
                        shared_key=shared_key
                    )
                    
                    self._log(f"Connected successfully! Shared key established.")
                    return self.connection
                
            except socket.timeout:
                self._log("Timeout waiting for server response")
                continue
            except Exception as e:
                self._log(f"Connection error: {e}")
                break
                
        self._log("Failed to connect after maximum retries")
        return None

    def send_message(self, message: str) -> bool:
        if not self.connection:
            self._log("Not connected to server")
            return False
            
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
                
            self.connection.send(data= message, flag= Packet.FLAG_MSG)
            self._log(f"Message sent to server")
            return True
        except Exception as e:
            self._log(f"Failed to send message: {e}")
            return False

    def receive_packet(self, timeout: float = 5.0) -> str | None:
        if not self.connection:
            self._log("Not connected to server")
            return None
            
        try:
            data, addr = self.socket.recvfrom(4096)
            packet = Packet.decode(data)
            self._log(f"Packet recieved from {addr}: {packet.__repr__()}")

            conn.handle_packet(packet)
        except Exception as e:
            self._log(f"Failed to receive message: {e}")
            return None

    def _parse_recv_message(self, payload):
        try:
            username_part, message_part = payload.split("|", 1)
            username = username_part.split(":", 1)[1]
            message = message_part.split(":", 1)[1]
            return username, message
        except Exception as e:
            self._log(f"RCV message parsing error: {str(e)}")
            return None, None

    def _handle_new_connection(self, conn: Connection):
        server_thread = threading.Thread(
            target=self._handle_server,
            args=(conn,),
            daemon=True
        )
        server_thread.start()
        loop_thread = threading.Thread(
            target=self._listen_loop,
            args=(conn,),
            daemon=True
        )
        loop_thread.start()

    def _handle_server(self, conn: Connection):
        try:
            while not conn.closed:
                try:
                    payload = conn.recv(timeout=1.0)
                    decoded_payload = payload.decode()
                    if not all(x in decoded_payload for x in ["#USERNAME:", "|Message:"]):
                        self._log(f"Invalid message payload")
                        break
                    
                    username, message = self._parse_recv_message(decoded_payload)                        
                    self._log(f"Received message from {username}: {message}")
                except TimeoutError:
                    continue
                except Exception as e:
                    self._log(f"Error receiving message: {str(e)}")
                    break
        except Exception as e:
            self._log(f"Client handler error: {str(e)}")
        finally:
            conn.close()

    def close(self):
        if self.connection:
            self.connection.close()
            self._log("Connection closed")
        self.socket.close()

    def _listen_loop(self, conn: Connection):
        while True:
            try:
                data, _ = client.socket.recvfrom(4096)
                packet = Packet.decode(data)
                conn.handle_packet(packet)
            except Exception as e:
                pass            

if __name__ == '__main__':
    client = TCPClient()
    
    username = input("Please enter your username: ")
    conn = client.connect("127.0.0.1", 9000, username)
    if not conn:
        exit(1)
    client._handle_new_connection(conn)

    try:
        while True:
            client.send_message(input())
            #client.receive_packet()
        
    except KeyboardInterrupt:
        print("\nServer shutting down...")

    '''
    try:
        client.send_message("Hello Server!")
        
        response = client.receive_message()
        print(f"Server response: {response}")
        
    finally:
        client.close()
    '''