import threading
import time
from collections import deque
from socket_tcp.packet import Packet
from utils.dh import encrypt_message, decrypt_message
import random

class Connection:
    MSS = 500  
    INITIAL_WINDOW_SIZE = 5  
    ACK_TIMEOUT = 2.0 
    MAX_RETRIES = 5 

    def __init__(self, udp_socket, this_addr, target_addr, username=None, 
                 initial_seq=0, initial_ack=0, shared_key=None):
        self.udp_socket = udp_socket
        self.target_addr = target_addr
        self.this_addr = this_addr
        self.enc_key = shared_key
        self.username = username

        self.seq_num = initial_seq  
        self.ack_num = initial_ack 
        self.next_expected_seq = initial_ack  
        
        self.window_size = self.INITIAL_WINDOW_SIZE
        self.unacked_packets = {}
        self.send_buffer = deque() 
        self.send_lock = threading.Lock()
        
        self.recv_buffer = {}  
        self.recv_queue = deque() 
        self.recv_lock = threading.Lock()
        
        self.closed = False
        
        self.resend_thread = threading.Thread(target=self._resend_loop, daemon=True)
        self.resend_thread.start()

    def handle_packet(self, packet: Packet):
        if packet.is_ack():
            self._handle_ack(packet)
        elif packet.payload:
            self._handle_data_packet(packet)

    def _handle_ack(self, ack_packet: Packet):
        with self.send_lock:
            ack_num = ack_packet.ack_num
            if ack_num in self.unacked_packets:
                _, _, retries = self.unacked_packets[ack_num]
                print(f"[ACK] Packet seq={ack_num} acknowledged (after {retries} retries)")
                del self.unacked_packets[ack_num]
            else:
                print(f"[NACK] Couldn't find {ack_num}") 
            if len(self.unacked_packets) < self.window_size // 2:
                self.window_size = min(self.window_size + 1, 20) 
            else:
                self.window_size = max(self.INITIAL_WINDOW_SIZE, self.window_size - 1)

    def _handle_data_packet(self, packet: Packet):
        seq = packet.seq_num
        data = packet.payload
        
        '''
        if self.enc_key:
            try:
                data = decrypt_message(self.enc_key, data)
            except Exception as e:
                print(f"[DECRYPT ERROR] {e}")
                return
        '''
        
        with self.recv_lock:
            if seq in self.recv_buffer or seq < self.next_expected_seq:
                print(f"[DUP] Duplicate or old packet seq={seq}")
                return
                
            self.recv_buffer[seq] = data
            print(f"[RECV] Stored packet seq={seq}, len={len(data)}")

            while self.next_expected_seq in self.recv_buffer:
                payload = self.recv_buffer.pop(self.next_expected_seq)
                self.recv_queue.append(payload)
                self.next_expected_seq += len(payload)
                print(f"[RECV] Delivered data up to seq={self.next_expected_seq}")

        ack_pkt = Packet(
            src_port=self.this_addr[1],
            dst_port=packet.src_port,
            seq_num=self.seq_num, 
            ack_num=self.next_expected_seq, 
            flags=Packet.FLAG_ACK
        )
        self.udp_socket.sendto(ack_pkt.encode(), self.target_addr)
        print(f"[ACK] Sent ACK for next_expected_seq={self.next_expected_seq}")

    def _resend_loop(self):
        while not self.closed:
            time.sleep(0.1) 
            now = time.time()
            
            with self.send_lock:
                for seq, (pkt, send_time, retries) in list(self.unacked_packets.items()):
                    if now - send_time > self.ACK_TIMEOUT:
                        if retries >= self.MAX_RETRIES:
                            print(f"[FAIL] Max retries for seq={seq}, closing connection")
                            self.closed = True
                            del self.unacked_packets[seq]
                            continue
                            
                        print(f"[RETRY] Resending seq={seq} (attempt {retries+1}/{self.MAX_RETRIES})")
                        self.udp_socket.sendto(pkt.encode(), self.target_addr)
                        self.unacked_packets[seq] = (pkt, now, retries + 1)

    def send(self, data: bytes, flag= 0):
        if self.closed:
            raise ConnectionError("Connection closed")
            
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            raise TypeError("Data must be str or bytes")

        '''
        if self.enc_key:
            try:
                data = encrypt_message(self.enc_key, data)
            except Exception as e:
                print(f"[ENCRYPT ERROR] {e}")
                return False
        '''

        chunks = [data[i:i+self.MSS] for i in range(0, len(data), self.MSS)]
        
        with self.send_lock:
            for chunk in chunks:
                while len(self.unacked_packets) >= self.window_size and not self.closed:
                    time.sleep(0.1)
                
                if self.closed:
                    return False
                
                src_port = self.this_addr[1]
                dst_port = self.target_addr[1]
                pkt = Packet(
                    src_port=src_port,
                    dst_port=dst_port,
                    seq_num=self.seq_num,
                    ack_num=self.ack_num,
                    flags=flag,
                    payload=chunk
                )
                
                self.udp_socket.sendto(pkt.encode(), self.target_addr)
                self.unacked_packets[self.seq_num + pkt.payload_length()] = (pkt, time.time(), 0)
                print(f"[SENT] seq={self.seq_num}, len={len(chunk)}")
                
                self.seq_num += len(chunk)
        
        return True

    def recv(self, timeout=None) -> bytes:
        start_time = time.time()
        while not self.closed:
            with self.recv_lock:
                if self.recv_queue:
                    return self.recv_queue.popleft()
            
            if timeout is not None and (time.time() - start_time) > timeout:
                raise TimeoutError("No data received")
            
            time.sleep(0.01)
        
        raise ConnectionError("Connection closed")

    def close(self):
        if self.closed:
            return
            
        self.closed = True
        
        fin_pkt = Packet(
            src_port=self.this_addr[1],
            dst_port=self.target_addr[1],
            seq_num=self.seq_num,
            ack_num=self.ack_num,
            flags=Packet.FLAG_FIN
        )
        self.udp_socket.sendto(fin_pkt.encode(), self.target_addr)
        print(f"[FIN] Sent FIN to {self.target_addr}")
        
        if self.resend_thread.is_alive():
            self.resend_thread.join(timeout=1.0)
        
        print(f"[CLOSED] Connection with {self.target_addr}")