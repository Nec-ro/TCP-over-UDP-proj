import struct

class Packet:
    HEADER_FORMAT = '!HHIIHH'  # src_port, dst_port, seq, ack, flags, length
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    FLAG_SYN = 0x01
    FLAG_ACK = 0x02
    FLAG_FIN = 0x04
    FLAG_RST = 0x08
    FLAG_MSG = 0x10

    def __init__(self, src_port, dst_port, seq_num, ack_num, flags=0, payload=b''):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.payload = payload or b''

    def encode(self):
        header = struct.pack(
            self.HEADER_FORMAT,
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            self.flags,
            len(self.payload)
        )
        return header + self.payload

    @classmethod
    def decode(cls, data):
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Incomplete packet received.")

        header = data[:cls.HEADER_SIZE]
        payload = data[cls.HEADER_SIZE:]
        src_port, dst_port, seq, ack, flags, length = struct.unpack(cls.HEADER_FORMAT, header)

        if len(payload) != length:
            raise ValueError("Payload length mismatch.")

        return cls(src_port, dst_port, seq, ack, flags, payload)

    def is_syn(self):
        return self.flags & self.FLAG_SYN

    def is_ack(self):
        return self.flags & self.FLAG_ACK

    def is_fin(self):
        return self.flags & self.FLAG_FIN

    def is_rst(self):
        return self.flags & self.FLAG_RST

    def is_msg(self):
        return self.flags & self.MSG

    def payload_length(self):
        return len(self.payload)

    def __repr__(self):
        return f"<Packet seq={self.seq_num} ack={self.ack_num} flags={self.flags} len={len(self.payload)}>"
