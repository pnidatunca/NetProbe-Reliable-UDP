import struct
import hashlib

# Paket formatımızı tanımlıyoruz:
# '!' -> Network byte order (Ağ iletişimi standardı)
# 'B' -> Paket tipi (1 byte: 0=DATA, 1=ACK)
# 'I' -> Sequence Number (4 bytes)
# '32s' -> Checksum (32 bytes - SHA256 hash)[cite: 1]
HEADER_FORMAT = "!BI32s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def calculate_checksum(data):
    """Verinin bozulup bozulmadığını kontrol etmek için SHA256 parmak izini alır[cite: 1]."""
    return hashlib.sha256(data).digest()

def create_packet(pkt_type, seq_num, payload):
    """Veriyi başlık (header) ekleyerek paket haline getirir[cite: 1]."""
    checksum = calculate_checksum(payload)
    header = struct.pack(HEADER_FORMAT, pkt_type, seq_num, checksum)
    return header + payload

def parse_packet(raw_data):
    """Gelen ham veriyi başlık ve veri (payload) olarak parçalarına ayırır[cite: 1]."""
    header = raw_data[:HEADER_SIZE]
    payload = raw_data[HEADER_SIZE:]
    pkt_type, seq_num, checksum = struct.unpack(HEADER_FORMAT, header)
    return pkt_type, seq_num, checksum, payload