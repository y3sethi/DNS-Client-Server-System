import socket
import struct

# Predefined DNS table for domain names and IPs
dns_table = {
    "google.com": ["192.165.1.1", "192.165.1.10"],
    "youtube.com": ["192.165.1.2"],
    "uwaterloo.ca": ["192.165.1.3"],
    "wikipedia.org": ["192.165.1.4"],
    "amazon.ca": ["192.165.1.5"]
}

# Server details
HOST = '127.0.0.1'
PORT = 10053  # Choose a port in the recommended range

def parse_request(request):
    # Extracts the domain name from the DNS request
    qname = ""
    idx = 12  # DNS header size
    while request[idx] != 0:
        length = request[idx]
        qname += request[idx + 1: idx + 1 + length].decode() + "."
        idx += length + 1
    return qname.strip(".")

def create_response(request, domain_name):
    transaction_id = request[:2]
    flags = struct.pack("!H", 0x8400)  # Response with QR, AA, RCODE 0
    qdcount = struct.pack("!H", 1)  # One question
    ancount = struct.pack("!H", len(dns_table[domain_name]))  # Number of answers
    nscount = struct.pack("!H", 0)  # No authority records
    arcount = struct.pack("!H", 0)  # No additional records

    # Question section (echoed from request)
    question = request[12:12 + len(domain_name) + 6]

    # Answer section
    answer = b""
    # Set TTL based on domain
    ttl = 260 if domain_name == "google.com" else 160
    for ip in dns_table[domain_name]:
        answer += b'\xc0\x0c'  # Name pointer to domain name in question
        answer += struct.pack("!H", 1)  # TYPE A
        answer += struct.pack("!H", 1)  # CLASS IN
        answer += struct.pack("!I", ttl)  # TTL, dynamically set
        answer += struct.pack("!H", 4)  # RDLENGTH
        answer += socket.inet_aton(ip)  # RDATA (IP address in binary format)

    return transaction_id + flags + qdcount + ancount + nscount + arcount + question + answer

# Start server
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
    server_socket.bind((HOST, PORT))
    print(f"DNS Server running on {HOST}:{PORT}")
    while True:
        request, client_address = server_socket.recvfrom(512)
        print("Request:", ' '.join(f"{b:02x}" for b in request))

        domain_name = parse_request(request)
        if domain_name in dns_table:
            response = create_response(request, domain_name)
            print("Response:", ' '.join(f"{b:02x}" for b in response))
            server_socket.sendto(response, client_address)
        else:
            # Handle domain not found
            flags = struct.pack("!H", 0x8403)  # RCODE 3 (Name Error)
            response = request[:2] + flags + request[4:6] + b'\x00\x00\x00\x00' + request[12:]
            print("Response:", ' '.join(f"{b:02x}" for b in response))
            server_socket.sendto(response, client_address)
