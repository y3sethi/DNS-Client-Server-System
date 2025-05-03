import socket
import struct
import random

# Server details
HOST = '127.0.0.1'  # Localhost for same-machine testing
PORT = 10053        # Port used by the server

def create_query(domain_name):
    # Create a DNS query for a given domain name
    transaction_id = struct.pack("!H", random.randint(0, 65535))  # Random ID
    flags = struct.pack("!H", 0x0400)  # Standard query
    qdcount = struct.pack("!H", 1)  # One question
    ancount = struct.pack("!H", 0)
    nscount = struct.pack("!H", 0)
    arcount = struct.pack("!H", 0)

    # Encode domain name (e.g., "google.com" -> "\x06google\x03com\x00")
    query = b""
    for part in domain_name.split("."):
        query += struct.pack("B", len(part)) + part.encode()
    query += b"\x00"  # End of QNAME

    qtype = struct.pack("!H", 1)  # Type A record
    qclass = struct.pack("!H", 1)  # Class IN (Internet)

    return transaction_id + flags + qdcount + ancount + nscount + arcount + query + qtype + qclass

def parse_response(response, domain_name):
    # Parse the DNS response from the server and print it in the required format
    ancount = struct.unpack("!H", response[6:8])[0]  # Answer count
    if ancount == 0:
        print("No address found for this domain.")
        return

    # Move to the answer section
    offset = 12 + len(response[12:].split(b'\x00')[0]) + 5
    for _ in range(ancount):
        # Extract type and class
        rtype = struct.unpack("!H", response[offset + 2: offset + 4])[0]
        rclass = struct.unpack("!H", response[offset + 4: offset + 6])[0]
        ttl = struct.unpack("!I", response[offset + 6: offset + 10])[0]
        addr_len = struct.unpack("!H", response[offset + 10: offset + 12])[0]
        ip = socket.inet_ntoa(response[offset + 12: offset + 12 + addr_len])
        
        # Map type and class for readability
        type_str = "A" if rtype == 1 else "Unknown"
        class_str = "IN" if rclass == 1 else "Unknown"

        # Print in the specified format
        print(f"> {domain_name}: type {type_str}, class {class_str}, TTL {ttl}, addr ({addr_len}) {ip}")
        offset += 16

# Main client loop
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
    print("DNS Client started. Type 'end' to exit.")
    while True:
        domain_name = input("Enter Domain Name: ").strip()
        if domain_name.lower() == "end":
            print("Session ended")
            break

        # Send DNS query
        query = create_query(domain_name)
        client_socket.sendto(query, (HOST, PORT))

        # Receive and parse the response
        response, _ = client_socket.recvfrom(512)
        parse_response(response, domain_name)
