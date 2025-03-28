import socket
import struct
import threading
import time  
from grading import MSS, DEFAULT_TIMEOUT

SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

EXIT_SUCCESS = 0
EXIT_ERROR = 1

class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

class TCPState:
    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RCVD = 3
    ESTABLISHED = 4
    FIN_SENT = 5
    CLOSE_WAIT = 6
    LAST_ACK = 7
    TIME_WAIT = 8

class Packet:
    def __init__(self, seq=0, ack=0, flags=0, payload=b""):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload

    def encode(self):
        header = struct.pack("!IIIH", self.seq, self.ack, self.flags, len(self.payload))
        return header + self.payload

    @staticmethod
    def decode(data):
        header_size = struct.calcsize("!IIIH")
        seq, ack, flags, payload_len = struct.unpack("!IIIH", data[:header_size])
        payload = data[header_size:]
        return Packet(seq, ack, flags, payload)


class TransportSocket:
    def __init__(self):
        self.sock_fd = None

        self.recv_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.wait_cond = threading.Condition(self.recv_lock)

        self.death_lock = threading.Lock()
        self.dying = False
        self.thread = None

        self.window = {
            "last_ack": 0,            # The next seq we expect from peer (used for receiving data)
            "next_seq_expected": 0,   # The highest ack we've received for *our* transmitted data
            "recv_buf": b"",          # Received data buffer
            "recv_len": 0,            # How many bytes are in recv_buf
            "next_seq_to_send": 0,    # The sequence number for the next packet we send
        }
        self.sock_type = None
        self.conn = None
        self.my_port = None
        
        self.state = TCPState.CLOSED
        self.time_wait_start = None
        self.connection_established = threading.Event()
        self.connection_closed = threading.Event()

    def socket(self, sock_type, port, server_ip=None):
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_type = sock_type

        if sock_type == "TCP_INITIATOR":
            self.conn = (server_ip, port)
            self.sock_fd.bind(("", 0))  # Bind to any available local port
            self.state = TCPState.CLOSED
        elif sock_type == "TCP_LISTENER":
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))
            self.state = TCPState.LISTEN
        else:
            print("Unknown socket type")
            return EXIT_ERROR

        self.sock_fd.settimeout(1.0)

        self.my_port = self.sock_fd.getsockname()[1]

        self.thread = threading.Thread(target=self.backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    def connect(self):
        if self.state != TCPState.CLOSED or self.sock_type != "TCP_INITIATOR":
            return EXIT_ERROR
            
        print(f"Sending SYN to initiate connection")
        syn_packet = Packet(seq=self.window["next_seq_to_send"], ack=0, flags=SYN_FLAG)
        self.sock_fd.sendto(syn_packet.encode(), self.conn)
        
        self.window["next_seq_to_send"] += 1
        
        self.state = TCPState.SYN_SENT
        
        if not self.connection_established.wait(timeout=DEFAULT_TIMEOUT):
            print("Connection timeout")
            self.state = TCPState.CLOSED
            return EXIT_ERROR
            
        return EXIT_SUCCESS

    def close(self):
        print(f"Closing socket in state {self.state}")
        if self.state == TCPState.ESTABLISHED or self.state == TCPState.SYN_RCVD:
            print(f"Sending FIN packet")
            fin_packet = Packet(seq=self.window["next_seq_to_send"], ack=self.window["last_ack"], flags=FIN_FLAG)
            self.sock_fd.sendto(fin_packet.encode(), self.conn)
            
            self.window["next_seq_to_send"] += 1
            
            self.state = TCPState.FIN_SENT
            
            self.connection_closed.wait(timeout=DEFAULT_TIMEOUT)
            
        elif self.state == TCPState.CLOSE_WAIT:
            print(f"Sending FIN packet")
            fin_packet = Packet(seq=self.window["next_seq_to_send"], ack=self.window["last_ack"], flags=FIN_FLAG)
            self.sock_fd.sendto(fin_packet.encode(), self.conn)
            
            self.window["next_seq_to_send"] += 1
            
            self.state = TCPState.LAST_ACK
            
            self.connection_closed.wait(timeout=DEFAULT_TIMEOUT)

        self.death_lock.acquire()
        try:
            self.dying = True
        finally:
            self.death_lock.release()

        if self.thread:
            self.thread.join()

        if self.sock_fd:
            self.sock_fd.close()
        else:
            print("Error: Null socket")
            return EXIT_ERROR

        return EXIT_SUCCESS

    def send(self, data):
        if not self.conn and self.sock_type == "TCP_INITIATOR":
            raise ValueError("Connection not established.")
        
        # If we're a client and not connected yet, establish connection
        if self.sock_type == "TCP_INITIATOR" and self.state == TCPState.CLOSED:
            if self.connect() != EXIT_SUCCESS:
                raise ConnectionError("Failed to establish connection")
        
        # For server, wait for the connection to be established
        if self.sock_type == "TCP_LISTENER" and self.state in [TCPState.LISTEN, TCPState.SYN_RCVD]:
            print("Waiting for connection to be established before sending...")
            # Wait for the connection_established event
            if not self.connection_established.wait(timeout=30):  # 30-second timeout
                raise ConnectionError("Timeout waiting for connection")
        
        if self.state != TCPState.ESTABLISHED:
            raise ConnectionError(f"Cannot send data in state {self.state}")
        
        with self.send_lock:
            self.send_segment(data)

    def recv(self, buf, length, flags):
        # If we're a client and not connected yet, establish connection
        if self.sock_type == "TCP_INITIATOR" and self.state == TCPState.CLOSED:
            if self.connect() != EXIT_SUCCESS:
                return EXIT_ERROR
        
        # For server, wait for the connection to be established
        if self.sock_type == "TCP_LISTENER" and self.state == TCPState.LISTEN:
            print("Waiting for connection to be established...")
            if not self.connection_established.wait(timeout=30):  # 30-second timeout
                print("Timeout waiting for connection")
                return EXIT_ERROR
        
        # Make sure we're in a state where we can receive data
        if self.state not in [TCPState.ESTABLISHED, TCPState.CLOSE_WAIT]:
            print(f"Cannot receive data in state {self.state}")
            return EXIT_ERROR
            
        read_len = 0

        if length < 0:
            print("ERROR: Negative length")
            return EXIT_ERROR

        # If blocking read, wait until there's data in buffer
        if flags == ReadMode.NO_FLAG:
            with self.wait_cond:
                while self.window["recv_len"] == 0:
                    self.wait_cond.wait()

        self.recv_lock.acquire()
        try:
            if flags in [ReadMode.NO_WAIT, ReadMode.NO_FLAG]:
                if self.window["recv_len"] > 0:
                    read_len = min(self.window["recv_len"], length)
                    buf[0] = self.window["recv_buf"][:read_len]

                    # Remove data from the buffer
                    if read_len < self.window["recv_len"]:
                        self.window["recv_buf"] = self.window["recv_buf"][read_len:]
                        self.window["recv_len"] -= read_len
                    else:
                        self.window["recv_buf"] = b""
                        self.window["recv_len"] = 0
            else:
                print("ERROR: Unknown or unimplemented flag.")
                read_len = EXIT_ERROR
        finally:
            self.recv_lock.release()

        return read_len

    def send_segment(self, data):
        offset = 0
        total_len = len(data)

        # While there's data left to send
        while offset < total_len:
            payload_len = min(MSS, total_len - offset)

            seq_no = self.window["next_seq_to_send"]
            chunk = data[offset : offset + payload_len]

            segment = Packet(seq=seq_no, ack=self.window["last_ack"], flags=0, payload=chunk)

            ack_goal = seq_no + payload_len

            while True:
                print(f"Sending segment (seq={seq_no}, len={payload_len})")
                self.sock_fd.sendto(segment.encode(), self.conn)

                if self.wait_for_ack(ack_goal):
                    print(f"Segment {seq_no} acknowledged.")
                    self.window["next_seq_to_send"] += payload_len
                    break
                else:
                    print("Timeout: Retransmitting segment.")

            offset += payload_len


    def wait_for_ack(self, ack_goal):
        with self.recv_lock:
            start = time.time()
            while self.window["next_seq_expected"] < ack_goal:
                elapsed = time.time() - start
                remaining = DEFAULT_TIMEOUT - elapsed
                if remaining <= 0:
                    return False

                self.wait_cond.wait(timeout=remaining)

            return True

    def backend(self):
        while not self.dying:
            try:
                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)

                # If no peer is set, establish connection (for listener)
                if self.conn is None:
                    self.conn = addr

                # Handle connection establishment
                if self.state == TCPState.LISTEN and (packet.flags & SYN_FLAG) != 0:
                    print(f"Received SYN, sending SYN+ACK")
                    synack_packet = Packet(seq=self.window["next_seq_to_send"], ack=packet.seq + 1, flags=SYN_FLAG | ACK_FLAG)
                    self.sock_fd.sendto(synack_packet.encode(), addr)
                    
                    self.window["next_seq_to_send"] += 1
                    
                    self.window["last_ack"] = packet.seq + 1
                    
                    self.state = TCPState.SYN_RCVD

                elif self.state == TCPState.SYN_SENT:
                    if (packet.flags & SYN_FLAG) != 0 and (packet.flags & ACK_FLAG) != 0:
                        print(f"Received SYN+ACK, sending ACK")
                        self.window["next_seq_expected"] = packet.ack
                        
                        ack_packet = Packet(seq=self.window["next_seq_to_send"], ack=packet.seq + 1, flags=ACK_FLAG)
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        self.window["last_ack"] = packet.seq + 1
                        
                        self.state = TCPState.ESTABLISHED
                        self.connection_established.set()
                        
                    elif (packet.flags & SYN_FLAG) != 0:
                        print(f"Received SYN (simultaneous open), sending SYN+ACK")
                        synack_packet = Packet(seq=self.window["next_seq_to_send"], ack=packet.seq + 1, flags=SYN_FLAG | ACK_FLAG)
                        self.sock_fd.sendto(synack_packet.encode(), addr)
                        
                        self.window["last_ack"] = packet.seq + 1
                        
                        self.state = TCPState.SYN_RCVD

                elif self.state == TCPState.SYN_RCVD and (packet.flags & ACK_FLAG) != 0:
                    print(f"Received ACK for our SYN+ACK")
                    if packet.ack > self.window["next_seq_expected"]:
                        self.window["next_seq_expected"] = packet.ack
                    
                    self.state = TCPState.ESTABLISHED
                    self.connection_established.set()
                    print("Connection ESTABLISHED! Ready to send/receive data.")

                elif self.state == TCPState.ESTABLISHED and (packet.flags & FIN_FLAG) != 0:
                    print(f"Received FIN in ESTABLISHED, sending ACK and moving to CLOSE_WAIT")
                    ack_packet = Packet(seq=self.window["next_seq_to_send"], ack=packet.seq + 1, flags=ACK_FLAG)
                    self.sock_fd.sendto(ack_packet.encode(), addr)
                    
                    self.window["last_ack"] = packet.seq + 1
                    
                    self.state = TCPState.CLOSE_WAIT

                elif self.state == TCPState.FIN_SENT:
                    if (packet.flags & FIN_FLAG) != 0:
                        print(f"Received FIN in FIN_SENT, sending ACK and moving to TIME_WAIT")
                        ack_packet = Packet(seq=self.window["next_seq_to_send"], ack=packet.seq + 1, flags=ACK_FLAG)
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        self.window["last_ack"] = packet.seq + 1
                        
                        self.state = TCPState.TIME_WAIT
                        self.time_wait_start = time.time()
                        self.connection_closed.set()
                    elif (packet.flags & ACK_FLAG) != 0:
                        print(f"Received ACK for our FIN in FIN_SENT, waiting for peer's FIN")
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack

                elif self.state == TCPState.LAST_ACK and (packet.flags & ACK_FLAG) != 0:
                    print(f"Received ACK for our FIN in LAST_ACK, moving to CLOSED")
                    if packet.ack > self.window["next_seq_expected"]:
                        self.window["next_seq_expected"] = packet.ack
                    
                    self.state = TCPState.CLOSED
                    self.connection_closed.set()

                elif (packet.flags & ACK_FLAG) != 0 and not (packet.flags & SYN_FLAG) and not (packet.flags & FIN_FLAG):
                    with self.recv_lock:
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                            print(f"Updated next_seq_expected to {packet.ack}")
                        self.wait_cond.notify_all()

                if len(packet.payload) > 0 and self.state in [TCPState.ESTABLISHED, TCPState.CLOSE_WAIT]:
                    if packet.seq == self.window["last_ack"]:
                        with self.recv_lock:
                            self.window["recv_buf"] += packet.payload
                            self.window["recv_len"] += len(packet.payload)

                        with self.wait_cond:
                            self.wait_cond.notify_all()

                        print(f"Received segment {packet.seq} with {len(packet.payload)} bytes.")

                        ack_val = packet.seq + len(packet.payload)
                        ack_packet = Packet(seq=self.window["next_seq_to_send"], ack=ack_val, flags=ACK_FLAG)
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        self.window["last_ack"] = ack_val
                    else:
                        print(f"Out-of-order packet: seq={packet.seq}, expected={self.window['last_ack']}")

                if self.state == TCPState.TIME_WAIT:
                    if time.time() - self.time_wait_start >= 2 * DEFAULT_TIMEOUT:  # 2 segment lifetimes
                        print(f"TIME_WAIT timeout, moving to CLOSED")
                        self.state = TCPState.CLOSED
                        self.connection_closed.set()

            except socket.timeout:
                if self.state == TCPState.TIME_WAIT:
                    if time.time() - self.time_wait_start >= 2 * DEFAULT_TIMEOUT:  # 2 segment lifetimes
                        print(f"TIME_WAIT timeout, moving to CLOSED")
                        self.state = TCPState.CLOSED
                        self.connection_closed.set()
                continue
        
            except Exception as e:
                if not self.dying:
                    print(f"Error in backend: {e}")