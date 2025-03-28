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

def state_to_string(state):
    """Convert TCPState enum value to readable string"""
    states = {
        TCPState.CLOSED: "CLOSED",
        TCPState.LISTEN: "LISTEN",
        TCPState.SYN_SENT: "SYN_SENT",
        TCPState.SYN_RCVD: "SYN_RCVD",
        TCPState.ESTABLISHED: "ESTABLISHED",
        TCPState.FIN_SENT: "FIN_SENT",
        TCPState.CLOSE_WAIT: "CLOSE_WAIT", 
        TCPState.LAST_ACK: "LAST_ACK",
        TCPState.TIME_WAIT: "TIME_WAIT"
    }
    return states.get(state, f"UNKNOWN({state})")

def format_flags(flags):
    """Convert flags value to readable string"""
    flag_names = []
    if flags & SYN_FLAG:
        flag_names.append("SYN")
    if flags & ACK_FLAG:
        flag_names.append("ACK")
    if flags & FIN_FLAG:
        flag_names.append("FIN")
    if flags & SACK_FLAG:
        flag_names.append("SACK")
    if not flag_names:
        return "NONE"
    return "+".join(flag_names)

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
            print(f"[{state_to_string(self.state)}] Socket created as TCP_INITIATOR, connecting to {server_ip}:{port}")
        elif sock_type == "TCP_LISTENER":
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))
            self.state = TCPState.LISTEN
            print(f"[{state_to_string(self.state)}] Socket created as TCP_LISTENER, listening on port {port}")
        else:
            print(f"[ERROR] Unknown socket type: {sock_type}")
            return EXIT_ERROR

        self.sock_fd.settimeout(1.0)

        self.my_port = self.sock_fd.getsockname()[1]

        self.thread = threading.Thread(target=self.backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    def connect(self):
        if self.state != TCPState.CLOSED or self.sock_type != "TCP_INITIATOR":
            print(f"[{state_to_string(self.state)}] Cannot connect: invalid state or socket type")
            return EXIT_ERROR
            
        syn_packet = Packet(seq=self.window["next_seq_to_send"], ack=0, flags=SYN_FLAG)
        print(f"[{state_to_string(self.state)}] Sending SYN packet (seq={syn_packet.seq}, ack={syn_packet.ack}, flags={format_flags(syn_packet.flags)})")
        self.sock_fd.sendto(syn_packet.encode(), self.conn)
        
        self.window["next_seq_to_send"] += 1
        
        old_state = self.state
        self.state = TCPState.SYN_SENT
        print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Waiting for SYN+ACK")
        
        if not self.connection_established.wait(timeout=DEFAULT_TIMEOUT):
            print(f"[{state_to_string(self.state)}] Connection timeout")
            self.state = TCPState.CLOSED
            print(f"[{state_to_string(self.state)} -> CLOSED] Connection failed")
            return EXIT_ERROR
            
        return EXIT_SUCCESS

    def close(self):
        print(f"[{state_to_string(self.state)}] Closing socket")

        old_state = self.state
        if self.state == TCPState.ESTABLISHED or self.state == TCPState.SYN_RCVD:
            self.state = TCPState.FIN_SENT
            print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Beginning active close")
            
        elif self.state == TCPState.CLOSE_WAIT:
            self.state = TCPState.LAST_ACK
            print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Responding to peer close")
            
        fin_packet = Packet(seq=self.window["next_seq_to_send"], ack=self.window["last_ack"], flags=FIN_FLAG)
        print(f"[{state_to_string(self.state)}] Sending FIN packet (seq={fin_packet.seq}, ack={fin_packet.ack}, flags={format_flags(fin_packet.flags)})")
        self.sock_fd.sendto(fin_packet.encode(), self.conn)
        self.window["next_seq_to_send"] += 1
        
        if not self.connection_closed.wait(timeout=DEFAULT_TIMEOUT):
            print(f"[{state_to_string(self.state)}] Close operation timed out")
        
        self.death_lock.acquire()
        try:
            self.dying = True
        finally:
            self.death_lock.release()

        if self.thread:
            self.thread.join()

        if self.sock_fd:
            self.sock_fd.close()
            print(f"[CLOSED] Socket resources released")
        else:
            print("[ERROR] Null socket")
            return EXIT_ERROR

        return EXIT_SUCCESS

    def send(self, data):
        if not self.conn and self.sock_type == "TCP_INITIATOR":
            print(f"[{state_to_string(self.state)}] Connection not established")
            raise ValueError("Connection not established.")
        
        # If we're a client and not connected yet, establish connection
        if self.sock_type == "TCP_INITIATOR" and self.state == TCPState.CLOSED:
            print(f"[{state_to_string(self.state)}] Establishing connection before sending")
            if self.connect() != EXIT_SUCCESS:
                print(f"[{state_to_string(self.state)}] Failed to establish connection")
                raise ConnectionError("Failed to establish connection")
        
        # For server, wait for the connection to be established
        if self.sock_type == "TCP_LISTENER" and self.state in [TCPState.LISTEN, TCPState.SYN_RCVD]:
            print(f"[{state_to_string(self.state)}] Waiting for connection to be established before sending")
            # Wait for the connection_established event
            if not self.connection_established.wait(timeout=30):  # 30-second timeout
                print(f"[{state_to_string(self.state)}] Timeout waiting for connection")
                raise ConnectionError("Timeout waiting for connection")
        
        if self.state != TCPState.ESTABLISHED:
            print(f"[{state_to_string(self.state)}] Cannot send data in current state")
            raise ConnectionError(f"Cannot send data in state {self.state}")
        
        with self.send_lock:
            print(f"[{state_to_string(self.state)}] Sending {len(data)} bytes of data")
            self.send_segment(data)

    def recv(self, buf, length, flags):
        # If we're a client and not connected yet, establish connection
        if self.sock_type == "TCP_INITIATOR" and self.state == TCPState.CLOSED:
            print(f"[{state_to_string(self.state)}] Establishing connection before receiving")
            if self.connect() != EXIT_SUCCESS:
                print(f"[{state_to_string(self.state)}] Failed to establish connection")
                return EXIT_ERROR
        
        # For server, wait for the connection to be established
        if self.sock_type == "TCP_LISTENER" and self.state == TCPState.LISTEN:
            print(f"[{state_to_string(self.state)}] Waiting for connection to be established before receiving")
            if not self.connection_established.wait(timeout=30):  # 30-second timeout
                print(f"[{state_to_string(self.state)}] Timeout waiting for connection")
                return EXIT_ERROR
        
        # Make sure we're in a state where we can receive data
        if self.state not in [TCPState.ESTABLISHED, TCPState.CLOSE_WAIT]:
            print(f"[{state_to_string(self.state)}] Cannot receive data in current state")
            return EXIT_ERROR
            
        read_len = 0

        if length < 0:
            print("[ERROR] Negative length")
            return EXIT_ERROR

        # If blocking read, wait until there's data in buffer
        if flags == ReadMode.NO_FLAG:
            print(f"[{state_to_string(self.state)}] Blocking read, waiting for data")
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
                    
                    print(f"[{state_to_string(self.state)}] Read {read_len} bytes from buffer, {self.window['recv_len']} bytes remaining")
            else:
                print(f"[ERROR] Unknown or unimplemented flag: {flags}")
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
                print(f"[{state_to_string(self.state)}] Sending data segment (seq={segment.seq}, ack={segment.ack}, flags={format_flags(segment.flags)}, len={payload_len})")
                self.sock_fd.sendto(segment.encode(), self.conn)

                if self.wait_for_ack(ack_goal):
                    print(f"[{state_to_string(self.state)}] Segment acknowledged (seq={seq_no}, ack_goal={ack_goal})")
                    self.window["next_seq_to_send"] += payload_len
                    break
                else:
                    print(f"[{state_to_string(self.state)}] Timeout: Retransmitting segment (seq={segment.seq}, ack={segment.ack})")

            offset += payload_len


    def wait_for_ack(self, ack_goal):
        with self.recv_lock:
            start = time.time()
            print(f"[{state_to_string(self.state)}] Waiting for ACK (current={self.window['next_seq_expected']}, goal={ack_goal})")
            while self.window["next_seq_expected"] < ack_goal:
                elapsed = time.time() - start
                remaining = DEFAULT_TIMEOUT - elapsed
                if remaining <= 0:
                    print(f"[{state_to_string(self.state)}] ACK timeout (current={self.window['next_seq_expected']}, goal={ack_goal})")
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
                    print(f"[{state_to_string(self.state)}] New peer connection from {addr}")

                print(f"[{state_to_string(self.state)}] Received packet (seq={packet.seq}, ack={packet.ack}, flags={format_flags(packet.flags)}, payload_len={len(packet.payload)})")

                # Handle connection establishment
                if self.state == TCPState.LISTEN and (packet.flags & SYN_FLAG) != 0:
                    synack_packet = Packet(seq=self.window["next_seq_to_send"], ack=packet.seq + 1, flags=SYN_FLAG | ACK_FLAG)
                    print(f"[{state_to_string(self.state)}] Sending SYN+ACK packet (seq={synack_packet.seq}, ack={synack_packet.ack}, flags={format_flags(synack_packet.flags)})")
                    self.sock_fd.sendto(synack_packet.encode(), addr)

                    self.window["next_seq_to_send"] += 1
                    self.window["last_ack"] = packet.seq + 1
                    
                    old_state = self.state
                    self.state = TCPState.SYN_RCVD
                    print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Handshake step 1 complete")

                elif self.state == TCPState.SYN_SENT:
                    if (packet.flags & SYN_FLAG) != 0 and (packet.flags & ACK_FLAG) != 0:
                        self.window["next_seq_expected"] = packet.ack
                        
                        ack_packet = Packet(seq=self.window["next_seq_to_send"], ack=packet.seq + 1, flags=ACK_FLAG)
                        print(f"[{state_to_string(self.state)}] Sending ACK packet (seq={ack_packet.seq}, ack={ack_packet.ack}, flags={format_flags(ack_packet.flags)})")
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        self.window["last_ack"] = packet.seq + 1
                        
                        old_state = self.state
                        self.state = TCPState.ESTABLISHED
                        print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Connection established")
                        self.connection_established.set()
                        
                    elif (packet.flags & SYN_FLAG) != 0:
                        synack_packet = Packet(seq=self.window["next_seq_to_send"], ack=packet.seq + 1, flags=SYN_FLAG | ACK_FLAG)
                        print(f"[{state_to_string(self.state)}] Simultaneous open: Sending SYN+ACK (seq={synack_packet.seq}, ack={synack_packet.ack}, flags={format_flags(synack_packet.flags)})")
                        self.sock_fd.sendto(synack_packet.encode(), addr)
                        
                        self.window["last_ack"] = packet.seq + 1
                        
                        old_state = self.state
                        self.state = TCPState.SYN_RCVD
                        print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Simultaneous open")

                elif self.state == TCPState.SYN_RCVD and (packet.flags & ACK_FLAG) != 0:
                    if packet.ack > self.window["next_seq_expected"]:
                        self.window["next_seq_expected"] = packet.ack
                        print(f"[{state_to_string(self.state)}] Updated next_seq_expected to {packet.ack}")
                    
                    old_state = self.state
                    self.state = TCPState.ESTABLISHED
                    print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Connection established")
                    self.connection_established.set()

                elif self.state == TCPState.ESTABLISHED and (packet.flags & FIN_FLAG) != 0:
                    ack_packet = Packet(seq=self.window["next_seq_to_send"], ack=packet.seq + 1, flags=ACK_FLAG)
                    print(f"[{state_to_string(self.state)}] Sending ACK for FIN (seq={ack_packet.seq}, ack={ack_packet.ack}, flags={format_flags(ack_packet.flags)})")
                    self.sock_fd.sendto(ack_packet.encode(), addr)
                    
                    self.window["last_ack"] = packet.seq + 1
                    
                    old_state = self.state
                    self.state = TCPState.CLOSE_WAIT
                    print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Remote initiated close")

                elif self.state == TCPState.FIN_SENT:
                    if (packet.flags & FIN_FLAG) != 0:
                        ack_packet = Packet(seq=self.window["next_seq_to_send"], ack=packet.seq + 1, flags=ACK_FLAG)
                        print(f"[{state_to_string(self.state)}] Sending ACK for FIN (seq={ack_packet.seq}, ack={ack_packet.ack}, flags={format_flags(ack_packet.flags)})")
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        self.window["last_ack"] = packet.seq + 1
                        
                        old_state = self.state
                        self.state = TCPState.TIME_WAIT
                        self.time_wait_start = time.time()
                        print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Entering TIME_WAIT")
                        self.connection_closed.set()
                    elif (packet.flags & ACK_FLAG) != 0:
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                            print(f"[{state_to_string(self.state)}] Updated next_seq_expected to {packet.ack}")
                        print(f"[{state_to_string(self.state)}] Received ACK for our FIN, waiting for peer's FIN")

                elif self.state == TCPState.LAST_ACK and (packet.flags & ACK_FLAG) != 0:
                    if packet.ack > self.window["next_seq_expected"]:
                        self.window["next_seq_expected"] = packet.ack
                        print(f"[{state_to_string(self.state)}] Updated next_seq_expected to {packet.ack}")
                    
                    old_state = self.state
                    self.state = TCPState.CLOSED
                    print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Connection closed")
                    self.connection_closed.set()

                elif (packet.flags & ACK_FLAG) != 0 and not (packet.flags & SYN_FLAG) and not (packet.flags & FIN_FLAG):
                    with self.recv_lock:
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                            print(f"[{state_to_string(self.state)}] Updated next_seq_expected to {packet.ack}")
                        self.wait_cond.notify_all()

                if len(packet.payload) > 0 and self.state in [TCPState.ESTABLISHED, TCPState.CLOSE_WAIT]:
                    if packet.seq == self.window["last_ack"]:
                        with self.recv_lock:
                            self.window["recv_buf"] += packet.payload
                            self.window["recv_len"] += len(packet.payload)

                        with self.wait_cond:
                            self.wait_cond.notify_all()

                        print(f"[{state_to_string(self.state)}] Received data segment (seq={packet.seq}, len={len(packet.payload)}, total_received={self.window['recv_len']})")

                        ack_val = packet.seq + len(packet.payload)
                        ack_packet = Packet(seq=self.window["next_seq_to_send"], ack=ack_val, flags=ACK_FLAG)
                        print(f"[{state_to_string(self.state)}] Sending ACK for data (seq={ack_packet.seq}, ack={ack_packet.ack}, flags={format_flags(ack_packet.flags)})")
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        self.window["last_ack"] = ack_val
                    else:
                        print(f"[{state_to_string(self.state)}] Out-of-order packet (received_seq={packet.seq}, expected_seq={self.window['last_ack']})")
                        continue

                if self.state == TCPState.TIME_WAIT:
                    if time.time() - self.time_wait_start >= 2 * DEFAULT_TIMEOUT:  # 2 segment lifetimes
                        old_state = self.state
                        self.state = TCPState.CLOSED
                        print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] TIME_WAIT completed")
                        self.connection_closed.set()
        
            except Exception as e:
                if not self.dying:
                    print(f"[ERROR] Backend exception: {e}")