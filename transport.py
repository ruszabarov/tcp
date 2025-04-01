import socket
import struct
import threading
import time  
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER
from logs import TCPState, state_to_string, format_flags


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

class Packet:
    def __init__(self, seq=0, ack=0, flags=0, adv_window=0, payload=b""):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.adv_window = adv_window
        self.payload = payload

    def encode(self):
        header = struct.pack("!IIIIH", self.seq, self.ack, self.flags, self.adv_window, len(self.payload))
        return header + self.payload

    @staticmethod
    def decode(data):
        header_size = struct.calcsize("!IIIIH")
        seq, ack, flags, adv_window, payload_len = struct.unpack("!IIIIH", data[:header_size])
        payload = data[header_size:]
        return Packet(seq, ack, flags, adv_window, payload)


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
            "send_window": MAX_NETWORK_BUFFER,  # Current send window size (based on receiver's advertised window)
            "last_byte_sent": 0,      # Last byte sent (for calculating effective window)
            "last_byte_acked": 0      # Last byte acknowledged (for calculating effective window)
        }
        self.sock_type = None
        self.conn = None
        self.my_port = None
        
        self.state = TCPState.CLOSED
        self.time_wait_start = None
        self.connection_established = threading.Event()
        self.connection_closed = threading.Event()
        self.last_window_probe_time = 0

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
            
        syn_packet = Packet(seq=self.window["next_seq_to_send"], ack=0, flags=SYN_FLAG, adv_window=MAX_NETWORK_BUFFER)
        print(f"[{state_to_string(self.state)}] Sending SYN packet (seq={syn_packet.seq}, ack={syn_packet.ack}, flags={format_flags(syn_packet.flags)}, adv_window={syn_packet.adv_window})")
        self.sock_fd.sendto(syn_packet.encode(), self.conn)
        
        self.window["next_seq_to_send"] += 1
        self.window["last_byte_sent"] = self.window["next_seq_to_send"]
        
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
            
        # Calculate advertised window
        avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
        fin_packet = Packet(seq=self.window["next_seq_to_send"], ack=self.window["last_ack"], 
                           flags=FIN_FLAG, adv_window=avail_window)
        print(f"[{state_to_string(self.state)}] Sending FIN packet (seq={fin_packet.seq}, ack={fin_packet.ack}, flags={format_flags(fin_packet.flags)}, adv_window={avail_window})")
        self.sock_fd.sendto(fin_packet.encode(), self.conn)
        self.window["next_seq_to_send"] += 1
        self.window["last_byte_sent"] = self.window["next_seq_to_send"]
        
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
                raise ConnectionError("Failed to establish connection")
        
        # For server, wait for the connection to be established
        if self.sock_type == "TCP_LISTENER" and self.state in [TCPState.LISTEN, TCPState.SYN_RCVD]:
            print(f"[{state_to_string(self.state)}] Waiting for connection to be established before sending")
            # Wait for the connection_established event
            if not self.connection_established.wait(timeout=30):  # 30-second timeout
                raise ConnectionError("Timeout waiting for connection")
        
        if self.state != TCPState.ESTABLISHED:
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
                    
                    # After reading data, we should update our advertised window
                    # and inform the sender that we have more space available
                    if self.state == TCPState.ESTABLISHED and self.conn:
                        avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                        ack_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=ACK_FLAG, 
                            adv_window=avail_window
                        )
                        print(f"[{state_to_string(self.state)}] Sending window update (adv_window={avail_window})")
                        self.sock_fd.sendto(ack_packet.encode(), self.conn)
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
            # Calculate effective window
            with self.recv_lock:
                effective_window = self.window["send_window"] - (self.window["last_byte_sent"] - self.window["last_byte_acked"])
                
                # If effective window is zero or negative, need to do window probing
                if effective_window <= 0:
                    current_time = time.time()
                    # Only send a probe every 1 second
                    if current_time - self.last_window_probe_time >= 1:
                        self.last_window_probe_time = current_time
                        print(f"[{state_to_string(self.state)}] Zero window condition, sending probe")
                        self.send_window_probe()
                    else:
                        # Wait a bit before trying again
                        self.wait_cond.wait(0.1)
                    continue
                
                # Determine how much data we can send (limited by effective window)
                payload_len = min(MSS, total_len - offset, effective_window)
                
                seq_no = self.window["next_seq_to_send"]
                chunk = data[offset : offset + payload_len]
                
                # Calculate available receive window to advertise
                avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                
                segment = Packet(
                    seq=seq_no, 
                    ack=self.window["last_ack"], 
                    flags=0, 
                    adv_window=avail_window, 
                    payload=chunk
                )
                
                ack_goal = seq_no + payload_len
                
                # Update last_byte_sent
                self.window["last_byte_sent"] = seq_no + payload_len
                
            # Send packet outside the lock
            print(f"[{state_to_string(self.state)}] Sending data segment (seq={segment.seq}, ack={segment.ack}, flags={format_flags(segment.flags)}, len={payload_len}, effective_window={effective_window})")
            self.sock_fd.sendto(segment.encode(), self.conn)
            
            if self.wait_for_ack(ack_goal):
                print(f"[{state_to_string(self.state)}] Segment acknowledged (seq={seq_no}, ack_goal={ack_goal})")
                with self.recv_lock:
                    self.window["next_seq_to_send"] += payload_len
                offset += payload_len
            else:
                print(f"[{state_to_string(self.state)}] Timeout: Will retransmit segment (seq={segment.seq}, ack={segment.ack})")
    
    def send_window_probe(self):
        """Send a 1-byte probe to check if the receiver's window has opened"""
        with self.recv_lock:
            seq_no = self.window["last_byte_acked"]  # Start of unacknowledged data
            
            # Calculate available window to advertise
            avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
            
            # Create a 1-byte probe
            probe = Packet(
                seq=seq_no, 
                ack=self.window["last_ack"], 
                flags=0, 
                adv_window=avail_window, 
                payload=b"?",  # 1-byte probe
            )
            
        print(f"[{state_to_string(self.state)}] Sending window probe (seq={seq_no})")
        self.sock_fd.sendto(probe.encode(), self.conn)

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

                # Wait for ACK to arrive
                self.wait_cond.wait(timeout=remaining)
                
                # If we got ACK with right sequence number, update last_byte_acked
                if self.window["next_seq_expected"] >= ack_goal:
                    self.window["last_byte_acked"] = ack_goal
            
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

                print(f"[{state_to_string(self.state)}] Received packet (seq={packet.seq}, ack={packet.ack}, flags={format_flags(packet.flags)}, payload_len={len(packet.payload)}, adv_window={packet.adv_window})")

                # Update the send window
                with self.recv_lock:
                    if packet.adv_window >= 0:
                        self.window["send_window"] = packet.adv_window
                        print(f"[{state_to_string(self.state)}] Updated send window to {packet.adv_window}")

                # Handle connection establishment
                if self.state == TCPState.LISTEN and (packet.flags & SYN_FLAG) != 0:
                    avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                    synack_packet = Packet(
                        seq=self.window["next_seq_to_send"], 
                        ack=packet.seq + 1, 
                        flags=SYN_FLAG | ACK_FLAG, 
                        adv_window=avail_window
                    )
                    print(f"[{state_to_string(self.state)}] Sending SYN+ACK packet (seq={synack_packet.seq}, ack={synack_packet.ack}, flags={format_flags(synack_packet.flags)}, adv_window={avail_window})")
                    self.sock_fd.sendto(synack_packet.encode(), addr)

                    self.window["next_seq_to_send"] += 1
                    self.window["last_byte_sent"] = self.window["next_seq_to_send"]
                    self.window["last_ack"] = packet.seq + 1
                    
                    old_state = self.state
                    self.state = TCPState.SYN_RCVD
                    print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Handshake step 1 complete")

                elif self.state == TCPState.SYN_SENT:
                    if (packet.flags & SYN_FLAG) != 0 and (packet.flags & ACK_FLAG) != 0:
                        with self.recv_lock:
                            self.window["next_seq_expected"] = packet.ack
                            self.window["last_byte_acked"] = packet.ack
                            self.window["send_window"] = packet.adv_window
                            
                            avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=packet.seq + 1, 
                                flags=ACK_FLAG, 
                                adv_window=avail_window
                            )
                        
                        print(f"[{state_to_string(self.state)}] Sending ACK packet (seq={ack_packet.seq}, ack={ack_packet.ack}, flags={format_flags(ack_packet.flags)}, adv_window={avail_window})")
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        self.window["last_ack"] = packet.seq + 1
                        
                        old_state = self.state
                        self.state = TCPState.ESTABLISHED
                        print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Connection established")
                        self.connection_established.set()
                        
                    elif (packet.flags & SYN_FLAG) != 0:
                        avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                        synack_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=packet.seq + 1, 
                            flags=SYN_FLAG | ACK_FLAG, 
                            adv_window=avail_window
                        )
                        print(f"[{state_to_string(self.state)}] Simultaneous open: Sending SYN+ACK (seq={synack_packet.seq}, ack={synack_packet.ack}, flags={format_flags(synack_packet.flags)}, adv_window={avail_window})")
                        self.sock_fd.sendto(synack_packet.encode(), addr)
                        
                        self.window["last_ack"] = packet.seq + 1
                        
                        old_state = self.state
                        self.state = TCPState.SYN_RCVD
                        print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Simultaneous open")

                elif self.state == TCPState.SYN_RCVD and (packet.flags & ACK_FLAG) != 0:
                    with self.recv_lock:
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                            self.window["last_byte_acked"] = packet.ack
                            print(f"[{state_to_string(self.state)}] Updated next_seq_expected to {packet.ack}")
                    
                    old_state = self.state
                    self.state = TCPState.ESTABLISHED
                    print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Connection established")
                    self.connection_established.set()

                elif self.state == TCPState.ESTABLISHED and (packet.flags & FIN_FLAG) != 0:
                    avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                    ack_packet = Packet(
                        seq=self.window["next_seq_to_send"], 
                        ack=packet.seq + 1, 
                        flags=ACK_FLAG, 
                        adv_window=avail_window
                    )
                    print(f"[{state_to_string(self.state)}] Sending ACK for FIN (seq={ack_packet.seq}, ack={ack_packet.ack}, flags={format_flags(ack_packet.flags)}, adv_window={avail_window})")
                    self.sock_fd.sendto(ack_packet.encode(), addr)
                    
                    self.window["last_ack"] = packet.seq + 1
                    
                    old_state = self.state
                    self.state = TCPState.CLOSE_WAIT
                    print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Remote initiated close")

                elif self.state == TCPState.FIN_SENT:
                    if (packet.flags & FIN_FLAG) != 0:
                        avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                        ack_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=packet.seq + 1, 
                            flags=ACK_FLAG, 
                            adv_window=avail_window
                        )
                        print(f"[{state_to_string(self.state)}] Sending ACK for FIN (seq={ack_packet.seq}, ack={ack_packet.ack}, flags={format_flags(ack_packet.flags)}, adv_window={avail_window})")
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        self.window["last_ack"] = packet.seq + 1
                        
                        old_state = self.state
                        self.state = TCPState.TIME_WAIT
                        self.time_wait_start = time.time()
                        print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Entering TIME_WAIT")
                        self.connection_closed.set()
                    elif (packet.flags & ACK_FLAG) != 0:
                        with self.recv_lock:
                            if packet.ack > self.window["next_seq_expected"]:
                                self.window["next_seq_expected"] = packet.ack
                                self.window["last_byte_acked"] = packet.ack
                                print(f"[{state_to_string(self.state)}] Updated next_seq_expected to {packet.ack}")
                        print(f"[{state_to_string(self.state)}] Received ACK for our FIN, waiting for peer's FIN")

                elif self.state == TCPState.LAST_ACK and (packet.flags & ACK_FLAG) != 0:
                    with self.recv_lock:
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                            self.window["last_byte_acked"] = packet.ack
                            print(f"[{state_to_string(self.state)}] Updated next_seq_expected to {packet.ack}")
                    
                    old_state = self.state
                    self.state = TCPState.CLOSED
                    print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Connection closed")
                    self.connection_closed.set()

                elif (packet.flags & ACK_FLAG) != 0 and not (packet.flags & SYN_FLAG) and not (packet.flags & FIN_FLAG):
                    with self.recv_lock:
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                            self.window["last_byte_acked"] = packet.ack
                            print(f"[{state_to_string(self.state)}] Updated next_seq_expected to {packet.ack}")
                        self.wait_cond.notify_all()

                if len(packet.payload) > 0 and self.state in [TCPState.ESTABLISHED, TCPState.CLOSE_WAIT]:
                    if packet.seq == self.window["last_ack"]:
                        # Check if we have enough buffer space
                        if self.window["recv_len"] + len(packet.payload) <= MAX_NETWORK_BUFFER:
                            with self.recv_lock:   
                                self.window["recv_buf"] += packet.payload
                                self.window["recv_len"] += len(packet.payload)

                            with self.wait_cond:
                                self.wait_cond.notify_all()

                            print(f"[{state_to_string(self.state)}] Received data segment (seq={packet.seq}, len={len(packet.payload)}, total_received={self.window['recv_len']})")

                            ack_val = packet.seq + len(packet.payload)
                            # Calculate advertised window
                            avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=ack_val, 
                                flags=ACK_FLAG, 
                                adv_window=avail_window
                            )
                            print(f"[{state_to_string(self.state)}] Sending ACK for data (seq={ack_packet.seq}, ack={ack_packet.ack}, flags={format_flags(ack_packet.flags)}, adv_window={avail_window})")
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                            self.window["last_ack"] = ack_val
                        else:
                            print(f"[{state_to_string(self.state)}] Buffer overflow: Cannot receive more data")
                            # Advertise zero window
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=0
                            )
                            print(f"[{state_to_string(self.state)}] Advertising zero window (seq={ack_packet.seq}, ack={ack_packet.ack}, adv_window=0)")
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                    else:
                        print(f"[{state_to_string(self.state)}] Out-of-order packet (received_seq={packet.seq}, expected_seq={self.window['last_ack']})")
                        # Send duplicate ACK
                        avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                        dup_ack = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=ACK_FLAG, 
                            adv_window=avail_window
                        )
                        print(f"[{state_to_string(self.state)}] Sending duplicate ACK (seq={dup_ack.seq}, ack={dup_ack.ack}, adv_window={avail_window})")
                        self.sock_fd.sendto(dup_ack.encode(), addr)
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