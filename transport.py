import socket
import struct
import threading
import time
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER, WINDOW_INITIAL_SSTHRESH, WINDOW_INITIAL_WINDOW_SIZE
from logs import TCPState, state_to_string, format_flags


SYN_FLAG = 0x8   # Synchronization flag
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

EXIT_SUCCESS = 0
EXIT_ERROR = 1

# Congestion control states
class CongestionState:
    SLOW_START = 0
    CONGESTION_AVOIDANCE = 1
    FAST_RECOVERY = 2

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
        self.sack_left = 0
        self.sack_right = 0

    def encode(self):
        header = struct.pack("!IIIIH", self.seq, self.ack, self.flags, self.adv_window, len(self.payload))
        # If SACK is active, append the 64-bit SACK block (two 32-bit unsigned ints).
        if self.flags & SACK_FLAG:
            header += struct.pack("!II", self.sack_left, self.sack_right)
        return header + self.payload

    @staticmethod
    def decode(data):
        base_header_size = struct.calcsize("!IIIIH")
        seq, ack, flags, adv_window, payload_len = struct.unpack("!IIIIH", data[:base_header_size])
        offset = base_header_size
        sack_left = 0
        sack_right = 0
        # If SACK flag is set, read the next 8 bytes (64 bits) for the SACK block.
        if flags & SACK_FLAG:
            sack_left, sack_right = struct.unpack("!II", data[offset:offset + 8])
            offset += 8
        payload = data[offset:offset + payload_len]
        pkt = Packet(seq, ack, flags, adv_window, payload)
        if flags & SACK_FLAG:
            pkt.sack_left = sack_left
            pkt.sack_right = sack_right
        return pkt


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

        # RTT estimation variables
        self.alpha = 0.875  # Common value used in TCP implementations
        self.beta = 0.75    # For RTT deviation (variance)
        self.estimated_rtt = None     # Smoothed RTT estimate
        self.dev_rtt = None           # RTT deviation
        self.current_timeout = DEFAULT_TIMEOUT  # Initial timeout
        self.rtt_lock = threading.Lock()  # For thread-safe access to RTT values
        self.send_times = {}          # Dictionary to store send times for packets

        # Congestion control variables
        self.cwnd = WINDOW_INITIAL_WINDOW_SIZE
        self.ssthresh = WINDOW_INITIAL_SSTHRESH
        self.congestion_state = CongestionState.SLOW_START
        self.dup_ack_count = 0
        self.last_ack_received = 0

        # Congestion state strings for logging
        self.congestion_state_strings = {
            CongestionState.SLOW_START: "SLOW_START",
            CongestionState.CONGESTION_AVOIDANCE: "CONGESTION_AVOIDANCE",
            CongestionState.FAST_RECOVERY: "FAST_RECOVERY"
        }

        # Each entry is a tuple (left_edge, right_edge) representing an out-of-order block.
        self.out_of_order_segments = []

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

        # Record send time for SYN packet
        self.send_times[syn_packet.seq] = time.time()
        self.sock_fd.sendto(syn_packet.encode(), self.conn)

        self.window["next_seq_to_send"] += 1
        self.window["last_byte_sent"] = self.window["next_seq_to_send"]

        old_state = self.state
        self.state = TCPState.SYN_SENT
        print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Waiting for SYN+ACK")

        # Use dynamic timeout instead of fixed timeout
        if not self.connection_established.wait(timeout=self.current_timeout):
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

        # Record send time for FIN packet
        self.send_times[fin_packet.seq] = time.time()
        self.sock_fd.sendto(fin_packet.encode(), self.conn)

        self.window["next_seq_to_send"] += 1
        self.window["last_byte_sent"] = self.window["next_seq_to_send"]

        # Use dynamic timeout
        if not self.connection_closed.wait(timeout=self.current_timeout):
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
            print(f"[{state_to_string(self.state)}][{self.congestion_state_strings[self.congestion_state]} cwnd={self.cwnd}] Sending {len(data)} bytes of data")
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

    def handle_timeout(self):
        """Handle congestion control on timeout (TCP Reno)"""
        with self.rtt_lock:
            old_cwnd = self.cwnd
            old_ssthresh = self.ssthresh
            
            # Set ssthresh to half of current window, but at least 2 MSS
            self.ssthresh = max(self.cwnd // 2, 2 * MSS)
            # Reset cwnd to 1 MSS (TCP Tahoe behavior)
            self.cwnd = MSS
            # Reset duplicate ACK count
            self.dup_ack_count = 0
            # Enter slow start phase
            self.congestion_state = CongestionState.SLOW_START
            
            print(f"[CONGESTION] Timeout: cwnd {old_cwnd} -> {self.cwnd}, ssthresh {old_ssthresh} -> {self.ssthresh}, entering {self.congestion_state_strings[self.congestion_state]}")

    def handle_new_ack(self, ack_val):
        """Handle congestion control when a new ACK is received"""
        with self.rtt_lock:
            if self.congestion_state == CongestionState.FAST_RECOVERY:
                # Exit fast recovery (TCP Reno)
                old_cwnd = self.cwnd
                self.cwnd = self.ssthresh
                self.dup_ack_count = 0
                self.congestion_state = CongestionState.CONGESTION_AVOIDANCE
                print(f"[CONGESTION] Fast recovery complete: cwnd {old_cwnd} -> {self.cwnd}, entering {self.congestion_state_strings[self.congestion_state]}")
            elif self.congestion_state == CongestionState.SLOW_START:
                # In slow start, increase cwnd by 1 MSS for each ACK
                old_cwnd = self.cwnd
                self.cwnd += MSS
                print(f"[CONGESTION] Slow start: cwnd {old_cwnd} -> {self.cwnd}")
                if self.cwnd >= self.ssthresh:
                    self.congestion_state = CongestionState.CONGESTION_AVOIDANCE
                    print(f"[CONGESTION] Slow start threshold reached: cwnd = {self.cwnd}, entering {self.congestion_state_strings[self.congestion_state]}")
            elif self.congestion_state == CongestionState.CONGESTION_AVOIDANCE:
                # In congestion avoidance, increase cwnd by MSS * MSS / cwnd (approximately 1 MSS per RTT)
                old_cwnd = self.cwnd
                self.cwnd += max(1, (MSS * MSS) // self.cwnd)
                print(f"[CONGESTION] Congestion avoidance: cwnd {old_cwnd} -> {self.cwnd}")
            
            # Reset duplicate ACK count for new ACK
            self.dup_ack_count = 0
            self.last_ack_received = ack_val

    def handle_duplicate_ack(self, ack_val):
        """Handle congestion control when a duplicate ACK is received"""
        with self.rtt_lock:
            if ack_val == self.last_ack_received:
                self.dup_ack_count += 1
                print(f"[CONGESTION] Duplicate ACK #{self.dup_ack_count} for {ack_val}")
                
                if self.dup_ack_count == 3:
                    # Fast retransmit/fast recovery (TCP Reno)
                    old_cwnd = self.cwnd
                    old_ssthresh = self.ssthresh
                    
                    # Set ssthresh to half of current window, but at least 2 MSS
                    self.ssthresh = max(self.cwnd // 2, 2 * MSS)
                    # Set cwnd to ssthresh + 3 MSS (TCP Reno behavior)
                    self.cwnd = self.ssthresh + 3 * MSS
                    # Enter fast recovery
                    self.congestion_state = CongestionState.FAST_RECOVERY
                    
                    print(f"[CONGESTION] Fast retransmit: cwnd {old_cwnd} -> {self.cwnd}, ssthresh {old_ssthresh} -> {self.ssthresh}, entering {self.congestion_state_strings[self.congestion_state]}")
                    
                    # Indicate need for retransmission
                    return True
                elif self.congestion_state == CongestionState.FAST_RECOVERY:
                    # In fast recovery, increase cwnd by 1 MSS for each additional duplicate ACK (TCP Reno)
                    old_cwnd = self.cwnd
                    self.cwnd += MSS
                    print(f"[CONGESTION] Fast recovery: cwnd {old_cwnd} -> {self.cwnd}")
            else:
                # If it's a different ACK, reset counter
                self.dup_ack_count = 1
                self.last_ack_received = ack_val
            
            return False

    def retransmit_segment(self, seq_no):
        """Retransmit a segment starting from the given sequence number"""
        print(f"[{state_to_string(self.state)}][{self.congestion_state_strings[self.congestion_state]} cwnd={self.cwnd}] Fast retransmit for seq={seq_no}")
        
        # For a proper implementation, we would need a send buffer to get the data to retransmit
        # Since this implementation doesn't have a send buffer, we'll just mark it for retransmission
        # The actual retransmission will occur on timeout in the send_segment method
        pass

    def send_segment(self, data):
        offset = 0
        total_len = len(data)

        # While there's data left to send
        while offset < total_len:
            # Calculate effective window (min of cwnd and advertised window)
            with self.recv_lock:
                # Use minimum of congestion window and advertised window
                effective_window = min(self.cwnd, self.window["send_window"]) - (self.window["last_byte_sent"] - self.window["last_byte_acked"])

                # If effective window is zero or negative, need to do window probing
                if effective_window <= 0:
                    current_time = time.time()
                    # Only send a probe every 1 second
                    if current_time - self.last_window_probe_time >= 1:
                        self.last_window_probe_time = current_time
                        print(f"[{state_to_string(self.state)}][{self.congestion_state_strings[self.congestion_state]} cwnd={self.cwnd}] Zero window condition, sending probe")
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
                
            # Record send time for RTT calculation
            self.send_times[seq_no] = time.time()
                
            # Send packet outside the lock
            print(f"[{state_to_string(self.state)}][{self.congestion_state_strings[self.congestion_state]} cwnd={self.cwnd}] Sending data segment (seq={segment.seq}, ack={segment.ack}, flags={format_flags(segment.flags)}, len={payload_len}, effective_window={effective_window})")
            self.sock_fd.sendto(segment.encode(), self.conn)
            
            if self.wait_for_ack(ack_goal):
                print(f"[{state_to_string(self.state)}][{self.congestion_state_strings[self.congestion_state]} cwnd={self.cwnd}] Segment acknowledged (seq={seq_no}, ack_goal={ack_goal})")
                with self.recv_lock:
                    self.window["next_seq_to_send"] += payload_len
                offset += payload_len
            else:
                print(f"[{state_to_string(self.state)}][{self.congestion_state_strings[self.congestion_state]} cwnd={self.cwnd}] Timeout: Will retransmit segment (seq={segment.seq}, ack={segment.ack})")
                # Handle timeout for congestion control
                self.handle_timeout()
    
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
            
        # Record send time for RTT calculation
        self.send_times[seq_no] = time.time()
        
        print(f"[{state_to_string(self.state)}][{self.congestion_state_strings[self.congestion_state]} cwnd={self.cwnd}] Sending window probe (seq={seq_no})")
        self.sock_fd.sendto(probe.encode(), self.conn)

    def update_rtt_estimate(self, sample_rtt):
        with self.rtt_lock:
            if self.estimated_rtt is None:
                # First RTT measurement
                self.estimated_rtt = sample_rtt
                self.dev_rtt = sample_rtt / 2  # Initial deviation estimate
            else:
                # Update RTT estimate using EWMA
                self.estimated_rtt = self.alpha * self.estimated_rtt + (1 - self.alpha) * sample_rtt
                
                # Update RTT deviation
                rtt_diff = abs(sample_rtt - self.estimated_rtt)
                self.dev_rtt = self.beta * self.dev_rtt + (1 - self.beta) * rtt_diff
            
            # Calculate timeout value (common formula: EstimatedRTT + 4 * DevRTT)
            self.current_timeout = self.estimated_rtt + 4 * self.dev_rtt
            
            # Set bounds on timeout value (min: 1 second, max: 60 seconds)
            self.current_timeout = min(max(1.0, self.current_timeout), 60.0)
            
            print(f"[RTT] Sample RTT: {sample_rtt:.3f}s, Estimated RTT: {self.estimated_rtt:.3f}s, "
                  f"Deviation: {self.dev_rtt:.3f}s, New timeout: {self.current_timeout:.3f}s")

    def wait_for_ack(self, ack_goal):
        with self.recv_lock:
            start = time.time()
            print(f"[{state_to_string(self.state)}][{self.congestion_state_strings[self.congestion_state]} cwnd={self.cwnd}] Waiting for ACK (current={self.window['next_seq_expected']}, goal={ack_goal})")
            while self.window["next_seq_expected"] < ack_goal:
                elapsed = time.time() - start
                remaining = self.current_timeout - elapsed  # Use dynamic timeout
                if remaining <= 0:
                    print(f"[{state_to_string(self.state)}][{self.congestion_state_strings[self.congestion_state]} cwnd={self.cwnd}] ACK timeout (current={self.window['next_seq_expected']}, goal={ack_goal})")
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

                print(f"[{state_to_string(self.state)}][{self.congestion_state_strings[self.congestion_state]} cwnd={self.cwnd}] Received packet (seq={packet.seq}, ack={packet.ack}, flags={format_flags(packet.flags)}, payload_len={len(packet.payload)}, adv_window={packet.adv_window})")

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
                    
                    # Record send time for SYN+ACK
                    self.send_times[synack_packet.seq] = time.time()
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
                            
                            # Calculate RTT for SYN
                            if packet.ack - 1 in self.send_times:
                                sample_rtt = time.time() - self.send_times[packet.ack - 1]
                                del self.send_times[packet.ack - 1]  # Clean up dictionary
                                self.update_rtt_estimate(sample_rtt)
                            
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
                        
                        # Record send time for SYN+ACK
                        self.send_times[synack_packet.seq] = time.time()
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
                            
                            # Calculate RTT for SYN+ACK
                            if packet.ack - 1 in self.send_times:
                                sample_rtt = time.time() - self.send_times[packet.ack - 1]
                                del self.send_times[packet.ack - 1]  # Clean up dictionary
                                self.update_rtt_estimate(sample_rtt)
                    
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
                                
                                # Calculate RTT for FIN
                                if packet.ack - 1 in self.send_times:
                                    sample_rtt = time.time() - self.send_times[packet.ack - 1]
                                    del self.send_times[packet.ack - 1]  # Clean up dictionary
                                    self.update_rtt_estimate(sample_rtt)
                        print(f"[{state_to_string(self.state)}] Received ACK for our FIN, waiting for peer's FIN")

                elif self.state == TCPState.LAST_ACK and (packet.flags & ACK_FLAG) != 0:
                    with self.recv_lock:
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                            self.window["last_byte_acked"] = packet.ack
                            print(f"[{state_to_string(self.state)}] Updated next_seq_expected to {packet.ack}")
                            
                            # Calculate RTT for FIN in LAST_ACK state
                            if packet.ack - 1 in self.send_times:
                                sample_rtt = time.time() - self.send_times[packet.ack - 1]
                                del self.send_times[packet.ack - 1]  # Clean up dictionary
                                self.update_rtt_estimate(sample_rtt)
                    
                    old_state = self.state
                    self.state = TCPState.CLOSED
                    print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] Connection closed")
                    self.connection_closed.set()

                elif (packet.flags & ACK_FLAG) != 0 and not (packet.flags & SYN_FLAG) and not (packet.flags & FIN_FLAG):
                    with self.recv_lock:
                        if packet.ack > self.window["next_seq_expected"]:
                            # This is a new ACK - process it for congestion control
                            old_seq_expected = self.window["next_seq_expected"]
                            self.window["next_seq_expected"] = packet.ack
                            self.window["last_byte_acked"] = packet.ack
                            print(f"[{state_to_string(self.state)}] Updated next_seq_expected to {packet.ack}")
                            
                            # Calculate RTT for data segment
                            # Find the most recent sequence number that this ACK covers
                            for seq in sorted([s for s in self.send_times.keys() if s < packet.ack], reverse=True):
                                if seq >= old_seq_expected:
                                    sample_rtt = time.time() - self.send_times[seq]
                                    del self.send_times[seq]  # Clean up dictionary
                                    self.update_rtt_estimate(sample_rtt)
                                    break
                            
                            # Clean up old entries from send_times dictionary
                            for seq in list(self.send_times.keys()):
                                if seq < packet.ack:
                                    del self.send_times[seq]
                            
                            # Handle congestion control for new ACK
                            self.handle_new_ack(packet.ack)
                        else:
                            # This is a duplicate ACK - process it for fast retransmit/recovery
                            need_retransmit = self.handle_duplicate_ack(packet.ack)
                            if need_retransmit:
                                # Retransmit the lost segment (fast retransmit)
                                self.retransmit_segment(packet.ack)
                        
                        self.wait_cond.notify_all()

                if len(packet.payload) > 0 and self.state in [TCPState.ESTABLISHED, TCPState.CLOSE_WAIT]:
                    # Check for contiguous data; otherwise, record out-of-order segments for SACK.
                    if packet.seq == self.window["last_ack"]:
                        # In-order: deliver data.
                        if self.window["recv_len"] + len(packet.payload) <= MAX_NETWORK_BUFFER:
                            with self.recv_lock:   
                                self.window["recv_buf"] += packet.payload
                                self.window["recv_len"] += len(packet.payload)

                            with self.wait_cond:
                                self.wait_cond.notify_all()

                            print(f"[{state_to_string(self.state)}] Received data segment (seq={packet.seq}, len={len(packet.payload)}, total_received={self.window['recv_len']})")

                            # Advance the expected sequence number.
                            new_ack = packet.seq + len(packet.payload)
                            # Check if any previously recorded out-of-order segment now makes the data contiguous.
                            # (Assumes segments are kept sorted by left edge.)
                            self.out_of_order_segments.sort()
                            removed = []
                            for seg in self.out_of_order_segments:
                                if seg[0] == new_ack:
                                    new_ack = seg[1]
                                    removed.append(seg)
                            # Remove merged segments
                            for seg in removed:
                                self.out_of_order_segments.remove(seg)
                            self.window["last_ack"] = new_ack

                            # Advertise our available window
                            avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"],
                                ack=self.window["last_ack"],
                                flags=ACK_FLAG,
                                adv_window=avail_window
                            )
                            print(f"[{state_to_string(self.state)}] Sending ACK for data (seq={ack_packet.seq}, ack={ack_packet.ack}, flags={format_flags(ack_packet.flags)}, adv_window={avail_window})")
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                        else:
                            print(f"[{state_to_string(self.state)}] Buffer overflow: Cannot receive more data")
                            # Advertise zero window if full.
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=0
                            )
                            print(f"[{state_to_string(self.state)}] Advertising zero window (seq={ack_packet.seq}, ack={ack_packet.ack}, adv_window=0)")
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                    else:
                        # Out-of-order data received.
                        print(
                            f"[{state_to_string(self.state)}] Out-of-order packet (received_seq={packet.seq}, expected_seq={self.window['last_ack']})")
                        # Record the non-contiguous block.
                        new_block = (packet.seq, packet.seq + len(packet.payload))
                        merged = False
                        for i, (left, right) in enumerate(self.out_of_order_segments):
                            # If the new block overlaps an existing one, merge them.
                            if not (new_block[1] < left or new_block[0] > right):
                                new_left = min(left, new_block[0])
                                new_right = max(right, new_block[1])
                                self.out_of_order_segments[i] = (new_left, new_right)
                                merged = True
                                break
                        if not merged:
                            self.out_of_order_segments.append(new_block)
                        # Sort the list so that the lowest block is first.
                        self.out_of_order_segments.sort()

                        # Send duplicate ACK including SACK information.
                        avail_window = MAX_NETWORK_BUFFER - self.window["recv_len"]
                        dup_ack = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=ACK_FLAG, 
                            adv_window=avail_window
                        )
                        # Report the earliest out-of-order block.
                        if self.out_of_order_segments:
                            sack_left, sack_right = self.out_of_order_segments[0]
                            dup_ack.sack_left = sack_left
                            dup_ack.sack_right = sack_right
                            print(
                                f"[{state_to_string(self.state)}] Sending duplicate ACK with SACK (ack={dup_ack.ack}, sack=({sack_left}, {sack_right}))")
                        else:
                            print(f"[{state_to_string(self.state)}] Sending duplicate ACK (ack={dup_ack.ack})")
                        self.sock_fd.sendto(dup_ack.encode(), addr)
                        continue

                if self.state == TCPState.TIME_WAIT:
                    if time.time() - self.time_wait_start >= 2 * self.current_timeout:  # Use dynamic timeout
                        old_state = self.state
                        self.state = TCPState.CLOSED
                        print(f"[{state_to_string(old_state)} -> {state_to_string(self.state)}] TIME_WAIT completed")
                        self.connection_closed.set()
        
            except Exception as e:
                if not self.dying:
                    print(f"[ERROR] Backend exception: {e}")