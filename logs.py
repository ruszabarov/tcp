"""
Logging utilities for the TCP implementation.
"""

SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

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