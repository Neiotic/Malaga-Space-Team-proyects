import numpy as np
from gnuradio import gr
import pmt

class blk(gr.basic_block):
    """AX.25 UI Frame Builder block.
    Takes input messages (string or u8vector), wraps them in AX.25 UI frame,
    and publishes the frame as a byte PDU."""
    def __init__(self, dest_call='DEST', dest_ssid=0, src_call='SRC', src_ssid=0):
        gr.basic_block.__init__(
            self,
            name='AX.25 Frame Builder',
            in_sig=None,
            out_sig=None
        )
        self.dest_call = dest_call
        self.dest_ssid = dest_ssid
        self.src_call = src_call
        self.src_ssid = src_ssid
        
        self.message_port_register_in(pmt.intern('in'))
        self.set_msg_handler(pmt.intern('in'), self.handle_msg)
        self.message_port_register_out(pmt.intern('out'))

    def encode_address(self, callsign, ssid, is_last):
        # Pad callsign to 6 characters
        call = callsign.upper().ljust(6)[:6]
        encoded = []
        for char in call:
            encoded.append(ord(char) << 1)
        # SSID byte: 0x60 | (ssid << 1) | (1 if is_last else 0)
        ssid_byte = 0x60 | ((ssid & 0x0F) << 1) | (1 if is_last else 0)
        encoded.append(ssid_byte)
        return bytes(encoded)

    def handle_msg(self, msg_pmt):
        if pmt.is_pair(msg_pmt):
            meta = pmt.car(msg_pmt)
            payload_pmt = pmt.cdr(msg_pmt)
        else:
            meta = pmt.make_dict()
            payload_pmt = msg_pmt

        if pmt.is_u8vector(payload_pmt):
            payload = bytes(pmt.u8vector_elements(payload_pmt))
        elif pmt.is_symbol(payload_pmt) or pmt.is_string(payload_pmt):
            payload = pmt.to_python(payload_pmt).encode('utf-8')
        else:
            try:
                payload = str(pmt.to_python(payload_pmt)).encode('utf-8')
            except Exception:
                return

        dest_addr = self.encode_address(self.dest_call, self.dest_ssid, False)
        src_addr = self.encode_address(self.src_call, self.src_ssid, True)
        control = b'\x03' # UI Frame
        pid = b'\xF0'     # No layer 3 protocol
        
        frame = dest_addr + src_addr + control + pid + payload
        
        out_msg = pmt.cons(meta, pmt.init_u8vector(len(frame), list(frame)))
        self.message_port_pub(pmt.intern('out'), out_msg)
