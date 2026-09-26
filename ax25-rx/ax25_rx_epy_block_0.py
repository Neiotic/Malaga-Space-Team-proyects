"""
Embedded Python Blocks:

Each time this file is saved, GRC will instantiate the first class it finds
to get ports and parameters of your block. The arguments to __init__  will
be the parameters. All of them are required to have default values!
"""

import numpy as np
import pmt
from gnuradio import gr


class blk(gr.sync_block):  # other base classes are basic_block, decim_block, interp_block
    """Embedded Python Block example - a simple multiply const"""

    def __init__(self):  # only default arguments here
        """arguments to this function show up as parameters in GRC"""
        gr.sync_block.__init__(
            self,
            name='AX.25 ASCII Decoder',   # will show up in GRC
            in_sig=None,
            out_sig=None
        )
        
        # Puerto de entrada de mensajes
        self.message_port_register_in(pmt.intern("in"))

        # Puerto de salida de mensajes
        self.message_port_register_out(pmt.intern("out"))

        self.set_msg_handler(
            pmt.intern("in"),
            self.handle_msg
        )


    def handle_msg(self, msg):

        # El PDU tiene:
        # msg = pair(metadata, data)
        data = pmt.cdr(msg)

        # Convertimos el vector PMT a bytes
        data_bytes = bytes(pmt.u8vector_elements(data))

        # Cabecera AX.25:
        # 7 bytes destino
        # 7 bytes origen
        # 1 byte control
        # 1 byte PID
        # ----------------
        # 16 bytes
        payload = data_bytes[16:]

        # Convertir payload a ASCII
        text = payload.decode("ascii", errors="replace")

        print("================================")
        print("AX.25 PAYLOAD:")
        print(text)
        print("================================")

        # Mandar el texto como PDU al siguiente bloque
        text_bytes = text.encode("ascii", errors="replace")

        out_vector = pmt.init_u8vector(
            len(text_bytes),
            list(text_bytes)
        )

        self.message_port_pub(
            pmt.intern("out"),
            pmt.cons(pmt.PMT_NIL, out_vector)
        )