#!/usr/bin/env python3
"""
Simulador SLE RAF Provider (ISP1/TML) para testing con YAMCS.

Implementa el nivel minimo del protocolo:
  - TML (Transport Mapping Layer): framing TCP
  - SLE BIND / BIND-RETURN
  - SLE RAF START / START-RETURN
  - SLE RAF TRANSFER-DATA (envia TM frames)
  - SLE STOP / STOP-RETURN
  - SLE UNBIND / UNBIND-RETURN
  - TML heartbeat

Uso:
  python3 sle_provider.py --port 4000
"""

import argparse
import math
import socket
import struct
import threading
import time
import traceback

# ---------------------------------------------------------------------------
# TML (Transport Mapping Layer) - ISP1
# ---------------------------------------------------------------------------
TML_SLE_PDU = 0x01000000
TML_CTX_MSG = 0x02000000
TML_HB_MSG  = 0x03000000


def tml_send(sock, pdu_type, data=b""):
    header = struct.pack(">II", pdu_type, len(data))
    sock.sendall(header + data)


def tml_recv(sock):
    header = b""
    while len(header) < 8:
        chunk = sock.recv(8 - len(header))
        if not chunk:
            return None, None
        header += chunk
    pdu_type, length = struct.unpack(">II", header)
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None, None
        data += chunk
    return pdu_type, data


# ---------------------------------------------------------------------------
# ASN.1 BER encoding helpers
# ---------------------------------------------------------------------------

def _ber_encode_tag(tag_class, constructed, number):
    first = (tag_class << 6) | (constructed << 5)
    if number < 31:
        return bytes([first | number])
    out = bytes([first | 31])
    digits = []
    n = number
    while n > 0:
        digits.append(n & 0x7F)
        n >>= 7
    digits.reverse()
    for i, d in enumerate(digits):
        out += bytes([d | 0x80]) if i < len(digits) - 1 else bytes([d])
    return out


def _ber_encode_length(length):
    if length < 0x80:
        return bytes([length])
    octets = []
    n = length
    while n > 0:
        octets.append(n & 0xFF)
        n >>= 8
    octets.reverse()
    return bytes([0x80 | len(octets)]) + bytes(octets)


def _tlv(tag_bytes, value):
    return tag_bytes + _ber_encode_length(len(value)) + value


def _int_content(value):
    """Raw BER integer content bytes (no tag/length)."""
    if value == 0:
        return b'\x00'
    if value > 0:
        octets = []
        n = value
        while n > 0:
            octets.append(n & 0xFF)
            n >>= 8
        octets.reverse()
        if octets[0] & 0x80:
            octets.insert(0, 0)
        return bytes(octets)
    # negative
    n = value
    octets = []
    while True:
        octets.append(n & 0xFF)
        n >>= 8
        if n == -1 and octets[-1] & 0x80:
            break
        if n == 0 and not (octets[-1] & 0x80):
            break
    octets.reverse()
    return bytes(octets)


def ber_integer(value):
    return _tlv(b'\x02', _int_content(value))


def ber_octet_string(data):
    return _tlv(b'\x04', data)


def ber_visible_string(s):
    return _tlv(b'\x1a', s.encode('ascii'))


def ber_ctx(number, constructed, value):
    """Context-class tag [number] wrapping value bytes."""
    tag = _ber_encode_tag(2, 1 if constructed else 0, number)
    return _tlv(tag, value)


# ---------------------------------------------------------------------------
# Minimal BER decoder
# ---------------------------------------------------------------------------

def ber_decode_tlv(data, offset=0):
    b = data[offset]; offset += 1
    tag_class = (b >> 6) & 3
    constructed = bool(b & 0x20)
    number = b & 0x1F
    if number == 31:
        number = 0
        while True:
            b = data[offset]; offset += 1
            number = (number << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    b = data[offset]; offset += 1
    if b < 0x80:
        length = b
    else:
        num = b & 0x7F
        length = 0
        for _ in range(num):
            length = (length << 8) | data[offset]; offset += 1
    value = data[offset:offset + length]
    return tag_class, constructed, number, value, offset + length


# ---------------------------------------------------------------------------
# SLE PDU builders
#
# Clave: [N] IMPLICIT SEQUENCE  ->  el tag SEQUENCE (30) se sustituye por
# el context tag [N] constructed.  El contenido va DIRECTAMENTE dentro
# del context tag, SIN un SEQUENCE wrapper adicional.
# ---------------------------------------------------------------------------

def _cred_unused():
    """Credentials CHOICE: unused [0] IMPLICIT NULL  ->  80 00"""
    return b'\x80\x00'


def _positive_null():
    """result CHOICE: positive [0] IMPLICIT NULL  ->  80 00"""
    return b'\x80\x00'


def build_bind_return(version=5):
    """SleBindReturn [101] IMPLICIT SEQUENCE { credentials, responderId, result }"""
    contents = (
        _cred_unused()
        + ber_visible_string("GS-ESA")
        + _tlv(b'\x80', _int_content(version))  # result positive [0] IMPLICIT INTEGER
    )
    return ber_ctx(101, True, contents)


def build_raf_start_return(invoke_id=0):
    """RafStartReturn [1] IMPLICIT SEQUENCE { creds, invokeId, result }"""
    contents = _cred_unused() + ber_integer(invoke_id) + _positive_null()
    return ber_ctx(1, True, contents)


def build_raf_stop_return(invoke_id=0):
    """SleAcknowledgement [3] IMPLICIT SEQUENCE { creds, invokeId, result }"""
    contents = _cred_unused() + ber_integer(invoke_id) + _positive_null()
    return ber_ctx(3, True, contents)


def build_unbind_return():
    """SleUnbindReturn [103] IMPLICIT SEQUENCE { creds, result }"""
    contents = _cred_unused() + _positive_null()
    return ber_ctx(103, True, contents)


def build_schedule_status_report_return(invoke_id=0):
    """RafScheduleStatusReportReturn [5] IMPLICIT SEQUENCE { creds, invokeId, result }
       result CHOICE positiveResult [0] IMPLICIT NULL -> 80 00
       Yamcs envia SCHEDULE-STATUS-REPORT [4] tras el START y espera este return;
       si no llega dentro de returnTimeout aborta la sesion (STOP/UNBIND)."""
    contents = _cred_unused() + ber_integer(invoke_id) + _positive_null()
    return ber_ctx(5, True, contents)


# -- RAF TRANSFER-DATA -------------------------------------------------------

def _cds_time_now():
    """CCSDS Day Segmented 8 bytes: 2B days + 4B ms + 2B us"""
    now = time.time()
    epoch_1958 = -378691200.0
    total = now - epoch_1958
    days = int(total / 86400)
    frac = total - days * 86400
    ms = int(frac * 1000)
    us = int((frac * 1e6) % 1000)
    return struct.pack(">HIH", days, ms, us)


def build_raf_transfer_buffer(frame_data, seq_counter):
    """
    RafTransferBuffer [8] ::= SEQUENCE OF FrameOrNotification
    FrameOrNotification  ::= CHOICE { annotatedFrame [0] IMPLICIT RafTransferDataInvocation }
    """
    ert = _cds_time_now()

    transfer_data = (
        _cred_unused()                        # invokerCredentials
        + _tlv(b'\x80', ert)                  # earthReceiveTime [0] IMPLICIT CDS
        + _tlv(b'\x81', b'ANT1')              # antennaId localForm [1] IMPLICIT
        + ber_integer(-1)                     # dataLinkContinuity
        + ber_integer(0)                      # deliveredFrameQuality good
        + b'\x80\x00'                         # privateAnnotation null [0]
        + ber_octet_string(frame_data)        # data
    )

    frame_or_notif = ber_ctx(0, True, transfer_data)
    return ber_ctx(8, True, frame_or_notif)


# ---------------------------------------------------------------------------
# CCSDS TM Frame builder
# ---------------------------------------------------------------------------
FRAME_LENGTH = 1115


def crc16_ccitt(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def build_ccsds_packet(seq_count):
    apid = 100
    # Version=0, Type=0, SecHdrFlag=0 (NotPresent), APID=100.
    # El contenedor Spacecraft del XTCE exige SecHdrFlag == NotPresent para
    # decodificar el payload; con 0x0800 (SecHdrFlag=1) solo casaba la cabecera.
    pkt_id = apid & 0x07FF
    pkt_seq = 0xC000 | (seq_count & 0x3FFF)
    t = time.time()
    payload = struct.pack(">fIIffffffffffff",
                          0.0, 1, seq_count, 0.0, 400.0,
                          6771.0 + 10*math.sin(t*0.1), 0.0, 0.0,
                          0.0, 7.67, 0.0,
                          40.41 + 5*math.sin(t*0.05),
                          -3.70 + 5*math.cos(t*0.05),
                          8.0 + math.sin(t*0.5), 8.2)
    pad = 120 - len(payload)
    if pad > 0:
        payload += b'\x00' * pad
    hdr = struct.pack(">HHH", pkt_id, pkt_seq, len(payload) - 1)
    return hdr + payload


def build_tm_frame(spacecraft_id=0x01, vc_id=0, frame_seq=0):
    pkt = build_ccsds_packet(frame_seq)
    word1 = (0b00 << 14) | ((spacecraft_id & 0x3FF) << 4) | ((vc_id & 0x07) << 1)
    mcfc = frame_seq & 0xFF
    vcfc = frame_seq & 0xFF
    header = struct.pack(">HBBH", word1, mcfc, vcfc, 0x0000)
    data_len = FRAME_LENGTH - 6 - 2
    data_field = pkt[:data_len] if len(pkt) > data_len else pkt + b'\xFE'*(data_len - len(pkt))
    frame = header + data_field
    frame += struct.pack(">H", crc16_ccitt(frame))
    return frame


# ---------------------------------------------------------------------------
# SLE Provider state machine
# ---------------------------------------------------------------------------
class SleRafProvider:
    def __init__(self, conn, addr, frame_rate=1.0):
        self.conn = conn
        self.addr = addr
        self.frame_rate = frame_rate
        self.running = True
        self.bound = False
        self.active = False
        self.frame_seq = 0
        self.lock = threading.Lock()
        self.hb_interval = 25

    def handle(self):
        print(f"[SLE] Conexion aceptada de {self.addr}")

        # 1) Esperar TML Context Message del iniciador (YAMCS)
        pdu_type, data = tml_recv(self.conn)
        if pdu_type != TML_CTX_MSG:
            print(f"[SLE] Esperaba Context Message, recibido: {pdu_type}")
            self.conn.close()
            return

        if len(data) >= 12:
            # ISP1 Context: 4B proto + 4B version + 2B heartbeat + 2B deadfactor
            proto, ver, hb, df = struct.unpack_from(">IIHH", data, 0)
            print(f"[SLE] TML Context: proto={proto:#x} ver={ver} hb={hb}s df={df}")
            if hb > 0:
                self.hb_interval = max(hb - 5, 5)
        else:
            print(f"[SLE] TML Context recibido ({len(data)} bytes)")

        # NO enviamos Context Message de vuelta (solo el iniciador lo envia)

        # 2) Hilos auxiliares
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._data_loop, daemon=True).start()

        # 3) Loop principal
        try:
            while self.running:
                pdu_type, pdu_data = tml_recv(self.conn)
                if pdu_data is None:
                    print("[SLE] Conexion cerrada")
                    break
                if pdu_type == TML_HB_MSG:
                    with self.lock:
                        tml_send(self.conn, TML_HB_MSG)
                    continue
                if pdu_type == TML_SLE_PDU:
                    self._handle_sle_pdu(pdu_data)
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"[SLE] Error: {e}")
        finally:
            self.running = False
            self.conn.close()
            print(f"[SLE] Sesion terminada con {self.addr}")

    def _handle_sle_pdu(self, data):
        try:
            tc, _, num, value, _ = ber_decode_tlv(data, 0)
            if tc != 2:
                print(f"[SLE] PDU inesperado: class={tc} num={num}")
                return

            if num == 100:                    # BIND
                print("[SLE] <- BIND")
                resp = build_bind_return(version=5)
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU, resp)
                self.bound = True
                print("[SLE] -> BIND-RETURN (positivo)")

            elif num == 0:                    # RAF START
                iid = self._extract_invoke_id(value)
                print(f"[SLE] <- RAF START (invokeId={iid})")
                resp = build_raf_start_return(iid)
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU, resp)
                self.active = True
                print("[SLE] -> START-RETURN -- enviando TM frames...")

            elif num == 2:                    # RAF STOP
                iid = self._extract_invoke_id(value)
                print(f"[SLE] <- RAF STOP (invokeId={iid})")
                self.active = False
                resp = build_raf_stop_return(iid)
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU, resp)
                print("[SLE] -> STOP-RETURN")

            elif num == 4:                    # RAF SCHEDULE-STATUS-REPORT
                iid = self._extract_invoke_id(value)
                print(f"[SLE] <- RAF SCHEDULE-STATUS-REPORT (invokeId={iid})")
                resp = build_schedule_status_report_return(iid)
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU, resp)
                print("[SLE] -> SCHEDULE-STATUS-REPORT-RETURN (positivo)")

            elif num == 102:                  # UNBIND
                print("[SLE] <- UNBIND")
                self.active = False
                self.bound = False
                resp = build_unbind_return()
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU, resp)
                print("[SLE] -> UNBIND-RETURN")
                self.running = False

            else:
                print(f"[SLE] PDU desconocido: context [{num}]")

        except Exception as e:
            print(f"[SLE] Error procesando PDU: {e}")
            traceback.print_exc()

    def _extract_invoke_id(self, value):
        try:
            _, _, _, _, off = ber_decode_tlv(value, 0)
            _, _, _, iv, _ = ber_decode_tlv(value, off)
            r = 0
            for b in iv:
                r = (r << 8) | b
            return r
        except Exception:
            return 0

    def _heartbeat_loop(self):
        while self.running:
            time.sleep(self.hb_interval)
            if not self.running:
                break
            try:
                with self.lock:
                    tml_send(self.conn, TML_HB_MSG)
            except OSError:
                break

    def _data_loop(self):
        while self.running:
            if self.active:
                try:
                    frame = build_tm_frame(spacecraft_id=0x01, vc_id=0,
                                           frame_seq=self.frame_seq)
                    pdu = build_raf_transfer_buffer(frame, self.frame_seq)
                    with self.lock:
                        tml_send(self.conn, TML_SLE_PDU, pdu)
                    if self.frame_seq % 10 == 0:
                        print(f"[SLE] -> Frame #{self.frame_seq} ({len(frame)} bytes)")
                    self.frame_seq += 1
                except (BrokenPipeError, OSError):
                    self.running = False
                    break
            time.sleep(1.0 / self.frame_rate)


# ---------------------------------------------------------------------------
# Forward CLTU service - PDU de retorno (proveedor -> YAMCS)
# Estructura ASN.1 verificada contra jsle-1.1.1 (ccsds.sle.transfer.service.cltu)
# ---------------------------------------------------------------------------

def build_cltu_start_return(invoke_id=0):
    """CltuStartReturn [1] IMPLICIT SEQUENCE {
         performerCredentials, invokeId,
         result CHOICE { positiveResult [0] SEQUENCE {
                             startRadiationTime Time,           -- ccsdsFormat [0] CDS 8B
                             stopRadiationTime  ConditionalTime -- undefined  [0] NULL
                         } } }"""
    start_rad = _tlv(b'\x80', _cds_time_now())          # Time ccsdsFormat [0] IMPLICIT OCTET STRING
    stop_rad = b'\x80\x00'                              # ConditionalTime undefined [0] IMPLICIT NULL
    positive = ber_ctx(0, True, start_rad + stop_rad)   # positiveResult [0] IMPLICIT SEQUENCE
    contents = _cred_unused() + ber_integer(invoke_id) + positive
    return ber_ctx(1, True, contents)


def build_cltu_transfer_data_return(invoke_id, cltu_id, buffer_available=1_000_000):
    """CltuTransferDataReturn [11] IMPLICIT SEQUENCE {
         performerCredentials, invokeId, cltuIdentification,
         cltuBufferAvailable, result CHOICE { positiveResult [0] IMPLICIT NULL } }"""
    contents = (
        _cred_unused()
        + ber_integer(invoke_id)
        + ber_integer(cltu_id)
        + ber_integer(buffer_available)
        + b'\x80\x00'                                  # positiveResult [0] IMPLICIT NULL
    )
    return ber_ctx(11, True, contents)


def _cltu_last_ok(cltu_id):
    """CltuLastOk cltuOk [1] SEQUENCE { cltuIdentification, radiationStopTime Time }"""
    inner = ber_integer(cltu_id) + _tlv(b'\x80', _cds_time_now())   # cltuId + Time ccsdsFormat [0]
    return ber_ctx(1, True, inner)                                  # cltuOk [1]


def build_cltu_status_report(n_recv, n_proc, n_rad, last_ok_id=None,
                             buffer_available=1_000_000):
    """CltuStatusReportInvocation [13] IMPLICIT SEQUENCE {
         invokerCredentials, cltuLastProcessed, cltuLastOk,
         cltuProductionStatus, uplinkStatus,
         numberOfCltusReceived, numberOfCltusProcessed, numberOfCltusRadiated,
         cltuBufferAvailable }
       Clave: cltuProductionStatus = operational(0) -> habilita el uplink en YAMCS
       (TcSleLink.isUplinkPossible exige prodStatus==operational). uplink = nominal(3)."""
    last_processed = b'\x80\x00'                        # cltuLastProcessed: noCltuProcessed [0] NULL
    last_ok = _cltu_last_ok(last_ok_id) if last_ok_id is not None else b'\x80\x00'  # noCltuOk [0] NULL
    contents = (
        _cred_unused()
        + last_processed
        + last_ok
        + ber_integer(0)          # cltuProductionStatus = operational
        + ber_integer(3)          # uplinkStatus       = nominal
        + ber_integer(n_recv)     # numberOfCltusReceived
        + ber_integer(n_proc)     # numberOfCltusProcessed
        + ber_integer(n_rad)      # numberOfCltusRadiated
        + ber_integer(buffer_available)   # cltuBufferAvailable
    )
    return ber_ctx(13, True, contents)


# ---------------------------------------------------------------------------
# Decodificacion CLTU -> TC Transfer Frame -> telecomando (para mostrarlo)
# ---------------------------------------------------------------------------
CLTU_START_SEQ = b'\xeb\x90'
CLTU_TAIL_SEQ = b'\xc5\xc5\xc5\xc5\xc5\xc5\xc5\x79'
CMD_NAMES = {1: "Reboot", 2: "SwitchVoltageOn", 3: "SwitchVoltageOff"}


def decode_cltu(cltu):
    """Quita start/tail y toma los 7 bytes de info de cada codeblock BCH(63,56)."""
    data = cltu
    if data.startswith(CLTU_START_SEQ):
        data = data[len(CLTU_START_SEQ):]
    ti = data.find(CLTU_TAIL_SEQ)
    if ti != -1:
        data = data[:ti]
    frame = bytearray()
    for i in range(0, len(data) - (len(data) % 8), 8):
        frame += data[i:i + 7]                         # 7 info + 1 paridad BCH
    return bytes(frame)


def parse_tc_frame(frame):
    """Cabecera TC Transfer Frame (5B) + campo de datos = paquete CCSDS TC."""
    info = {'scid': None, 'vcid': None, 'seq': None, 'command': None}
    if len(frame) < 5:
        return info
    w0 = (frame[0] << 8) | frame[1]     # version/bypass/ctrl/spare/scid(10)
    w1 = (frame[2] << 8) | frame[3]     # vcid(6)/framelen(10)
    info['scid'] = w0 & 0x03FF
    info['vcid'] = (w1 >> 10) & 0x3F
    info['seq'] = frame[4]
    body = frame[5:]                    # paquete CCSDS TC
    if len(body) >= 8:
        apid = ((body[0] << 8) | body[1]) & 0x07FF
        packet_id = (body[6] << 8) | body[7]   # Packet_ID: campo de 16 bits tras cabecera CCSDS de 6B
        name = CMD_NAMES.get(packet_id, f"Packet_ID={packet_id}")
        info['command'] = f"APID={apid}  {name}"
    return info


# ---------------------------------------------------------------------------
# Forward CLTU Provider - recibe telecomandos de YAMCS
# ---------------------------------------------------------------------------
class SleCltuProvider:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.running = True
        self.active = False
        self.lock = threading.Lock()
        self.hb_interval = 25
        self.cltu_count = 0
        self.num_received = 0
        self.last_ok_id = None

    def handle(self):
        print(f"[CLTU] Conexion aceptada de {self.addr}")
        pdu_type, data = tml_recv(self.conn)
        if pdu_type != TML_CTX_MSG:
            print(f"[CLTU] Esperaba Context Message, recibido: {pdu_type}")
            self.conn.close()
            return
        if len(data) >= 12:
            proto, ver, hb, df = struct.unpack_from(">IIHH", data, 0)
            print(f"[CLTU] TML Context: proto={proto:#x} ver={ver} hb={hb}s df={df}")
            if hb > 0:
                self.hb_interval = max(hb - 5, 5)

        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

        try:
            while self.running:
                pdu_type, pdu_data = tml_recv(self.conn)
                if pdu_data is None:
                    print("[CLTU] Conexion cerrada")
                    break
                if pdu_type == TML_HB_MSG:
                    with self.lock:
                        tml_send(self.conn, TML_HB_MSG)
                    continue
                if pdu_type == TML_SLE_PDU:
                    self._handle_sle_pdu(pdu_data)
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"[CLTU] Error: {e}")
        finally:
            self.running = False
            self.conn.close()
            print(f"[CLTU] Sesion terminada con {self.addr}  (CLTUs recibidos: {self.cltu_count})")

    def _handle_sle_pdu(self, data):
        try:
            tc, _, num, value, _ = ber_decode_tlv(data, 0)
            if tc != 2:
                print(f"[CLTU] PDU inesperado: class={tc} num={num}")
                return

            if num == 100:                        # BIND
                print("[CLTU] <- BIND")
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU, build_bind_return(version=2))
                print("[CLTU] -> BIND-RETURN (positivo)")

            elif num == 0:                        # CLTU START
                iid = self._extract_invoke_id(value)
                print(f"[CLTU] <- CLTU START (invokeId={iid})")
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU, build_cltu_start_return(iid))
                self.active = True
                threading.Thread(target=self._status_loop, daemon=True).start()
                print("[CLTU] -> START-RETURN -- uplink OPERATIONAL, listo para telecomandos")

            elif num == 10:                       # CLTU TRANSFER-DATA (el telecomando)
                iid, cltu_id, cltu = self._parse_transfer_data(value)
                self.cltu_count += 1
                self.num_received += 1
                self.last_ok_id = cltu_id         # lo damos por radiado
                print(f"[CLTU] <- CLTU-TRANSFER-DATA #{self.cltu_count} (id={cltu_id}, {len(cltu)} bytes)")
                self._decode_and_show(cltu)
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU,
                             build_cltu_transfer_data_return(iid, cltu_id))
                print("[CLTU] -> TRANSFER-DATA-RETURN (positivo)")
                self._send_status_report()        # confirma radiacion (drena pendingFrames en YAMCS)

            elif num == 4:                        # SCHEDULE-STATUS-REPORT
                iid = self._extract_invoke_id(value)
                print(f"[CLTU] <- SCHEDULE-STATUS-REPORT (invokeId={iid})")
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU, build_schedule_status_report_return(iid))
                print("[CLTU] -> SCHEDULE-STATUS-REPORT-RETURN (positivo)")

            elif num == 2:                        # STOP
                iid = self._extract_invoke_id(value)
                print(f"[CLTU] <- CLTU STOP (invokeId={iid})")
                self.active = False
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU, build_raf_stop_return(iid))
                print("[CLTU] -> STOP-RETURN")

            elif num == 102:                      # UNBIND
                print("[CLTU] <- UNBIND")
                self.active = False
                with self.lock:
                    tml_send(self.conn, TML_SLE_PDU, build_unbind_return())
                print("[CLTU] -> UNBIND-RETURN")
                self.running = False

            else:
                print(f"[CLTU] PDU desconocido: context [{num}]")

        except Exception as e:
            print(f"[CLTU] Error procesando PDU: {e}")
            traceback.print_exc()

    def _extract_invoke_id(self, value):
        try:
            _, _, _, _, off = ber_decode_tlv(value, 0)    # skip credentials
            _, _, _, iv, _ = ber_decode_tlv(value, off)   # invokeId
            r = 0
            for b in iv:
                r = (r << 8) | b
            return r
        except Exception:
            return 0

    def _parse_transfer_data(self, value):
        """Recorre los TLV: invokeId y cltuId son los 2 primeros INTEGER (0x02),
        el CLTU es el OCTET STRING (0x04)."""
        offset = 0
        ints = []
        cltu = b""
        n = len(value)
        while offset < n:
            tclass, cons, num, val, offset = ber_decode_tlv(value, offset)
            if tclass == 0 and num == 2 and not cons:      # UNIVERSAL INTEGER
                r = 0
                for b in val:
                    r = (r << 8) | b
                ints.append(r)
            elif tclass == 0 and num == 4 and not cons:    # UNIVERSAL OCTET STRING = cltuData
                cltu = val
        invoke_id = ints[0] if len(ints) >= 1 else 0
        cltu_id = ints[1] if len(ints) >= 2 else 0
        return invoke_id, cltu_id, cltu

    def _decode_and_show(self, cltu):
        print(f"        CLTU crudo = {cltu.hex()}")
        try:
            frame = decode_cltu(cltu)
            info = parse_tc_frame(frame)
            print(f"        Frame TC ({len(frame)}B): scid={info['scid']} "
                  f"vc={info['vcid']} seq={info['seq']} data={frame[5:20].hex()}")
            if info['command']:
                print(f"        >>> TELECOMANDO RECIBIDO: {info['command']}")
        except Exception as e:
            print(f"        (decode parcial: {e})")

    def _send_status_report(self):
        try:
            pdu = build_cltu_status_report(self.num_received, self.num_received,
                                           self.num_received, self.last_ok_id)
            with self.lock:
                tml_send(self.conn, TML_SLE_PDU, pdu)
        except OSError:
            self.running = False

    def _status_loop(self):
        # Primer reporte inmediato: marca production=operational -> uplink disponible
        self._send_status_report()
        print("[CLTU] -> STATUS-REPORT (production=operational, uplink=nominal)")
        while self.running and self.active:
            time.sleep(2)
            if not (self.running and self.active):
                break
            self._send_status_report()

    def _heartbeat_loop(self):
        while self.running:
            time.sleep(self.hb_interval)
            if not self.running:
                break
            try:
                with self.lock:
                    tml_send(self.conn, TML_HB_MSG)
            except OSError:
                break


# ---------------------------------------------------------------------------
def _serve(port, provider_cls, extra_args, tag):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    try:
        while True:
            conn, addr = srv.accept()
            handler = provider_cls(conn, addr, *extra_args)
            threading.Thread(target=handler.handle, daemon=True).start()
    except OSError as e:
        print(f"[{tag}] Listener detenido: {e}")
    finally:
        srv.close()


def main():
    ap = argparse.ArgumentParser(description="SLE RAF + CLTU Provider Simulator")
    ap.add_argument("--port", type=int, default=4000, help="puerto RAF (bajada TM)")
    ap.add_argument("--cltu-port", type=int, default=4001, help="puerto CLTU (subida TC)")
    ap.add_argument("--rate", type=float, default=1.0)
    args = ap.parse_args()

    print("=" * 60)
    print("  SLE Provider Simulator (antena)")
    print(f"  RAF  - bajada TM : puerto {args.port}   ({args.rate} fps)")
    print(f"  CLTU - subida TC : puerto {args.cltu_port}")
    print("=" * 60)

    threading.Thread(target=_serve,
                     args=(args.port, SleRafProvider, (args.rate,), "SLE"),
                     daemon=True).start()
    threading.Thread(target=_serve,
                     args=(args.cltu_port, SleCltuProvider, (), "CLTU"),
                     daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SLE] Provider detenido.")


if __name__ == "__main__":
    main()
