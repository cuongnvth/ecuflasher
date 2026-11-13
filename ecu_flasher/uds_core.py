"""
uds_core.py — Core UDS/CAN/SeedKey/Firmware logic.
"""
from __future__ import annotations

import binascii
import ctypes
import glob
import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

try:
    import can
except ImportError:
    can = None

PY_BITS = struct.calcsize("P") * 8
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

KEYGEN_RESULT = {
    1: "buffer too small", 2: "security level invalid",
    3: "variant invalid", 4: "unspecified error",
}

def pe_bitness(path: str) -> Optional[int]:
    try:
        with open(path, "rb") as f:
            hdr = f.read(4096)
        if hdr[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", hdr, 0x3C)[0]
        if hdr[pe:pe + 4] != b"PE\0\0":
            return None
        machine = struct.unpack_from("<H", hdr, pe + 4)[0]
    except (OSError, struct.error):
        return None
    return {0x014C: 32, 0x8664: 64}.get(machine)

def _call_generate_key(dll_path, export_name, seed, level, variant=b""):
    loaders = [ctypes.CDLL]
    if hasattr(ctypes, "WinDLL"):
        loaders.append(ctypes.WinDLL)
    last_exc = None
    for loader in loaders:
        dll = loader(dll_path)
        try:
            fn = getattr(dll, export_name)
        except AttributeError as exc:
            raise RuntimeError(f"DLL export not found: {export_name}") from exc
        fn.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32,
                       ctypes.c_uint32, ctypes.c_char_p,
                       ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32,
                       ctypes.POINTER(ctypes.c_uint32)]
        fn.restype = ctypes.c_int
        seed_arr = (ctypes.c_ubyte * len(seed)).from_buffer_copy(seed)
        key_arr = (ctypes.c_ubyte * 256)()
        key_len = ctypes.c_uint32(0)
        try:
            rc = fn(seed_arr, len(seed), level, variant, key_arr,
                    len(key_arr), ctypes.byref(key_len))
        except ValueError as exc:
            last_exc = exc
            continue
        if rc != 0:
            raise RuntimeError(f"Seed-Key DLL error {rc} ({KEYGEN_RESULT.get(rc, 'unknown')})")
        if key_len.value == 0 or key_len.value > len(key_arr):
            raise RuntimeError(f"Invalid key length {key_len.value}")
        return bytes(key_arr[:key_len.value])
    raise RuntimeError(f"Calling convention mismatch: {last_exc}")

def _seedkey_cli(args):
    try:
        dll, export, level, seed_hex = args
        key = _call_generate_key(dll, export, bytes.fromhex(seed_hex), int(level))
        sys.stdout.write("KEY:" + key.hex() + "\n")
        return 0
    except BaseException as exc:
        sys.stdout.write("ERR:" + f"{type(exc).__name__}: {exc}".replace("\n", " ") + "\n")
        return 2
    finally:
        sys.stdout.flush()

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--seedkey-once":
    sys.exit(_seedkey_cli(sys.argv[2:]))

def _frozen_bridge_path() -> Optional[str]:
    if not getattr(sys, "frozen", False):
        return None
    exe_dir = Path(sys.executable).parent
    cand = exe_dir / "bridge32" / "ECUFlasher32.exe"
    return str(cand) if cand.is_file() else None

def _python_bits(cmd):
    if cmd and cmd[0].lower().endswith("ecuflasher32.exe"):
        return 32
    try:
        out = subprocess.run(cmd + ["-c", "import struct;print(struct.calcsize('P')*8)"],
                             capture_output=True, text=True, timeout=20,
                             creationflags=_NO_WINDOW)
        return int(out.stdout.strip()) if out.returncode == 0 else None
    except Exception:
        return None

def find_python(bits, hint=""):
    if bits == PY_BITS:
        return [sys.executable]
    if bits == 32:
        bridge = _frozen_bridge_path()
        if bridge:
            return [bridge]
    if hint.strip():
        cand = [hint.strip()]
        if _python_bits(cand) == bits:
            return cand
    if os.name == "nt":
        cmd = ["py", f"-3-{bits}"]
        if _python_bits(cmd) == bits:
            return cmd
        patterns = []
        la = os.environ.get("LOCALAPPDATA")
        if la:
            patterns.append(os.path.join(la, "Programs", "Python", "Python3*", "python.exe"))
        for pf in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
            if pf:
                patterns.append(os.path.join(pf, "Python3*", "python.exe"))
        patterns.append("C:\\Python3*\\python.exe")
        for pat in patterns:
            for p in sorted(glob.glob(pat), reverse=True):
                if _python_bits([p]) == bits:
                    return [p]
    return None

class SeedKeyProvider:
    def __init__(self, dll_path, export_name, python_hint, log):
        if not dll_path:
            raise RuntimeError("Seed-Key DLL not selected")
        if not Path(dll_path).is_file():
            raise RuntimeError(f"Seed-Key DLL not found: {dll_path}")
        self.dll_path = os.path.abspath(dll_path)
        self.export = export_name or "GenerateKeyEx"
        self.log = log
        self.dll_bits = pe_bitness(self.dll_path)
        self.cmd = None
        if self.dll_bits is None:
            raise RuntimeError(f"Not a valid Windows DLL: {dll_path}")
        if self.dll_bits == PY_BITS:
            try:
                ctypes.CDLL(self.dll_path)
            except OSError as exc:
                raise RuntimeError(f"Cannot load DLL: {exc}") from exc
            log(f"[DLL] {Path(dll_path).name}: {self.dll_bits}-bit, direct")
        else:
            self.cmd = find_python(self.dll_bits, python_hint)
            if self.cmd is None:
                raise RuntimeError(
                    f"DLL is {self.dll_bits}-bit, Python {PY_BITS}-bit. "
                    f"Need Python {self.dll_bits}-bit or bridge32.")
            log(f"[DLL] {Path(dll_path).name}: {self.dll_bits}-bit, bridge={' '.join(self.cmd)}")

    def _bridge_command(self):
        if self.cmd is None:
            return []
        if self.cmd and self.cmd[0].lower().endswith("ecuflasher32.exe"):
            return self.cmd + ["--seedkey-once"]
        return self.cmd + [os.path.abspath(__file__), "--seedkey-once"]

    def calculate(self, seed, level):
        self.log(f"[SECURITY] level=0x{level:02X}, seed={seed.hex(' ').upper()}")
        if self.cmd is None:
            try:
                key = _call_generate_key(self.dll_path, self.export, seed, level)
            except OSError as exc:
                raise RuntimeError(f"Cannot load DLL: {exc}") from exc
        else:
            argv = self._bridge_command() + [self.dll_path, self.export, str(level), seed.hex()]
            try:
                proc = subprocess.run(argv, capture_output=True, text=True, timeout=30, creationflags=_NO_WINDOW)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Seed-Key bridge timeout") from exc
            line = next((ln.strip() for ln in reversed(proc.stdout.splitlines())
                         if ln.startswith(("KEY:", "ERR:"))), "")
            if line.startswith("KEY:"):
                key = bytes.fromhex(line[4:])
            else:
                detail = line[4:] if line.startswith("ERR:") else (proc.stderr.strip() or "no output")
                raise RuntimeError(f"Seed-Key bridge failed: {detail}")
        if len(key) == 20:
            key = key[:16]
        self.log(f"[SECURITY] key={key.hex(' ').upper()}")
        return key

@dataclass
class MemoryBlock:
    start: int
    data: bytes
    @property
    def end(self):
        return self.start + len(self.data) - 1

@dataclass
class FirmwareImage:
    path: Path
    blocks: list
    @property
    def total_size(self):
        return sum(len(x.data) for x in self.blocks)
    @property
    def start(self):
        return min(x.start for x in self.blocks)
    @property
    def end(self):
        return max(x.end for x in self.blocks)
    @property
    def joined_data(self):
        return b"".join(x.data for x in self.blocks)

class FirmwareParser:
    @staticmethod
    def load(path):
        suffix = Path(path).suffix.lower()
        if suffix in (".hex", ".ihex"):
            blocks = FirmwareParser._parse_intel_hex(path)
        elif suffix in (".s37", ".srec", ".s19", ".mot"):
            blocks = FirmwareParser._parse_srec(path)
        else:
            raise ValueError("Only Intel HEX and Motorola S-record are supported")
        if not blocks:
            raise ValueError("Firmware file contains no data")
        return FirmwareImage(Path(path), FirmwareParser._merge(blocks))

    @staticmethod
    def _merge(records):
        records.sort(key=lambda x: x.start)
        starts, bufs = [], []
        for rec in records:
            if not bufs or rec.start > starts[-1] + len(bufs[-1]):
                starts.append(rec.start)
                bufs.append(bytearray(rec.data))
                continue
            cur_start, cur = starts[-1], bufs[-1]
            cur_end = cur_start + len(cur)
            if rec.start < cur_end:
                overlap = min(cur_end - rec.start, len(rec.data))
                off = rec.start - cur_start
                if bytes(cur[off:off + overlap]) != rec.data[:overlap]:
                    raise ValueError(f"Conflict at 0x{rec.start:08X}")
                cur.extend(rec.data[overlap:])
            else:
                cur.extend(rec.data)
        return [MemoryBlock(s, bytes(b)) for s, b in zip(starts, bufs)]

    @staticmethod
    def _parse_intel_hex(path):
        upper, records = 0, []
        with open(path, "r", encoding="ascii") as f:
            for line_no, raw in enumerate(f, 1):
                line = raw.strip()
                if not line:
                    continue
                if not line.startswith(":"):
                    raise ValueError(f"HEX {line_no}: missing ':'")
                blob = bytes.fromhex(line[1:])
                if len(blob) < 5 or (sum(blob) & 0xFF) != 0:
                    raise ValueError(f"HEX {line_no}: bad checksum")
                count, ah, al, rtype = blob[:4]
                data = blob[4:-1]
                if count != len(data):
                    raise ValueError(f"HEX {line_no}: count mismatch")
                addr16 = (ah << 8) | al
                if rtype == 0x00:
                    records.append(MemoryBlock(upper + addr16, data))
                elif rtype == 0x01:
                    break
                elif rtype == 0x02:
                    upper = int.from_bytes(data, "big") << 4
                elif rtype == 0x04:
                    upper = int.from_bytes(data, "big") << 16
        return records

    @staticmethod
    def _parse_srec(path):
        addr_len = {"1": 2, "2": 3, "3": 4}
        records = []
        with open(path, "r", encoding="ascii") as f:
            for line_no, raw in enumerate(f, 1):
                line = raw.strip().upper()
                if not line:
                    continue
                if len(line) < 4 or line[0] != "S":
                    raise ValueError(f"SREC {line_no}: invalid")
                typ = line[1]
                blob = bytes.fromhex(line[2:])
                if not blob or blob[0] != len(blob) - 1:
                    raise ValueError(f"SREC {line_no}: count")
                if (sum(blob) & 0xFF) != 0xFF:
                    raise ValueError(f"SREC {line_no}: checksum")
                if typ not in addr_len:
                    continue
                n = addr_len[typ]
                address = int.from_bytes(blob[1:1 + n], "big")
                data = blob[1 + n:-1]
                records.append(MemoryBlock(address, data))
        return records

def crc32(data):
    return binascii.crc32(data) & 0xFFFFFFFF

def precise_sleep(seconds):
    if seconds <= 0:
        return
    end = time.perf_counter() + seconds
    if seconds > 0.003:
        time.sleep(seconds - 0.003)
    while time.perf_counter() < end:
        pass

CAN_FD_LENGTHS = (8, 12, 16, 20, 24, 32, 48, 64)

_TX_FULL_MARKERS = ("QUEUE_IS_FULL", "ERROR CODE 11", "QXMTFULL", "TRANSMIT QUEUE", "TX QUEUE")

def _is_tx_queue_full(exc):
    text = str(exc).upper()
    return any(m in text for m in _TX_FULL_MARKERS)

def send_with_retry(bus, msg, should_stop=None, timeout=3.0):
    """
    bus.send() that survives a full adapter TX queue (Vector XL_ERR_QUEUE_IS_FULL,
    PCAN QXMTFULL). It waits with a short exponential backoff until the queue drains.
    If it never drains the bus is not consuming frames (no ACK, wrong bitrate,
    bus-off, ECU unpowered), so a clear error is raised after `timeout` seconds.
    """
    deadline = time.monotonic() + timeout
    delay = 0.0005
    while True:
        try:
            return bus.send(msg)
        except Exception as exc:
            if not _is_tx_queue_full(exc):
                raise
            if should_stop is not None and should_stop():
                raise RuntimeError("Stopped by user") from exc
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"CAN TX queue stayed full for {timeout:.1f}s - the bus is not draining "
                    f"frames. Check ECU power, bitrate/CAN FD settings, termination and that "
                    f"another node ACKs.") from exc
            time.sleep(delay)
            delay = min(delay * 2, 0.01)

class UdsError(RuntimeError):
    pass

class TestcaseCompleted(RuntimeError):
    pass

class UdsClient:
    NRC = {
        0x10: "generalReject", 0x11: "serviceNotSupported",
        0x12: "subFunctionNotSupported", 0x13: "incorrectLength",
        0x21: "busyRepeatRequest", 0x22: "conditionsNotCorrect",
        0x24: "requestSequenceError", 0x31: "requestOutOfRange",
        0x33: "securityAccessDenied", 0x35: "invalidKey",
        0x36: "exceedAttempts", 0x37: "requiredDelay",
        0x70: "uploadDownloadNotAccepted", 0x71: "transferDataSuspended",
        0x72: "generalProgrammingFailure", 0x73: "wrongBlockSequenceCounter",
        0x78: "responsePending", 0x7E: "subFuncNotSupportedInSession",
        0x7F: "serviceNotSupportedInSession",
    }

    def __init__(self, bus, txid, rxid, log, fd=False, brs=False, should_stop=None, pad=0x00):
        if can is None:
            raise RuntimeError("python-can is not installed. Required for UDS communication.")
        self.bus, self.txid, self.rxid, self.log = bus, txid, rxid, log
        self.fd, self.brs = fd, brs and fd
        self.max_dl = 64 if fd else 8
        self.should_stop = should_stop or (lambda: False)
        self.pad = pad
        self.err_count = 0
        self.tx_ok = 0
        self.other_ids = set()

    def _legal_len(self, n):
        if not self.fd:
            return 8
        return next(x for x in CAN_FD_LENGTHS if x >= n)

    def _send_can(self, arbitration_id, data):
        frame = bytes(data).ljust(self._legal_len(len(data)), bytes([self.pad]))
        send_with_retry(self.bus,
                        can.Message(arbitration_id=arbitration_id, data=frame,
                                    is_extended_id=False, is_fd=self.fd,
                                    bitrate_switch=self.brs),
                        should_stop=self.should_stop)

    def _recv_can(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if self.should_stop():
                raise RuntimeError("Stopped by user")
            msg = self.bus.recv(min(0.05, max(0.001, deadline - time.monotonic())))
            if msg is not None:
                if getattr(msg, "is_error_frame", False):
                    self.err_count += 1
                elif getattr(msg, "is_rx", True) is False:
                    self.tx_ok += 1
                elif msg.arbitration_id == self.rxid and not msg.is_extended_id:
                    return bytes(msg.data)
                else:
                    self.other_ids.add(msg.arbitration_id)
            if time.monotonic() >= deadline:
                return None

    def _flush_rx(self):
        end = time.monotonic() + 0.05
        while time.monotonic() < end and self.bus.recv(0) is not None:
            pass

    def functional(self, arbitration_id, payload):
        if len(payload) > 7:
            raise ValueError("Functional request > 7 bytes")
        self.log(f"[TX-F 0x{arbitration_id:03X}] {payload.hex(' ').upper()}")
        self._send_can(arbitration_id, bytes([len(payload)]) + payload)

    @staticmethod
    def _stmin_seconds(st):
        if st <= 0x7F:
            return st / 1000.0
        if 0xF1 <= st <= 0xF9:
            return (st - 0xF0) / 10000.0
        return 0.0

    def _wait_flow_control(self, timeout):
        for _ in range(32):
            fc = self._recv_can(timeout)
            if fc is None:
                raise TimeoutError("No ISO-TP FC")
            pci = fc[0] >> 4
            if pci == 0:
                raise UdsError(f"ECU sent {fc.hex(' ').upper()} instead of FC")
            if pci != 3:
                continue
            status = fc[0] & 0x0F
            if status == 0:
                return fc[1], self._stmin_seconds(fc[2])
            if status == 1:
                continue
            raise UdsError(f"FlowStatus={status}")
        raise TimeoutError("ISO-TP WAIT limit")

    def _send_isotp(self, payload, timeout):
        n = len(payload)
        if n <= 7:
            self._send_can(self.txid, bytes([n]) + payload)
            return
        if self.fd and n <= self.max_dl - 2:
            self._send_can(self.txid, bytes([0x00, n]) + payload)
            return
        if n > 4095:
            raise UdsError("Payload too long")
        first = self.max_dl - 2
        self._send_can(self.txid, bytes([0x10 | ((n >> 8) & 0x0F), n & 0xFF]) + payload[:first])
        bs, delay = self._wait_flow_control(timeout)
        per_cf = self.max_dl - 1
        offset, seq, sent_in_block = first, 1, 0
        while offset < n:
            if self.should_stop():
                raise RuntimeError("Stopped by user")
            chunk = payload[offset:offset + per_cf]
            self._send_can(self.txid, bytes([0x20 | seq]) + chunk)
            offset += len(chunk)
            seq = (seq + 1) & 0x0F
            sent_in_block += 1
            if offset < n:
                if bs and sent_in_block >= bs:
                    bs, delay = self._wait_flow_control(timeout)
                    sent_in_block = 0
                elif delay:
                    precise_sleep(delay)

    def _recv_isotp(self, timeout, cf_timeout=1.0):
        deadline = time.monotonic() + timeout
        while True:
            first = self._recv_can(max(0.0, deadline - time.monotonic()))
            if first is None:
                raise TimeoutError("ISO-TP timeout")
            pci = first[0] >> 4
            if pci in (0, 1):
                break
        if pci == 0:
            n = first[0] & 0x0F
            if n == 0:
                n = first[1]
                return first[2:2 + n]
            return first[1:1 + n]
        length = ((first[0] & 0x0F) << 8) | first[1]
        data = bytearray(first[2:])
        self._send_can(self.txid, b"\x30\x00\x00")
        expected_seq = 1
        while len(data) < length:
            frame = self._recv_can(cf_timeout)
            if frame is None:
                raise TimeoutError("ISO-TP CF timeout")
            if (frame[0] >> 4) != 2 or (frame[0] & 0x0F) != expected_seq:
                raise UdsError("Invalid CF sequence")
            data.extend(frame[1:])
            expected_seq = (expected_seq + 1) & 0x0F
        return bytes(data[:length])

    def request(self, payload, timeout=5.0, busy_retries=0, timeout_retries=0, check=None, verbose=True, pending_timeout=30.0):
        expected = (payload[0] + 0x40) & 0xFF
        busy_left, timeout_left = busy_retries, timeout_retries
        self._flush_rx()
        while True:
            if verbose:
                self.log(f"[TX 0x{self.txid:03X}] {payload.hex(' ').upper()}")
            self._send_isotp(payload, timeout)
            deadline = time.monotonic() + timeout
            resend = False
            try:
                while True:
                    response = self._recv_isotp(max(0.001, deadline - time.monotonic()))
                    if verbose:
                        self.log(f"[RX 0x{self.rxid:03X}] {response.hex(' ').upper()}")
                    if len(response) >= 3 and response[0] == 0x7F:
                        nrc = response[2]
                        if nrc == 0x78:
                            deadline = time.monotonic() + pending_timeout
                            continue
                        if nrc == 0x21 and busy_left > 0:
                            busy_left -= 1
                            self.log("[UDS] Busy, retry in 1s")
                            time.sleep(1.0)
                            resend = True
                            break
                        raise UdsError(f"NRC 0x{nrc:02X} ({self.NRC.get(nrc, '?')}) for SID 0x{response[1]:02X}")
                    if not response or response[0] != expected or (check and not check(response)):
                        self.log(f"[WARN] Ignored: {response[:8].hex(' ').upper()}")
                        continue
                    return response
            except TimeoutError:
                if timeout_left <= 0:
                    raise TimeoutError(f"Timeout SID 0x{payload[0]:02X}")
                timeout_left -= 1
                self.log(f"[UDS] Timeout, resend ({timeout_retries - timeout_left}/{timeout_retries})")
                resend = True
            if not resend:
                break
        raise TimeoutError(f"Request failed SID 0x{payload[0]:02X}")

    def request_expect_nrc(self, payload, expected_nrc, timeout=5.0):
        self._flush_rx()
        self.log(f"[TX 0x{self.txid:03X}] {payload.hex(' ').upper()}")
        self._send_isotp(payload, timeout)
        response = self._recv_isotp(timeout)
        self.log(f"[RX 0x{self.rxid:03X}] {response.hex(' ').upper()}")
        if len(response) < 3 or response[:2] != bytes([0x7F, payload[0]]) or response[2] != expected_nrc:
            raise UdsError(f"Expected 7F {payload[0]:02X} {expected_nrc:02X}, got {response.hex(' ').upper()}")
        return response

    def request_allow_timeout(self, payload, timeout=2.0):
        self._flush_rx()
        self.log(f"[TX 0x{self.txid:03X}] {payload.hex(' ').upper()}")
        self._send_isotp(payload, timeout)
        try:
            response = self._recv_isotp(timeout)
        except TimeoutError:
            self.log(f"[TESTCASE] No response (allowed)")
            return None
        self.log(f"[RX 0x{self.rxid:03X}] {response.hex(' ').upper()}")
        return response

    def idle(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self.should_stop():
                raise RuntimeError("Stopped by user")
            time.sleep(0.05)

class DidDecoder:
    ASCII_DIDS = {0xF194}
    MIXED_PART_NUMBER_DIDS = {0xF188, 0xF191, 0xF103}

    @staticmethod
    def _decode_mixed(data):
        cleaned = data.rstrip(b"\x00\xFF ")
        if len(cleaned) != 9:
            return None
        prefix, bcd, suffix = cleaned[:3], cleaned[3:7], cleaned[7:]
        try:
            pt = prefix.decode("ascii")
            st = suffix.decode("ascii")
        except UnicodeDecodeError:
            return None
        if not all(32 <= ord(c) <= 126 for c in pt + st):
            return None
        digits = []
        for b in bcd:
            h, l = b >> 4, b & 0x0F
            if h > 9 or l > 9:
                return None
            digits.append(f"{h}{l}")
        return pt + "".join(digits) + st

    @classmethod
    def decode(cls, did, data):
        raw = data.hex(" ").upper()
        cleaned = data.rstrip(b"\x00\xFF ")
        if did in cls.MIXED_PART_NUMBER_DIDS:
            t = cls._decode_mixed(data)
            if t is not None:
                return t, raw
            return (f"Mixed decode error | RAW: {raw}" if raw else "<empty>"), raw
        if did in cls.ASCII_DIDS:
            try:
                t = cleaned.decode("ascii")
            except UnicodeDecodeError:
                return (f"ASCII error | RAW: {raw}" if raw else "<empty>"), raw
            if t and all(32 <= ord(c) <= 126 for c in t):
                return t, raw
            return (f"ASCII error | RAW: {raw}" if raw else "<empty>"), raw
        try:
            t = cleaned.decode("ascii")
            if t and all(32 <= ord(c) <= 126 for c in t):
                return t, raw
        except UnicodeDecodeError:
            pass
        return raw or "<empty>", raw

@dataclass
class FlashCallbacks:
    log: Callable
    progress: Callable
    should_stop: Callable

class _RestoreState:
    dtc_off = False
    comm_off = False
    hv_off = False

class FlashRunner:
    PRECONDITION_DELAY_SECONDS = 0.5

    def __init__(self, cfg, images, bus, callbacks):
        self.cfg, self.images, self.bus = cfg, images, bus
        self.cb = callbacks
        self._total = max(1, sum(img.total_size for _, img in images))
        self._done = 0

    def _log(self, text):
        self.cb.log(text)

    def _check_stop(self):
        if self.cb.should_stop():
            raise RuntimeError("Stopped by user")

    def _make_key_fn(self):
        override = self.cfg.get("_key_fn")
        if override:
            return override
        provider = SeedKeyProvider(self.cfg.get("key_dll", "").strip(),
                                   self.cfg.get("dll_export", "").strip(),
                                   self.cfg.get("python_hint", ""), self._log)
        return provider.calculate

    def run(self):
        try:
            self._run()
            return True, "Flashing completed successfully"
        except TestcaseCompleted as e:
            self._log(f"[TESTCASE PASS] {e}")
            return True, str(e)
        except Exception as e:
            self._log(f"[ERROR] {e}")
            return False, str(e)

    def _run(self):
        c = self.cfg
        if self.bus is None:
            raise RuntimeError("CAN not connected")
        uds = UdsClient(self.bus, c["txid"], c["rxid"], self._log,
                        fd=c.get("fd", False), brs=c.get("brs", False),
                        should_stop=self.cb.should_stop)
        tc = c.get("testcase_id")
        if not tc:
            self._run_flash_core(uds)
            return
        self._log(f"[TESTCASE {tc}] START")
        self._read_snapshot(uds, "BEFORE FLASH")
        terminal = None
        try:
            self._run_flash_core(uds)
            terminal = TestcaseCompleted(f"{tc} completed without expected negative")
        except TestcaseCompleted as exc:
            terminal = exc
        except Exception as exc:
            terminal = exc
        self._log(f"[TESTCASE {tc}] Wait {c.get('testcase_recovery_delay', 3.0):.1f}s")
        uds.idle(float(c.get("testcase_recovery_delay", 3.0)))
        self._read_snapshot(uds, "AFTER FLASH FAIL", retries=5)
        raise terminal

    def _read_snapshot(self, uds, label, retries=1):
        self._log(f"[TESTCASE][DID][{label}] Reading F101, F195, DB11")
        for did, name in ((0xF101, "F101"), (0xF195, "F195"), (0xDB11, "DB11")):
            last_exc = None
            for attempt in range(1, retries + 1):
                try:
                    rsp = uds.request(b"\x22" + did.to_bytes(2, "big"), timeout=3.0)
                    value = rsp[3:] if len(rsp) >= 3 and rsp[1:3] == did.to_bytes(2, "big") else rsp[1:]
                    self._log(f"[TESTCASE][DID][{label}] 0x{name} = {value.hex(' ').upper()}")
                    break
                except Exception as exc:
                    last_exc = exc
                    self._log(f"[TESTCASE][DID][{label}] 0x{name} attempt {attempt}/{retries}: {exc}")
                    if attempt < retries:
                        uds.idle(1.0)
            else:
                self._log(f"[TESTCASE][DID][{label}] 0x{name} NOT READ: {last_exc}")

    def _run_flash_core(self, uds):
        c = self.cfg
        key_fn = self._make_key_fn()
        names = [n for n, _ in self.images]
        has_driver = "Driver" in names
        st = _RestoreState()
        self._log("[FLASH] Sequence: " + " -> ".join(names))
        try:
            if has_driver:
                self._enter_programming(uds, key_fn, st)
                for i, (name, image) in enumerate(self.images):
                    self._flash_image(uds, name, image)
                    if i + 1 < len(self.images):
                        self._log("[FLASH] Wait 2s")
                        uds.idle(2.0)
                self._check_deps_reset(uds)
                self._restore_normal(uds, st)
            else:
                for i, (name, image) in enumerate(self.images):
                    self._enter_programming(uds, key_fn, st)
                    self._flash_image(uds, name, image)
                    self._check_deps_reset(uds)
                    if i + 1 < len(self.images):
                        self._log("[FLASH] Wait 2s")
                        uds.idle(2.0)
                self._restore_normal(uds, st)
        except TestcaseCompleted:
            raise
        except BaseException:
            self._restore_after_failure(uds, st)
            raise

    def _enter_programming(self, uds, key_fn, st):
        c = self.cfg
        fid = c["functional_id"]
        level = c["security_level"]
        self._log("[UDS] Default Session 10 01")
        rsp = uds.request(b"\x10\x01", timeout=3.0, check=lambda r: len(r) >= 2 and r[1] == 0x01)
        if rsp[1] != 0x01:
            raise UdsError(f"10 01 failed: {rsp.hex(' ').upper()}")
        uds.idle(0.10)
        self._log("[UDS] Extended Session 10 03")
        rsp = uds.request(b"\x10\x03", timeout=3.0, check=lambda r: len(r) >= 2 and r[1] == 0x03)
        if rsp[1] != 0x03:
            raise UdsError(f"10 03 failed: {rsp.hex(' ').upper()}")
        time.sleep(0.05)
        if c.get("turn_off_hv"):
            hv_level = 0x01
            rsp = uds.request(bytes([0x27, hv_level]))
            if len(rsp) < 3 or rsp[1] != hv_level:
                raise UdsError("Invalid HV seed")
            hv_key = key_fn(rsp[2:], hv_level)
            uds.request(bytes([0x27, hv_level + 1]) + hv_key)
            self._log("[SECURITY] HV level 0x01 unlocked")
            uds.request(b"\x31\x01\xF0\x00")
            st.hv_off = True
        uds.request(b"\x22\xF1\x91")
        self._log(f"[UDS] Wait {self.PRECONDITION_DELAY_SECONDS}s before 31 01 02 03")
        uds.idle(self.PRECONDITION_DELAY_SECONDS)
        uds.request(b"\x31\x01\x02\x03")
        pe = c.get("simulation_pause_event")
        if pe is not None:
            pe.set()
        self._log("[DBC] Pause simulation")
        uds.functional(fid, b"\x85\x82")
        st.dtc_off = True
        time.sleep(0.05)
        uds.functional(fid, b"\x28\x81\x03")
        st.comm_off = True
        time.sleep(0.05)
        uds.request(b"\x10\x02")
        self._log(f"[SECURITY] Request seed level 0x{level:02X}")
        seed_rsp = uds.request(bytes([0x27, level]))
        if len(seed_rsp) < 3 or seed_rsp[1] != level:
            raise UdsError("Invalid seed")
        key = key_fn(seed_rsp[2:], level)
        uds.request(bytes([0x27, (level + 1) & 0x7F]) + key)
        self._log(f"[SECURITY] Level 0x{level:02X} unlocked")
        import datetime as _dt
        d = _dt.datetime.now()
        bcd = lambda v: int(str(v), 16)
        fp = bytearray(b"\x2E\xF1\x07\x00\x00\x00" + b" " * 8 + b"T&V0000000123456666")
        fp[3:6] = bytes([bcd(d.year - 2000), bcd(d.month), bcd(d.day)])
        uds.request(bytes(fp))

    def _flash_image(self, uds, name, image):
        c = self.cfg
        tc = c.get("testcase_id")
        self._check_stop()
        self._log(f"[FLASH] {name}: 0x{image.start:08X}-0x{image.end:08X}, {image.total_size}B")
        if name != "Driver":
            erase = (b"\x31\x01\xFF\x00\x44" + image.start.to_bytes(4, "big")
                     + image.total_size.to_bytes(4, "big"))
            uds.request(erase, timeout=30.0)
        for block_index, block in enumerate(image.blocks):
            self._check_stop()
            req = self._build_req_download(block, tc)
            if tc in ("Cyber_SecureUpdate_48", "Cyber_SecureUpdate_49"):
                uds.request_expect_nrc(req, 0x70, timeout=5.0)
                raise TestcaseCompleted(f"{tc} passed: NRC 0x70")
            if tc in ("Cyber_SecureUpdate_45", "Cyber_SecureUpdate_46", "Cyber_SecureUpdate_47"):
                nr = {"Cyber_SecureUpdate_45": 0x71, "Cyber_SecureUpdate_46": 0x70,
                      "Cyber_SecureUpdate_47": 0x31}[tc]
                uds.request_expect_nrc(req, nr, timeout=5.0)
                raise TestcaseCompleted(f"{tc} passed: NRC 0x{nr:02X}")
            if tc == "Cyber_SecureUpdate_51":
                self._log(f"[TC {tc}] RequestDownload + inject 11 01")
                uds._flush_rx()
                uds._send_isotp(req, 2.0)
                precise_sleep(0.01)
                uds._send_isotp(b"\x11\x01", 2.0)
                try:
                    r = uds._recv_isotp(2.0)
                    self._log(f"[TC {tc}] Response: {r.hex(' ').upper()}")
                except TimeoutError:
                    self._log(f"[TC {tc}] No response")
                raise TestcaseCompleted(f"{tc} completed: reset during RequestDownload")
            rsp = uds.request(req)
            n = (rsp[1] >> 4) & 0x0F
            if n:
                max_len = int.from_bytes(rsp[2:2 + n], "big")
                if max_len <= 2:
                    raise UdsError(f"Invalid MaxBlockLength {max_len}")
            else:
                max_len = c["block_size"] + 2
            chunk_size = max(1, min(c["block_size"], max_len - 2))
            self._log(f"[UDS] MaxBlockLength={max_len}, TransferBlockSize={chunk_size}")
            tr_timeout = 2.0 if chunk_size > 62 else 0.2
            counter, offset = 1, 0
            final_transfer = None
            while offset < len(block.data):
                self._check_stop()
                chunk = block.data[offset:offset + chunk_size]
                cnt = counter
                transfer = bytes([0x36, cnt]) + chunk
                self._inject_negative(uds, tc, cnt, chunk, offset, chunk_size)
                uds.request(transfer, timeout=tr_timeout, busy_retries=5, timeout_retries=5,
                            check=lambda r, cc=cnt: len(r) >= 2 and r[1] == cc, verbose=False)
                final_transfer = transfer
                offset += len(chunk)
                self._done += len(chunk)
                self.cb.progress(name, min(100, int(self._done * 100 / self._total)))
                counter = (counter + 1) & 0xFF
            if tc == "Cyber_SecureUpdate_52" and block_index == len(image.blocks) - 1:
                self._log(f"[TC {tc}] 11 01 before 37")
                uds.request_allow_timeout(b"\x11\x01", timeout=2.0)
                raise TestcaseCompleted(f"{tc} completed: reset before 37")
            uds.request(b"\x37")
            if tc == "Cyber_SecureUpdate_41" and block_index == len(image.blocks) - 1:
                if final_transfer is None:
                    raise UdsError("TC41: no final")
                self._log(f"[TC {tc}] Resend 36 after 37")
                uds.request_expect_nrc(final_transfer, 0x24, timeout=5.0)
                raise TestcaseCompleted(f"{tc} passed: 7F 36 24")
            if tc == "Cyber_SecureUpdate_50" and block_index == len(image.blocks) - 1:
                self._log(f"[TC {tc}] 37 second time")
                uds.request_expect_nrc(b"\x37", 0x24, timeout=5.0)
                raise TestcaseCompleted(f"{tc} passed: 7F 37 24")
            if tc == "Cyber_SecureUpdate_53" and block_index == len(image.blocks) - 1:
                self._log(f"[TC {tc}] 11 01 after 37")
                uds.request_allow_timeout(b"\x11\x01", timeout=2.0)
                raise TestcaseCompleted(f"{tc} completed: reset after 37")
        correct_crc = crc32(image.joined_data)
        self._log(f"[CRC] {name}: CRC32=0x{correct_crc:08X}")
        req = b"\x31\x01\x02\x02" + correct_crc.to_bytes(4, "big")
        rsp = uds.request(req, timeout=30.0)
        if len(rsp) < 5 or rsp[1:4] != b"\x01\x02\x02" or rsp[4] != 0:
            raise UdsError(f"CheckMemory failed {name}: {rsp.hex(' ').upper()}")
        self._log(f"[FLASH] {name} completed")

    def _build_req_download(self, block, tc):
        req_addr = block.start
        req_size = len(block.data)
        if tc == "Cyber_SecureUpdate_45":
            req_size = max(1, len(block.data) - 1)
            self._log(f"[TC {tc}] Smaller size {req_size}")
        elif tc == "Cyber_SecureUpdate_46":
            req_addr = 0xFFFFFFFF
            self._log(f"[TC {tc}] Invalid addr 0xFFFFFFFF")
        elif tc == "Cyber_SecureUpdate_47":
            req_size = min(0xFFFFFFFF, len(block.data) + 0x01000000)
            self._log(f"[TC {tc}] Oversized {req_size}")
        elif tc == "Cyber_SecureUpdate_48":
            return b"\x34\x00\x45" + block.start.to_bytes(4, "big") + len(block.data).to_bytes(5, "big")
        elif tc == "Cyber_SecureUpdate_49":
            return b"\x34\xFF\x44" + block.start.to_bytes(4, "big") + len(block.data).to_bytes(4, "big")
        return b"\x34\x00\x44" + req_addr.to_bytes(4, "big") + req_size.to_bytes(4, "big")

    def _inject_negative(self, uds, tc, cnt, chunk, offset, chunk_size):
        if offset < chunk_size:
            return
        if tc == "Cyber_SecureUpdate_42":
            bad = bytes([0x36, (cnt + 1) & 0xFF]) + chunk
            self._log(f"[TC {tc}] Out-of-order BSC")
            uds.request_expect_nrc(bad, 0x73, timeout=5.0)
            raise TestcaseCompleted(f"{tc} passed: 7F 36 73")
        if tc == "Cyber_SecureUpdate_43":
            bad = bytes([0x36, (cnt - 1) & 0xFF]) + chunk
            self._log(f"[TC {tc}] Repeated BSC")
            uds.request_expect_nrc(bad, 0x73, timeout=5.0)
            raise TestcaseCompleted(f"{tc} passed: 7F 36 73")
        if tc == "Cyber_SecureUpdate_44":
            bad = bytes([0x36, cnt]) + chunk + b"\x00"
            self._log(f"[TC {tc}] Wrong block size")
            uds.request_expect_nrc(bad, 0x73, timeout=5.0)
            raise TestcaseCompleted(f"{tc} passed: rejected")

    def _check_deps_reset(self, uds):
        rsp = uds.request(b"\x31\x01\xFF\x01")
        if len(rsp) < 5 or rsp[4] != 0:
            raise UdsError("CheckDependencies failed")
        if not self.cfg["bypass_reset"]:
            uds.request(b"\x11\x01", timeout=10.0)

    def _restore_normal(self, uds, st):
        fid = self.cfg["functional_id"]
        uds.functional(fid, b"\x28\x80\x03")
        st.comm_off = False
        time.sleep(0.05)
        if self.cfg.get("turn_off_hv"):
            uds.request(b"\x31\x01\xF0\x00")
            st.hv_off = False
        uds.functional(fid, b"\x85\x81")
        st.dtc_off = False
        time.sleep(0.05)
        uds.functional(fid, b"\x10\x81")

    def _restore_after_failure(self, uds, st):
        fid = self.cfg["functional_id"]
        steps = []
        if st.comm_off:
            steps.append(b"\x28\x80\x03")
        if st.dtc_off:
            steps.append(b"\x85\x81")
        if st.comm_off or st.dtc_off:
            steps.append(b"\x10\x81")
        for p in steps:
            try:
                uds.functional(fid, p)
                time.sleep(0.05)
            except Exception as exc:
                self._log(f"[WARN] Restore failed: {exc}")
        if st.hv_off:
            self._log("[WARN] HV still OFF")
