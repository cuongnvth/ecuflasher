"""
create_project.py — Tạo project ECUFlasher hoàn chỉnh.
- Ẩn Security level & Block size, giữ giá trị mặc định ngầm.
- Cửa sổ cố định kích thước (không cho resize/maximize).
- Tự động tăng version mỗi lần build + hiển thị trên app.
- Hỗ trợ flash lặp nhiều lần + delay giữa các lần.
"""
from __future__ import annotations
import base64
import os
import sys
from pathlib import Path

ROOT = Path.cwd() / "ecu_flasher"
FILES: dict[str, str] = {}

# ============================================================
# 1. uds_core.py
# ============================================================
FILES["uds_core.py"] = r'''"""
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
'''

# ============================================================
# 2. ecu_flasher_app.py
# ============================================================
FILES["ecu_flasher_app.py"] = r'''"""
ecu_flasher_app.py — GUI PySide6
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import threading
import time
from collections import deque
from pathlib import Path

import can
try:
    import cantools
except ImportError:
    cantools = None

from PySide6.QtCore import (
    QObject, QThread, Signal, QTimer, Qt, QAbstractTableModel, QModelIndex,
)
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QGridLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QDialog, QPlainTextEdit,
    QProgressBar, QPushButton, QSpinBox, QVBoxLayout, QWidget, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QScrollArea, QSizePolicy,
    QSplitter, QFrame, QTableView, QTreeWidget, QTreeWidgetItem, QStyle,
    QFormLayout, QAbstractItemView,
)

from uds_core import (
    SeedKeyProvider, FirmwareParser, UdsClient, UdsError, DidDecoder,
    FlashRunner, FlashCallbacks, pe_bitness, find_python, PY_BITS, send_with_retry,
)

from app_version import APP_NAME, VERSION
try:
    from _build_info import BUILD_INFO      # generated by build_version.py at build time
except ImportError:
    BUILD_INFO = {}

def _active_build():
    """Build metadata, or {} when running from source / when it belongs to another version."""
    return BUILD_INFO if BUILD_INFO.get("version") == VERSION else {}

def version_text():
    """'v1.2.0 (build 15)' for a release build, 'v1.2.0 (dev)' when run from source."""
    info = _active_build()
    return f"v{VERSION} (build {info['build']})" if info.get("build") else f"v{VERSION} (dev)"

def version_details():
    info = _active_build()
    lines = [f"{APP_NAME} {version_text()}"]
    if info.get("date"):
        lines.append(f"Built: {info['date']}")
    if info.get("commit"):
        lines.append(f"Commit: {info['commit']}" + (" (uncommitted changes)" if info.get("dirty") else ""))
    return "\n".join(lines)

def _app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent

def _resource_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent

DARK_QSS = """
* { font-family: 'Segoe UI', Arial; font-size: 10pt; }
QMainWindow, QDialog { background: #1e1e28; }
QWidget { background: #1e1e28; color: #e6e6e6; }
QTabWidget::pane { border: 1px solid #2c2c38; background: #22222e; border-radius: 6px; }
QTabBar::tab { background: #2a2a36; color: #b0b0c0; padding: 8px 18px; margin-right: 2px;
               border-top-left-radius: 6px; border-top-right-radius: 6px; }
QTabBar::tab:selected { background: #0e639c; color: #ffffff; font-weight: 600; }
QTabBar::tab:hover:!selected { background: #34344a; }
QGroupBox { border: 1px solid #2c2c38; border-radius: 8px; margin-top: 12px;
            padding: 15px 10px 10px 10px; font-weight: 600; color: #b0b0c0; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #58a6ff; }
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTreeWidget {
    background: #2a2a36; border: 1px solid #38384a; border-radius: 5px;
    padding: 4px 8px; selection-background-color: #0e639c; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #58a6ff; }
QLineEdit:read-only { background: #232330; color: #a0a0b0; }
QPushButton { background: #2d2d3e; border: 1px solid #3a3a4e; border-radius: 5px;
              padding: 6px 14px; color: #e6e6e6; }
QPushButton:hover { background: #3a3a4e; border-color: #58a6ff; }
QPushButton:pressed { background: #0e639c; }
QPushButton:disabled { background: #26262f; color: #6a6a7a; border-color: #2c2c38; }
QPushButton[accent="true"] { background: #0e639c; border-color: #0e639c; font-weight: 600; }
QPushButton[accent="true"]:hover { background: #1177c2; }
QPushButton[accent="true"]:disabled { background: #1e4d6b; color: #7a8a9a; }
QPushButton[danger="true"] { background: #a83a3a; border-color: #a83a3a; font-weight: 600; }
QPushButton[danger="true"]:hover { background: #c44a4a; }
QPushButton[danger="true"]:disabled { background: #5a2a2a; color: #8a6a6a; }
QHeaderView::section { background: #2a2a36; color: #b0b0c0; padding: 5px; border: none;
                       border-right: 1px solid #38384a; border-bottom: 1px solid #38384a; }
QTreeWidget { gridline-color: #2c2c38; alternate-background-color: #26262f; }
QTreeWidget::item:selected { background: #0e639c; }
QTableView, QTableWidget { background: #1a1a24; alternate-background-color: #22222e;
    border: 1px solid #2c2c38; border-radius: 6px; gridline-color: #2c2c38;
    selection-background-color: #0e639c; selection-color: #ffffff; }
QProgressBar { background: #2a2a36; border: 1px solid #38384a; border-radius: 6px;
               text-align: center; height: 22px; color: #e6e6e6; }
QProgressBar::chunk { background: #0e639c; border-radius: 5px; }
QScrollBar:vertical { background: #1e1e28; width: 12px; border: none; }
QScrollBar::handle:vertical { background: #38384a; border-radius: 6px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #4a4a5e; }
QScrollBar:horizontal { background: #1e1e28; height: 12px; border: none; }
QScrollBar::handle:horizontal { background: #38384a; border-radius: 6px; min-width: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { background: none; border: none; }
QLabel[role="ok"] { color: #3fb950; font-weight: 600; }
QLabel[role="warn"] { color: #d29922; font-weight: 600; }
QLabel[role="err"] { color: #f85149; font-weight: 600; }
QLabel[role="info"] { color: #58a6ff; font-weight: 600; }
"""

# ============================================================
# CAN TRACE — hàng đợi nhẹ + chèn theo lô + giải mã DBC lazy
# ============================================================
def _fmt_value(v):
    if hasattr(v, "name"):
        return f"{v}"
    if isinstance(v, float):
        return f"{v:.6g}"
    return str(v)

class TraceRow:
    __slots__ = ("ts", "direction", "arb_id", "name", "msg_def", "is_fd", "raw",
                 "channel", "flags", "ts_text", "data_hex", "signals")

    def __init__(self, ts, direction, arb_id, name, msg_def, is_fd, raw, channel, flags):
        self.ts = ts
        self.direction = direction
        self.arb_id = arb_id
        self.name = name
        self.msg_def = msg_def
        self.is_fd = is_fd
        self.raw = raw
        self.channel = channel
        self.flags = flags
        self.ts_text = None
        self.data_hex = None
        self.signals = None

class TraceBridge:
    def __init__(self, maxlen=20000):
        self.queue = deque(maxlen=maxlen)
        self.enabled = True

    def push(self, msg, direction):
        if not self.enabled:
            return
        flags = []
        if getattr(msg, "bitrate_switch", False):
            flags.append("BRS")
        if getattr(msg, "is_error_frame", False):
            flags.append("ERR")
        self.queue.append((
            getattr(msg, "timestamp", 0.0) or time.time(),
            direction,
            int(msg.arbitration_id),
            bool(getattr(msg, "is_fd", False)),
            bytes(msg.data),
            str(getattr(msg, "channel", "")),
            ",".join(flags),
        ))

class TraceTableModel(QAbstractTableModel):
    HEADERS = ["Time", "Dir", "CAN ID", "Name", "Format", "DLC", "Data", "Signals", "Ch", "Flags"]

    def __init__(self, max_rows=8000, parent=None):
        super().__init__(parent)
        self.max_rows = max_rows
        self._rows = []
        self._fg_tx = QColor("#58a6ff")
        self._fg_rx = QColor("#3fb950")
        self._mono = QFont("Consolas")
        self._mono.setPointSize(9)

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        return self.HEADERS[section] if orientation == Qt.Orientation.Horizontal else section + 1

    @staticmethod
    def _decode_signals(row):
        if row.msg_def is None:
            return ""
        try:
            phys = row.msg_def.decode(row.raw, decode_choices=True, scaling=True, allow_truncated=True)
            return "; ".join(f"{k}={_fmt_value(v)}" for k, v in phys.items())
        except Exception as e:
            return f"DBC err: {e}"

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            row = self._rows[index.row()]
            c = index.column()
            if c == 0:
                if row.ts_text is None:
                    try:
                        row.ts_text = dt.datetime.fromtimestamp(row.ts).strftime("%H:%M:%S.%f")[:-3]
                    except Exception:
                        row.ts_text = ""
                return row.ts_text
            if c == 1: return row.direction
            if c == 2: return f"0x{row.arb_id:X}"
            if c == 3: return row.name
            if c == 4: return "FD" if row.is_fd else "Classic"
            if c == 5: return len(row.raw)
            if c == 6:
                if row.data_hex is None:
                    row.data_hex = row.raw.hex(" ").upper()
                return row.data_hex
            if c == 7:
                if row.signals is None:
                    row.signals = self._decode_signals(row)
                return row.signals
            if c == 8: return row.channel
            if c == 9: return row.flags
            return None
        if role == Qt.ItemDataRole.ForegroundRole:
            return self._fg_tx if self._rows[index.row()].direction == "TX" else self._fg_rx
        if role == Qt.ItemDataRole.FontRole and index.column() == 6:
            return self._mono
        return None

    def add_rows(self, rows):
        if not rows:
            return
        if len(rows) > self.max_rows:
            rows = rows[-self.max_rows:]
        overflow = len(self._rows) + len(rows) - self.max_rows
        if overflow > 0:
            cut = min(len(self._rows), overflow + self.max_rows // 8)
            if cut > 0:
                self.beginRemoveRows(QModelIndex(), 0, cut - 1)
                del self._rows[:cut]
                self.endRemoveRows()
        first = len(self._rows)
        self.beginInsertRows(QModelIndex(), first, first + len(rows) - 1)
        self._rows.extend(rows)
        self.endInsertRows()

    def clear_rows(self):
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

class TraceBus:
    def __init__(self, bus, bridge):
        object.__setattr__(self, "_bus", bus)
        object.__setattr__(self, "_bridge", bridge)

    def send(self, msg, *args, **kwargs):
        result = self._bus.send(msg, *args, **kwargs)
        data = msg.data
        if not (data and (data[0] >> 4) == 0x2):
            self._bridge.push(msg, "TX")
        return result

    def recv(self, timeout=None):
        msg = self._bus.recv(timeout)
        if msg is not None and getattr(msg, "is_rx", True):
            data = msg.data
            if not (data and (data[0] >> 4) == 0x2):
                self._bridge.push(msg, "RX")
        return msg

    def __getattr__(self, name):
        return getattr(self._bus, name)

    def __setattr__(self, name, value):
        if name in {"_bus", "_bridge"}:
            object.__setattr__(self, name, value)
        else:
            setattr(self._bus, name, value)

    def shutdown(self):
        return self._bus.shutdown()

class TraceWindow(QDialog):
    FLUSH_MS = 100
    MAX_PER_FLUSH = 1000

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.bridge = owner.trace_bridge
        self.setWindowTitle("CAN Trace")
        self.resize(1400, 700)
        self.setStyleSheet(DARK_QSS)
        self.paused = False
        self._count = 0
        self._suspended = False
        self._last_status = ""
        self._msg_cache = {}
        self._cache_db = None

        v = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.pause_btn = QPushButton("PAUSE")
        self.clear_btn = QPushButton("CLEAR")
        self.autoscroll = QCheckBox("Auto scroll")
        self.autoscroll.setChecked(True)
        self.status = QLabel("0 frames")
        bar.addWidget(self.pause_btn)
        bar.addWidget(self.clear_btn)
        bar.addWidget(self.autoscroll)
        bar.addStretch(1)
        bar.addWidget(self.status)
        v.addLayout(bar)

        self.model = TraceTableModel()
        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.view.setAlternatingRowColors(True)
        self.view.setShowGrid(False)
        self.view.setWordWrap(False)
        self.view.setTextElideMode(Qt.TextElideMode.ElideRight)

        vh = self.view.verticalHeader()
        vh.setVisible(False)
        vh.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        vh.setDefaultSectionSize(22)

        hh = self.view.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setStretchLastSection(False)
        for col, width in enumerate((100, 42, 80, 170, 62, 44, 430, 0, 50, 70)):
            if width:
                self.view.setColumnWidth(col, width)
        hh.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        v.addWidget(self.view, 1)

        self.pause_btn.clicked.connect(self._toggle_pause)
        self.clear_btn.clicked.connect(self.clear)

        self.flush_timer = QTimer(self)
        self.flush_timer.setInterval(self.FLUSH_MS)
        self.flush_timer.timeout.connect(self._flush)

    def showEvent(self, event):
        super().showEvent(event)
        self.flush_timer.start()

    def hideEvent(self, event):
        self.flush_timer.stop()
        super().hideEvent(event)

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.owner._update_trace_btn()

    def _toggle_pause(self):
        self.paused = not self.paused
        self.pause_btn.setText("RESUME" if self.paused else "PAUSE")
        self._update_status()

    def clear(self):
        self.model.clear_rows()
        self.bridge.queue.clear()
        self._count = 0
        self.paused = False
        self.pause_btn.setText("PAUSE")
        self._set_status("0 frames")

    def suspend(self):
        self._suspended = True
        self.bridge.enabled = False
        self.bridge.queue.clear()
        self._set_status("SUSPENDED")

    def resume(self):
        self._suspended = False
        self.bridge.queue.clear()
        self.bridge.enabled = True
        self._update_status()

    def _resolve(self, arb_id):
        db = self.owner.dbc_database
        if db is not self._cache_db:
            self._cache_db = db
            self._msg_cache.clear()
        try:
            return self._msg_cache[arb_id]
        except KeyError:
            pass
        msg_def = None
        if db is not None:
            try:
                msg_def = db.get_message_by_frame_id(arb_id)
            except Exception:
                msg_def = None
        self._msg_cache[arb_id] = msg_def
        return msg_def

    def _flush(self):
        if self.paused or self._suspended:
            self._update_status()
            return
        q = self.bridge.queue
        if not q:
            return
        rows = []
        for _ in range(min(len(q), self.MAX_PER_FLUSH)):
            try:
                ts, direction, arb_id, is_fd, raw, channel, flags = q.popleft()
            except IndexError:
                break
            m = self._resolve(arb_id)
            rows.append(TraceRow(ts, direction, arb_id, m.name if m is not None else "",
                                 m, is_fd, raw, channel, flags))
        self.model.add_rows(rows)
        self._count += len(rows)
        if self.autoscroll.isChecked():
            self.view.scrollToBottom()
        self._update_status()

    def _set_status(self, text):
        if text != self._last_status:
            self._last_status = text
            self.status.setText(text)

    def _update_status(self):
        if self._suspended:
            self._set_status("SUSPENDED")
            return
        pending = len(self.bridge.queue)
        state = "PAUSED" if self.paused else "LIVE"
        extra = f" | queued {pending}" if pending else ""
        self._set_status(f"{self._count} frames | {state}{extra}")

# ============================================================
# READ DID
# ============================================================
DID_ITEMS = [
    (0xF188, "SW P/N", True), (0xF148, "SW P/N rev", False),
    (0xF191, "HW P/N", True), (0xF141, "HW P/N rev", False),
    (0xF103, "Purchase P/N", True), (0xF143, "Purchase P/N rev", False),
    (0xF194, "Build Date", False), (0xF101, "Boot Version", True),
    (0xF195, "App Version", True), (0xDB11, "Active Bank", True),
]

class DidWorker(QObject):
    result = Signal(int, bool, str, str)
    finished = Signal()

    def __init__(self, bus, txid, rxid, fd, dids):
        super().__init__()
        self.bus, self.txid, self.rxid, self.fd = bus, txid, rxid, fd
        self.dids = list(dids)

    def run(self):
        uds = UdsClient(self.bus, self.txid, self.rxid, lambda _: None, fd=self.fd)
        try:
            for did in self.dids:
                try:
                    rsp = uds.request(b"\x22" + did.to_bytes(2, "big"), timeout=3.0)
                    if len(rsp) < 3 or rsp[0] != 0x62 or int.from_bytes(rsp[1:3], "big") != did:
                        raise UdsError(f"Unexpected: {rsp.hex(' ').upper()}")
                    value, raw = DidDecoder.decode(did, rsp[3:])
                    self.result.emit(did, True, value, raw)
                except Exception as e:
                    self.result.emit(did, False, str(e), "")
                time.sleep(0.05)
        finally:
            self.finished.emit()

class DidPanel(QDialog):
    COL_DID, COL_NAME, COL_VALUE, COL_RAW = range(4)
    C_MUTED = QColor("#6a6a7a")
    C_OK = QColor("#3fb950")
    C_ERR = QColor("#f85149")
    C_ACCENT = QColor("#58a6ff")
    C_TEXT = QColor("#e6e6e6")

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.thread = None
        self.worker = None
        self._row_of = {}
        self._ok = 0
        self._fail = 0
        self.setWindowTitle("Read DID")
        self.resize(820, 460)
        self.setMinimumSize(640, 380)
        self.setStyleSheet(DARK_QSS)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(6)
        self.read_all_btn = QPushButton("READ ALL")
        self.read_all_btn.setProperty("accent", "true")
        self.read_all_btn.clicked.connect(self.read_all)
        self.copy_btn = QPushButton("COPY")
        self.copy_btn.clicked.connect(self._copy_all)
        self.clear_btn = QPushButton("CLEAR")
        self.clear_btn.clicked.connect(self._reset_values)
        self.status = QLabel("Ready")
        self.status.setProperty("role", "info")
        top.addWidget(self.read_all_btn)
        top.addWidget(self.copy_btn)
        top.addWidget(self.clear_btn)
        top.addStretch(1)
        top.addWidget(self.status)
        root.addLayout(top)

        self.table = QTableWidget(len(DID_ITEMS), 4)
        self.table.setObjectName("didTable")
        self.table.setHorizontalHeaderLabels(["DID", "Name", "Value", "Raw"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.table.setStyleSheet("QTableWidget#didTable::item { padding: 0 8px; }")
        vh = self.table.verticalHeader()
        vh.setVisible(False)
        vh.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        vh.setDefaultSectionSize(32)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setStretchLastSection(False)
        self.table.setColumnWidth(self.COL_DID, 80)
        self.table.setColumnWidth(self.COL_NAME, 140)
        self.table.setColumnWidth(self.COL_RAW, 250)
        hh.setSectionResizeMode(self.COL_VALUE, QHeaderView.ResizeMode.Stretch)

        mono = QFont("Consolas")
        mono.setPointSize(10)
        for r, (did, name, important) in enumerate(DID_ITEMS):
            self._row_of[did] = r
            did_item = QTableWidgetItem(f"0x{did:04X}")
            did_item.setForeground(self.C_ACCENT if important else self.C_MUTED)
            f = did_item.font()
            f.setBold(important)
            did_item.setFont(f)
            name_item = QTableWidgetItem(name)
            name_item.setForeground(self.C_TEXT if important else QColor("#b0b0c0"))
            value_item = QTableWidgetItem("—")
            value_item.setFont(mono)
            value_item.setForeground(self.C_MUTED)
            raw_item = QTableWidgetItem("")
            raw_item.setFont(mono)
            raw_item.setForeground(self.C_MUTED)
            self.table.setItem(r, self.COL_DID, did_item)
            self.table.setItem(r, self.COL_NAME, name_item)
            self.table.setItem(r, self.COL_VALUE, value_item)
            self.table.setItem(r, self.COL_RAW, raw_item)
        root.addWidget(self.table, 1)

    def _set_status(self, text, role):
        self.status.setText(text)
        self.status.setProperty("role", role)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)

    def _set_cell(self, did, col, text, color, tooltip=""):
        r = self._row_of.get(did)
        if r is None:
            return
        item = self.table.item(r, col)
        item.setText(text)
        item.setForeground(color)
        item.setToolTip(tooltip)

    def _reset_values(self):
        if self.thread is not None:
            return
        for did in self._row_of:
            self._set_cell(did, self.COL_VALUE, "—", self.C_MUTED)
            self._set_cell(did, self.COL_RAW, "", self.C_MUTED)
        self._ok = self._fail = 0
        self._set_status("Ready", "info")

    def _copy_all(self):
        lines = []
        for r, (did, name, _) in enumerate(DID_ITEMS):
            value = self.table.item(r, self.COL_VALUE).text()
            lines.append(f"0x{did:04X}\t{name}\t{value}")
        QApplication.clipboard().setText("\n".join(lines))
        self._set_status("Copied to clipboard", "info")

    def read_all(self):
        if not self._can_read():
            return
        try:
            txid = int(self.owner.txid.text(), 0)
            rxid = int(self.owner.rxid.text(), 0)
        except ValueError as e:
            self._set_status(str(e), "err")
            return
        fd = self.owner.fd_check.isChecked() and self.owner.diag_fd.isChecked()
        self._ok = self._fail = 0
        for did in self._row_of:
            self._set_cell(did, self.COL_VALUE, "…", self.C_MUTED)
            self._set_cell(did, self.COL_RAW, "", self.C_MUTED)
        self.read_all_btn.setEnabled(False)
        self._set_status("Reading...", "info")
        self.thread = QThread(self)
        self.worker = DidWorker(self.owner.bus, txid, rxid, fd, [d for d, _, _ in DID_ITEMS])
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.result.connect(self._on_result)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self._on_done)
        self.thread.finished.connect(self._on_cleanup)
        self.thread.start()

    def _can_read(self):
        if self.owner.bus is None:
            self._set_status("Connect CAN first", "warn")
            return False
        if self.owner.thread is not None:
            self._set_status("Disabled while flashing", "warn")
            return False
        if self.thread is not None:
            return False
        return True

    def _on_result(self, did, ok, value, raw):
        if ok:
            self._ok += 1
        else:
            self._fail += 1
        color = self.C_OK if ok else self.C_ERR
        self._set_cell(did, self.COL_VALUE, value, color, value)
        self._set_cell(did, self.COL_RAW, raw, self.C_MUTED, raw)

    def _on_done(self):
        self.read_all_btn.setEnabled(True)
        total = self._ok + self._fail
        self._set_status(f"Done — {self._ok}/{total} OK", "ok" if self._fail == 0 else "warn")

    def _on_cleanup(self):
        if self.worker is not None: self.worker.deleteLater()
        if self.thread is not None: self.thread.deleteLater()
        self.worker = None
        self.thread = None

    def closeEvent(self, event):
        event.ignore()
        self.hide()

class FlashWorker(QObject):
    """Runs the flash sequence `repeat` times in a row, waiting `delay` seconds between runs."""
    log = Signal(str)
    progress = Signal(str, int)
    run_state = Signal(str, int, int, int)
    finished = Signal(bool, str)

    def __init__(self, cfg, images, bus, repeat=1, delay=0, stop_on_fail=True):
        super().__init__()
        self.cfg, self.images, self.bus = cfg, images, bus
        self.repeat = max(1, int(repeat))
        self.delay = max(0, int(delay))
        self.stop_on_fail = bool(stop_on_fail)
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def _emit_log(self, text):
        self.log.emit(f"[{dt.datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {text}")

    def run(self):
        cb = FlashCallbacks(
            log=self._emit_log,
            progress=lambda name, pct: self.progress.emit(name, pct),
            should_stop=self.stop_event.is_set,
        )
        total = self.repeat
        passed = failed = executed = 0
        interrupted = 0
        last = (False, "Stopped by user")
        for n in range(1, total + 1):
            if self.stop_event.is_set():
                break
            self.run_state.emit("run", n, total, 0)
            if total > 1:
                self._emit_log(f"[RUN {n}/{total}] START")
            t0 = time.monotonic()
            ok, msg = FlashRunner(self.cfg, self.images, self.bus, cb).run()
            last = (ok, msg)
            executed += 1
            elapsed = time.monotonic() - t0
            if ok:
                passed += 1
                verdict = "PASS"
            elif self.stop_event.is_set():
                interrupted = n
                verdict = "STOPPED"
            else:
                failed += 1
                verdict = "FAIL"
            if total > 1:
                self._emit_log(f"[RUN {n}/{total}] {verdict} in {elapsed:.1f}s" + ("" if ok else f" - {msg}"))
            if self.stop_event.is_set() or (not ok and self.stop_on_fail):
                break
            if n < total and self.delay > 0:
                self._emit_log(f"[RUN] Waiting {self.delay}s before run {n + 1}/{total}")
                for left in range(self.delay, 0, -1):
                    self.run_state.emit("wait", n + 1, total, left)
                    if self.stop_event.wait(1.0):
                        break
                if self.stop_event.is_set():
                    break

        if total == 1:
            self.finished.emit(*last)
            return
        parts = [f"{passed}/{total} runs passed"]
        if failed:
            parts.append(f"{failed} failed")
        if interrupted:
            parts.append(f"run {interrupted} interrupted")
        if self.stop_event.is_set():
            parts.append(f"stopped by user after {executed} run(s)")
        elif executed < total:
            parts.append(f"aborted after run {executed} (stop on first failure)")
        self.finished.emit(failed == 0 and passed == total, ", ".join(parts))

class SimulationWorker(QThread):
    log = Signal(str)
    
    def __init__(self, bus, msg_defs, e2e_enabled, is_fd=False):
        super().__init__()
        self.bus = bus
        self.msg_defs = msg_defs
        self.e2e_enabled = e2e_enabled
        self.is_fd = is_fd
        self._is_running = True
        self.counters = {}

    def run(self):
        next_due = {fid: time.monotonic() for fid in self.msg_defs}
        while self._is_running:
            now = time.monotonic()
            for fid, data in self.msg_defs.items():
                if now >= next_due[fid]:
                    try:
                        msg = data["msg"]
                        values = dict(data["values"])
                        
                        if self.e2e_enabled:
                            alive_sig = next((s for s in msg.signals if any(x in s.name.upper() for x in ["ALIVE", "COUNTER", "ARC"])), None)
                            if alive_sig:
                                mod = (1 << alive_sig.length) - 1
                                cur = self.counters.get(fid, 0)
                                values[alive_sig.name] = cur
                                self.counters[fid] = (cur + 1) & mod
                            
                            payload = bytearray(msg.encode(values, scaling=True))
                            
                            crc_sig = next((s for s in msg.signals if any(x in s.name.upper() for x in ["CRC", "CHECKSUM"])), None)
                            if crc_sig and crc_sig.length == 8:
                                byte_order = getattr(crc_sig, "byte_order", "little_endian")
                                if byte_order == "big_endian":
                                    if crc_sig.start % 8 == 7:
                                        crc_idx = crc_sig.start // 8
                                        if 0 <= crc_idx < len(payload):
                                            cover = payload[:crc_idx] + payload[crc_idx+1:]
                                            payload[crc_idx] = self._crc8_sae_j1850(cover)
                                else:
                                    if crc_sig.start % 8 == 0:
                                        crc_idx = crc_sig.start // 8
                                        if 0 <= crc_idx < len(payload):
                                            cover = payload[:crc_idx] + payload[crc_idx+1:]
                                            payload[crc_idx] = self._crc8_sae_j1850(cover)
                        else:
                            payload = msg.encode(values, scaling=True)
                            
                        payload_bytes = bytes(payload)
                        is_fd = len(payload_bytes) > 8 or self.is_fd
                        if is_fd:
                            valid_lengths = (8, 12, 16, 20, 24, 32, 48, 64)
                            for length in valid_lengths:
                                if length >= len(payload_bytes):
                                    payload_bytes = payload_bytes.ljust(length, b'\x00')
                                    break
                            if len(payload_bytes) > 64:
                                payload_bytes = payload_bytes[:64]
                        else:
                            payload_bytes = payload_bytes.ljust(8, b'\x00')

                        tx = can.Message(arbitration_id=fid, data=payload_bytes, 
                                         is_extended_id=msg.is_extended_frame, is_fd=is_fd)
                        send_with_retry(self.bus, tx, should_stop=lambda: not self._is_running,
                                        timeout=0.2)
                    except Exception as e:
                        self.log.emit(f"[SIM][ERROR] 0x{fid:X}: {e}")
                    next_due[fid] = now + (data["cycle"] / 1000.0)
            time.sleep(0.005)

    def stop(self):
        self._is_running = False
        
    @staticmethod
    def _crc8_sae_j1850(data: bytes) -> int:
        crc = 0xFF
        for b in data:
            crc ^= b
            for _ in range(8):
                if crc & 0x80:
                    crc = ((crc << 1) ^ 0x1D) & 0xFF
                else:
                    crc = (crc << 1) & 0xFF
        return crc ^ 0xFF

# --- Virtual ECU Simulator ---
class VirtualEcuWorker(QThread):
    log = Signal(str)
    
    def __init__(self, rxid, txid, fd):
        super().__init__()
        self.rxid = rxid
        self.txid = txid
        self.fd = fd
        self._is_running = True
        self.bus = None
        self.rx_buf = bytearray()
        self.rx_expected = 0

    def run(self):
        try:
            self.bus = can.Bus(interface="virtual", channel="virtual", receive_own_messages=False)
        except Exception as e:
            self.log.emit(f"[VECU][ERROR] Cannot open bus: {e}")
            return
            
        self.log.emit(f"[VECU] Virtual ECU started (RX=0x{self.rxid:X}, TX=0x{self.txid:X})")
        
        while self._is_running:
            msg = self.bus.recv(0.01)
            if msg is None: continue
            if msg.arbitration_id != self.rxid: continue
            
            data = bytes(msg.data)
            if not data: continue
            
            pci = data[0] >> 4
            
            if pci == 0:
                n = data[0] & 0x0F
                if n == 0: n = data[1]; payload = data[2:2+n]
                else: payload = data[1:1+n]
                self._handle_request(payload)
            elif pci == 1:
                length = ((data[0] & 0x0F) << 8) | data[1]
                self.rx_expected = length
                self.rx_buf = bytearray(data[2:])
                self._send_fc()
            elif pci == 2:
                self.rx_buf.extend(data[1:])
                if len(self.rx_buf) >= self.rx_expected:
                    self._handle_request(bytes(self.rx_buf[:self.rx_expected]))
                    self.rx_buf.clear()
            elif pci == 3:
                pass

    def _send_can(self, payload):
        if self.fd:
            valid_lengths = (8, 12, 16, 20, 24, 32, 48, 64)
            for length in valid_lengths:
                if length >= len(payload):
                    payload = payload.ljust(length, b'\x00')
                    break
        else:
            payload = payload.ljust(8, b'\x00')
            
        self.bus.send(can.Message(arbitration_id=self.txid, data=payload, is_extended_id=False, is_fd=self.fd))

    def _send_fc(self):
        self._send_can(b"\x30\x00\x00")

    def _send_isotp(self, payload):
        n = len(payload)
        if n <= 7:
            self._send_can(bytes([n]) + payload)
        else:
            first_data = payload[:6] if not self.fd else payload[:62]
            ff = bytes([0x10 | ((n >> 8) & 0x0F), n & 0xFF]) + first_data
            self._send_can(ff)
            offset = len(first_data)
            seq = 1
            while offset < n:
                chunk = payload[offset:offset + (7 if not self.fd else 63)]
                self._send_can(bytes([0x20 | seq]) + chunk)
                offset += len(chunk)
                seq = (seq + 1) & 0x0F

    def _handle_request(self, req):
        if not req: return
        sid = req[0]
        
        if sid == 0x3E:
            self._send_isotp(bytes([0x7E, req[1] if len(req) > 1 else 0]))
            
        elif sid == 0x10 and len(req) >= 2:
            self._send_isotp(bytes([0x50, req[1], 0x00, 0x32, 0x01, 0xF4]))
            
        elif sid == 0x11:
            self._send_isotp(bytes([0x51, req[1] if len(req) > 1 else 0x01]))
            
        elif sid == 0x22 and len(req) >= 3:
            did = (req[1] << 8) | req[2]
            data = bytearray([0x62, req[1], req[2]])
            if did == 0xF188: data.extend(b"ABC12345678")
            elif did == 0xF191: data.extend(b"DEF98765432")
            elif did == 0xF103: data.extend(b"GHI55566677")
            elif did == 0xF194: data.extend(b"20240115")
            elif did == 0xF195: data.extend(b"1.2.3")
            elif did == 0xF101: data.extend(b"0.0.1")
            elif did == 0xDB11: data.extend(b"\x01")
            elif did == 0xF148: data.extend(b"00")
            elif did == 0xF141: data.extend(b"01")
            elif did == 0xF143: data.extend(b"02")
            else:
                self._send_isotp(bytes([0x7F, 0x22, 0x31]))
                return
            self._send_isotp(bytes(data))
            
        elif sid == 0x27 and len(req) >= 2:
            sub = req[1]
            if sub & 1:
                self._send_isotp(bytes([0x67, sub]) + b"\x11\x22\x33\x44")
            else:
                self._send_isotp(bytes([0x67, sub]))
                
        elif sid == 0x28:
            self._send_isotp(bytes([0x68, req[1] if len(req) > 1 else 0]))
            
        elif sid == 0x2E:
            self._send_isotp(bytes([0x6E]) + req[1:3])
            
        elif sid == 0x31:
            self._send_isotp(bytes([0x71]) + req[1:4] + b"\x00\x00\x00")
            
        elif sid == 0x34:
            self._send_isotp(bytes([0x74, 0x20, 0x04, 0x00]))
            
        elif sid == 0x36:
            self._send_isotp(bytes([0x76, req[1] if len(req) > 1 else 1]))
            
        elif sid == 0x37:
            self._send_isotp(bytes([0x77]))
            
        elif sid == 0x85:
            self._send_isotp(bytes([0xC5, req[1] if len(req) > 1 else 0]))
            
        else:
            self._send_isotp(bytes([0x7F, sid, 0x11]))

    def stop(self):
        self._is_running = False
        if self.bus is not None:
            try: self.bus.shutdown()
            except Exception: pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {version_text()} — Vector / PEAK")
        # Cố định kích thước để tránh layout bị phá vỡ khi cửa sổ quá nhỏ
        self.setFixedSize(1150, 850)
        self.setStyleSheet(DARK_QSS)

        self.thread = None
        self.worker = None
        self.bus = None
        self.images = {}
        self.file_edits = {}
        self.file_checks = {}
        self.file_info = {}
        self.dbc_database = None
        self.dbc_messages = {}
        self.sim_worker = None
        self.vecu_worker = None

        self.trace_bridge = TraceBridge()
        self.trace_window = TraceWindow(self)
        self.did_panel = DidPanel(self)

        self._build_ui()
        self._adapter_changed(self.interface.currentText())
        self._load_config()
        self.log_line(f"[APP] {version_details().replace(chr(10), ' | ')}")

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 8, 10, 10)
        root.setSpacing(8)

        header = QFrame()
        header.setStyleSheet("QFrame { background: #22222e; border-radius: 8px; }")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(12, 8, 12, 8)
        
        self.status_label = QLabel("DISCONNECTED")
        self.status_label.setProperty("role", "err")
        hl.addWidget(self.status_label)
        hl.addSpacing(10)
        self.version_label = QLabel(version_text())
        self.version_label.setStyleSheet("color: #8a8a9a;")
        self.version_label.setToolTip(version_details())
        hl.addWidget(self.version_label)
        hl.addStretch(1)
        
        self.trace_btn = QPushButton("TRACE")
        self.trace_btn.clicked.connect(self.toggle_trace)
        self.did_btn = QPushButton("READ DID")
        self.did_btn.clicked.connect(self.show_did)
        self.save_cfg_btn = QPushButton("SAVE CONFIG")
        self.save_cfg_btn.setToolTip("Save the entire app configuration to a JSON file")
        self.save_cfg_btn.clicked.connect(self.save_config_as)
        self.load_cfg_btn = QPushButton("LOAD CONFIG")
        self.load_cfg_btn.setToolTip("Load a previously saved configuration")
        self.load_cfg_btn.clicked.connect(self.load_config_from)
        hl.addWidget(self.save_cfg_btn)
        hl.addWidget(self.load_cfg_btn)
        hl.addSpacing(12)
        hl.addWidget(self.trace_btn)
        hl.addWidget(self.did_btn)
        root.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_flash_tab(), "Flashing")
        self.tabs.addTab(self._build_sim_tab(), "Simulation")
        root.addWidget(self.tabs, 1)

        bottom = QFrame()
        bottom.setStyleSheet("QFrame { background: #22222e; border-radius: 8px; }")
        bl = QVBoxLayout(bottom)
        bl.setContentsMargins(10, 8, 10, 8)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        bl.addWidget(self.progress)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(130)
        self.log.setMaximumHeight(220)
        self.log.setStyleSheet("QPlainTextEdit { font-family: Consolas; font-size: 9pt; background: #1a1a24; border: 1px solid #2c2c38; }")
        bl.addWidget(self.log)
        root.addWidget(bottom)

    def _build_flash_tab(self):
        w = QWidget()
        layout = QHBoxLayout(w)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)
        left = QVBoxLayout()
        left.setSpacing(15)
        right = QVBoxLayout()
        right.setSpacing(15)
        layout.addLayout(left, 1)
        layout.addLayout(right, 1)

        files = QGroupBox("Firmware files")
        g = QGridLayout(files)
        g.setColumnStretch(1, 1)
        for row, name in enumerate(("Driver", "Bootloader", "Application")):
            cb = QCheckBox(name)
            cb.setMinimumWidth(100)
            edit = QLineEdit()
            edit.setReadOnly(True)
            btn = QPushButton("...")
            btn.setFixedWidth(44)
            info = QLabel("No file")
            info.setStyleSheet("color: #8a8a9a;")
            btn.clicked.connect(lambda _, n=name: self.select_file(n))
            g.addWidget(cb, row, 0)
            g.addWidget(edit, row, 1)
            g.addWidget(btn, row, 2)
            g.addWidget(info, row, 3)
            self.file_checks[name] = cb
            self.file_edits[name] = edit
            self.file_info[name] = info
        left.addWidget(files)

        ctrl = QGroupBox("Flash control")
        cg = QVBoxLayout(ctrl)

        opts = QGridLayout()
        opts.setHorizontalSpacing(10)
        self.repeat_spin = QSpinBox()
        self.repeat_spin.setRange(1, 9999)
        self.repeat_spin.setValue(1)
        self.repeat_spin.setToolTip("Number of consecutive flashing runs")
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 3600)
        self.delay_spin.setValue(10)
        self.delay_spin.setSuffix(" s")
        self.delay_spin.setToolTip("Wait time between two runs (lets the ECU finish rebooting)")
        self.stop_on_fail_check = QCheckBox("Stop on first failure")
        self.stop_on_fail_check.setChecked(True)
        self.stop_on_fail_check.setToolTip("Untick to keep running the remaining runs after a failed run")
        opts.addWidget(QLabel("Consecutive runs"), 0, 0)
        opts.addWidget(self.repeat_spin, 0, 1)
        opts.addWidget(QLabel("Delay between runs"), 1, 0)
        opts.addWidget(self.delay_spin, 1, 1)
        opts.addWidget(self.stop_on_fail_check, 2, 0, 1, 2)
        opts.setColumnStretch(1, 1)
        cg.addLayout(opts)

        self.start_btn = QPushButton("START FLASHING")
        self.start_btn.setProperty("accent", "true")
        self.start_btn.setMinimumHeight(50)
        self.start_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_flash)
        self.stop_btn = QPushButton("STOP")
        self.stop_btn.setProperty("danger", "true")
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_flash)
        cg.addWidget(self.start_btn)
        cg.addWidget(self.stop_btn)
        left.addWidget(ctrl)

        can_box = QGroupBox("CAN Connection")
        cg = QGridLayout(can_box)
        
        self.interface = QComboBox()
        self.interface.addItems(["CANoe / Vector", "PEAK PCAN-USB", "Virtual CAN (Debug)"])
        self.interface.currentTextChanged.connect(self._adapter_changed)
        
        self.channel = QComboBox()
        self.channel.setEditable(True)
        
        self.can_mode = QComboBox()
        self.can_mode.addItems(["CAN 2.0 (500 kbit/s)", "CAN FD (500 k / 2 Mbit/s)"])
        self.fd_check = QCheckBox()
        self.fd_check.hide()
        self.diag_fd = QCheckBox()
        self.diag_fd.hide()
        
        def _sync(text):
            is_fd = text.startswith("CAN FD")
            self.fd_check.setChecked(is_fd)
            self.diag_fd.setChecked(is_fd)
        self.can_mode.currentTextChanged.connect(_sync)
        _sync(self.can_mode.currentText())
        
        self.data_bitrate = QSpinBox()
        self.data_bitrate.setRange(500000, 8000000)
        self.data_bitrate.setValue(2000000)

        cg.addWidget(QLabel("Adapter"), 0, 0)
        cg.addWidget(self.interface, 1, 0)
        cg.addWidget(QLabel("Channel"), 0, 1)
        cg.addWidget(self.channel, 1, 1)
        cg.addWidget(QLabel("CAN type"), 2, 0)
        cg.addWidget(self.can_mode, 3, 0)
        cg.addWidget(QLabel("Data bitrate"), 2, 1)
        cg.addWidget(self.data_bitrate, 3, 1)

        self.connect_btn = QPushButton("CONNECT")
        self.connect_btn.setProperty("accent", "true")
        self.connect_btn.clicked.connect(self.connect_bus)
        self.disconnect_btn = QPushButton("DISCONNECT")
        self.disconnect_btn.setEnabled(False)
        self.disconnect_btn.clicked.connect(self.disconnect_bus)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.connect_btn)
        btn_layout.addWidget(self.disconnect_btn)
        
        cg.addLayout(btn_layout, 4, 0, 1, 2)
        right.addWidget(can_box)

        uds_box = QGroupBox("UDS Identifiers")
        ug = QGridLayout(uds_box)
        self.txid = QLineEdit("0x69B")
        self.rxid = QLineEdit("0x61B")
        self.fid = QLineEdit("0x6FF")
        
        # Ẩn Security level & Block size (giữ giá trị ngầm định)
        self.level = QLineEdit("0x07")
        self.level.hide()
        self.block_size = QComboBox()
        self.block_size.addItems(["128", "256", "512", "1024"])
        self.block_size.setCurrentText("1024")
        self.block_size.hide()
        
        self.hard_reset_check = QCheckBox("Hard reset (11 01)")
        self.hard_reset_check.setChecked(True)
        self.hv_check = QCheckBox("Turn off HV")
        
        ug.setHorizontalSpacing(10)
        ug.setVerticalSpacing(4)
        ug.addWidget(QLabel("TX ID"), 0, 0)
        ug.addWidget(self.txid, 1, 0)
        ug.addWidget(QLabel("RX ID"), 0, 1)
        ug.addWidget(self.rxid, 1, 1)
        ug.addWidget(QLabel("Functional ID"), 0, 2)
        ug.addWidget(self.fid, 1, 2)
        # Hàng 2 chỉ có 2 checkbox, trải rộng 2 cột đầu và 1 cột cuối cho cân
        ug.addWidget(self.hard_reset_check, 2, 0, 1, 2)
        ug.addWidget(self.hv_check, 2, 2)
        ug.setRowMinimumHeight(2, 32)
        for col in range(3):
            ug.setColumnStretch(col, 1)
        right.addWidget(uds_box)

        sk_box = QGroupBox("Seed-Key DLL")
        sg = QHBoxLayout(sk_box)
        self.dll_path = QLineEdit()
        self.dll_path.setReadOnly(True)
        dll_btn = QPushButton("...")
        dll_btn.setFixedWidth(44)
        dll_btn.clicked.connect(self.select_dll)
        
        self.dll_export = QLineEdit("GenerateKeyEx")
        self.py32_path = QLineEdit()
        
        sg.addWidget(self.dll_path, 1)
        sg.addWidget(dll_btn)
        right.addWidget(sk_box)

        left.addStretch(1)
        right.addStretch(1)
        return w

    def _build_sim_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(6, 8, 6, 6)
        v.setSpacing(8)

        top = QGroupBox("Simulation Setup")
        tg = QHBoxLayout(top)
        self.dbc_path = QLineEdit()
        self.dbc_path.setReadOnly(True)
        self.dbc_import_btn = QPushButton("IMPORT DBC")
        self.dbc_import_btn.clicked.connect(self.import_dbc)
        
        self.dbc_start_btn = QPushButton("START SIM")
        self.dbc_start_btn.setProperty("accent", "true")
        self.dbc_start_btn.setEnabled(False)
        self.dbc_start_btn.clicked.connect(self.start_sim)
        
        self.dbc_stop_btn = QPushButton("STOP SIM")
        self.dbc_stop_btn.setProperty("danger", "true")
        self.dbc_stop_btn.setEnabled(False)
        self.dbc_stop_btn.clicked.connect(self.stop_sim)

        self.dbc_status = QLabel("NOT RUNNING")
        self.dbc_status.setProperty("role", "warn")
        
        tg.addWidget(QLabel("DBC File"))
        tg.addWidget(self.dbc_path, 1)
        tg.addWidget(self.dbc_import_btn)
        tg.addWidget(self.dbc_start_btn)
        tg.addWidget(self.dbc_stop_btn)
        tg.addWidget(self.dbc_status)
        v.addWidget(top)

        filter_row = QHBoxLayout()
        self.dbc_id_filter = QLineEdit()
        self.dbc_id_filter.setPlaceholderText("Filter CAN ID (HEX): 216, 0x216, 18DAF110 (cách nhau bởi dấu phẩy)")
        self.dbc_id_filter.setClearButtonEnabled(True)
        self.dbc_id_filter.textChanged.connect(self._apply_dbc_id_filter)
        
        self.dbc_filter_clear_btn = QPushButton("CLEAR FILTER")
        self.dbc_filter_clear_btn.clicked.connect(self.dbc_id_filter.clear)
        
        self.dbc_filter_result = QLabel("SHOWING ALL")
        self.dbc_filter_result.setMinimumWidth(150)
        self.dbc_filter_result.setProperty("role", "info")
        
        filter_row.addWidget(QLabel("Message ID Filter"))
        filter_row.addWidget(self.dbc_id_filter, 1)
        filter_row.addWidget(self.dbc_filter_clear_btn)
        filter_row.addWidget(self.dbc_filter_result)
        v.addLayout(filter_row)

        ecu_row = QHBoxLayout()
        self.ecu_combo = QComboBox()
        self.ecu_combo.setMinimumWidth(150)
        
        self.btn_check_tx = QPushButton("Check TX from ECU")
        self.btn_check_tx.clicked.connect(lambda: self._select_by_ecu("tx"))
        
        self.btn_check_rx = QPushButton("Check RX to ECU")
        self.btn_check_rx.clicked.connect(lambda: self._select_by_ecu("rx"))
        
        self.btn_uncheck_all = QPushButton("Uncheck All")
        self.btn_uncheck_all.clicked.connect(self._uncheck_all)
        
        self.chk_e2e = QCheckBox("Auto E2E (Alive + CRC)")
        self.chk_e2e.setChecked(True)
        
        ecu_row.addWidget(QLabel("ECU/Node"))
        ecu_row.addWidget(self.ecu_combo)
        ecu_row.addWidget(self.btn_check_tx)
        ecu_row.addWidget(self.btn_check_rx)
        ecu_row.addWidget(self.btn_uncheck_all)
        ecu_row.addStretch(1)
        ecu_row.addWidget(self.chk_e2e)
        v.addLayout(ecu_row)

        self.dbc_tree = QTreeWidget()
        self.dbc_tree.setHeaderLabels(["Message / Signal", "Value", "Unit", "Cycle (ms)"])
        self.dbc_tree.setAlternatingRowColors(True)
        self.dbc_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.dbc_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.dbc_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.dbc_tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.dbc_tree.setColumnWidth(1, 200)
        self.dbc_tree.setColumnWidth(3, 80)
        v.addWidget(self.dbc_tree, 1)
        return w

    def select_file(self, name):
        path, _ = QFileDialog.getOpenFileName(self, f"Select {name}", "", "Firmware (*.hex *.ihex *.s37 *.srec *.s19 *.mot)")
        if not path: return
        self._load_firmware(name, path)

    def _load_firmware(self, name, path, checked=True):
        try:
            img = FirmwareParser.load(path)
        except Exception as e:
            self.log_line(f"[ERROR][FILE] {name}: {e}")
            return False
        self.images[name] = img
        self.file_edits[name].setText(path)
        self.file_checks[name].setChecked(checked)
        self.file_info[name].setText(f"{img.total_size} B | {len(img.blocks)} block")
        return True

    def select_dll(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Seed-Key DLL", "", "DLL (*.dll)")
        if not path: return
        self._set_dll(path)

    def _set_dll(self, path):
        self.dll_path.setText(path)
        bits = pe_bitness(path)
        if bits is None:
            self.log_line("[DLL][ERROR] Not a Windows DLL")
        elif bits == PY_BITS:
            self.log_line(f"[DLL] {bits}-bit, direct")
        else:
            cmd = find_python(bits, self.py32_path.text())
            if cmd:
                self.log_line(f"[DLL] {bits}-bit, bridge={' '.join(cmd)}")
            else:
                self.log_line(f"[DLL][ERROR] Need Python {bits}-bit")

    def import_dbc(self):
        if cantools is None:
            self.log_line("[ERROR] cantools not installed")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Import DBC", "", "DBC (*.dbc)")
        if not path: return
        self._load_dbc(path)

    def _load_dbc(self, path):
        if cantools is None:
            self.log_line("[ERROR] cantools not installed")
            return False
        try:
            db = cantools.database.load_file(path, strict=False)
        except Exception as e:
            self.log_line(f"[ERROR][DBC] {e}")
            return False
        self.dbc_database = db
        self.dbc_tree.clear()
        self.dbc_messages.clear()

        for msg in db.messages:
            fid = int(msg.frame_id)
            cycle_time = msg.cycle_time if msg.cycle_time else 100
            
            msg_item = QTreeWidgetItem(self.dbc_tree)
            msg_item.setText(0, f"0x{fid:X} - {msg.name}")
            msg_item.setText(3, str(cycle_time))
            msg_item.setFlags(msg_item.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEditable)
            msg_item.setCheckState(0, Qt.CheckState.Unchecked)
            msg_item.setData(0, Qt.ItemDataRole.UserRole, ("msg", fid))
            
            for sig in msg.signals:
                sig_item = QTreeWidgetItem(msg_item)
                sig_item.setText(0, sig.name)
                sig_item.setText(2, sig.unit or "")
                sig_item.setData(0, Qt.ItemDataRole.UserRole, ("sig", fid, sig.name))
                
                if hasattr(sig, "choices") and sig.choices:
                    combo = QComboBox()
                    for val, name_txt in sig.choices.items():
                        combo.addItem(str(name_txt), val)
                    default_val = sig.initial if sig.initial is not None else list(sig.choices.keys())[0]
                    idx = combo.findData(default_val)
                    if idx >= 0: combo.setCurrentIndex(idx)
                    self.dbc_tree.setItemWidget(sig_item, 1, combo)
                else:
                    default_val = sig.initial if sig.initial is not None else 0
                    sig_item.setText(1, str(default_val))
                    sig_item.setFlags(sig_item.flags() | Qt.ItemFlag.ItemIsEditable)
            
            self.dbc_messages[fid] = {"message": msg, "item": msg_item}
            
        self.dbc_tree.collapseAll()
        self.dbc_path.setText(path)
        self.dbc_status.setText(f"LOADED: {len(db.messages)} msg")
        self.dbc_status.setProperty("role", "ok")
        self.dbc_start_btn.setEnabled(self.bus is not None)
        self.log_line(f"[DBC] Loaded {path}")
        
        all_nodes = set()
        if hasattr(db, "nodes") and db.nodes:
            for n in db.nodes:
                node_name = getattr(n, "name", str(n)).strip()
                if node_name and node_name != "Vector__XXX":
                    all_nodes.add(node_name)

        self.ecu_combo.clear()
        if all_nodes:
            self.ecu_combo.addItems(sorted(list(all_nodes)))
            self.log_line(f"[DBC] Found {len(all_nodes)} network nodes: {', '.join(sorted(list(all_nodes)))}")
        else:
            self.ecu_combo.addItem("No network nodes defined")
            self.log_line("[DBC][WARN] No network nodes (BU_) found in DBC.")

        self._apply_dbc_id_filter()
        return True

    def _select_by_ecu(self, mode="tx"):
        if not self.dbc_database: return
        ecu = self.ecu_combo.currentText()
        if ecu in ("No network nodes defined", "No ECU defined"): return
        
        count = 0
        for fid, data in self.dbc_messages.items():
            msg = data["message"]
            matched = False
            
            if mode == "tx":
                if hasattr(msg, "senders") and msg.senders:
                    for s in msg.senders:
                        sender_name = getattr(s, "name", str(s)).strip()
                        if sender_name == ecu:
                            matched = True
                            break
            elif mode == "rx":
                if hasattr(msg, "receivers") and msg.receivers:
                    for r in msg.receivers:
                        recv_name = getattr(r, "name", str(r)).strip()
                        if recv_name == ecu:
                            matched = True
                            break
                
                if not matched:
                    for sig in msg.signals:
                        if hasattr(sig, "receivers") and sig.receivers:
                            for r in sig.receivers:
                                recv_name = getattr(r, "name", str(r)).strip()
                                if recv_name == ecu:
                                    matched = True
                                    break
                            if matched: break
                            
            if matched:
                data["item"].setCheckState(0, Qt.CheckState.Checked)
                count += 1
                
        self.log_line(f"[DBC] Checked {count} message(s) ({mode.upper()}) for ECU '{ecu}'")

    def _uncheck_all(self):
        for data in self.dbc_messages.values():
            data["item"].setCheckState(0, Qt.CheckState.Unchecked)

    def _parse_dbc_id_filter(self, text):
        text = text.replace(",", " ").replace(";", " ").replace("|", " ")
        ids, invalid = set(), []
        for tok in text.split():
            t = tok.strip().lower().replace("_", "")
            try:
                if t.startswith("d:"): v = int(t[2:], 10)
                elif t.startswith("dec:"): v = int(t[4:], 10)
                else: v = int(t[2:] if t.startswith("0x") else t, 16)
            except ValueError:
                invalid.append(tok)
                continue
            if 0 <= v <= 0x1FFFFFFF: ids.add(v)
            else: invalid.append(tok)
        return ids, invalid

    def _apply_dbc_id_filter(self):
        if not hasattr(self, "dbc_tree") or not self.dbc_tree: return
        text = self.dbc_id_filter.text().strip()
        ids, invalid = self._parse_dbc_id_filter(text)
        filtering = bool(text)
        
        visible_count = 0
        for i in range(self.dbc_tree.topLevelItemCount()):
            item = self.dbc_tree.topLevelItem(i)
            data = item.data(0, Qt.ItemDataRole.UserRole)
            fid = data[1] if data else -1
            
            visible = (not filtering) or (not invalid and fid in ids)
            item.setHidden(not visible)
            if visible: visible_count += 1
                
        if invalid:
            self.dbc_filter_result.setText(f"INVALID: {', '.join(invalid[:2])}")
            self.dbc_filter_result.setProperty("role", "err")
        elif filtering:
            self.dbc_filter_result.setText(f"SHOWING {visible_count} MSG")
            self.dbc_filter_result.setProperty("role", "ok")
        else:
            self.dbc_filter_result.setText("SHOWING ALL")
            self.dbc_filter_result.setProperty("role", "info")
        self.dbc_filter_result.style().polish(self.dbc_filter_result)

    def start_sim(self):
        if self.bus is None:
            self.log_line("[ERROR] Connect CAN first")
            return
            
        filter_text = self.dbc_id_filter.text().strip()
        valid_ids, invalid = self._parse_dbc_id_filter(filter_text)
        if invalid:
            self.log_line("[ERROR] Invalid ID filter format")
            return
        filter_active = bool(filter_text)
            
        active_msgs = {}
        for fid, data in self.dbc_messages.items():
            msg_item = data["item"]
            if msg_item.checkState(0) != Qt.CheckState.Checked:
                continue
            if filter_active and fid not in valid_ids:
                continue

            try:
                cycle = int(msg_item.text(3))
            except ValueError:
                cycle = 100

            values = {}
            for i in range(msg_item.childCount()):
                sig_item = msg_item.child(i)
                sig_name = sig_item.text(0)
                widget = self.dbc_tree.itemWidget(sig_item, 1)
                if widget and isinstance(widget, QComboBox):
                    values[sig_name] = widget.currentData()
                else:
                    raw_val = sig_item.text(1)
                    try: values[sig_name] = int(raw_val, 0)
                    except ValueError:
                        try: values[sig_name] = float(raw_val)
                        except ValueError: values[sig_name] = raw_val
            active_msgs[fid] = {"msg": data["message"], "cycle": cycle, "values": values}

        if not active_msgs:
            self.log_line("[ERROR] No messages checked for simulation (or filtered out).")
            return

        self.sim_worker = SimulationWorker(
            self.bus, 
            active_msgs, 
            self.chk_e2e.isChecked(),
            is_fd=self.fd_check.isChecked()
        )
        self.sim_worker.log.connect(self.log_line)
        self.sim_worker.start()
        
        self.dbc_start_btn.setEnabled(False)
        self.dbc_stop_btn.setEnabled(True)
        self.dbc_status.setText("RUNNING")
        self.dbc_status.setProperty("role", "ok")
        self.log_line(f"[DBC] Simulation started with {len(active_msgs)} message(s)")

    def stop_sim(self):
        if self.sim_worker is not None:
            self.sim_worker.stop()
            self.sim_worker.wait(1000)
            self.sim_worker = None
            
        self.dbc_start_btn.setEnabled(self.bus is not None)
        self.dbc_stop_btn.setEnabled(False)
        self.dbc_status.setText("STOPPED")
        self.dbc_status.setProperty("role", "warn")
        self.log_line("[DBC] Simulation stopped")

    def _adapter_changed(self, name):
        current = self.channel.currentText().strip()
        self.channel.blockSignals(True)
        self.channel.clear()
        if name == "CANoe / Vector":
            try:
                configs = can.detect_available_configs(interfaces="vector", timeout=3.0)
            except Exception as e:
                configs = []
            for cfg in configs:
                serial = int(cfg.get("serial", 0) or 0)
                hw = int(cfg.get("hw_channel", cfg.get("channel", 0)))
                gidx = int(cfg.get("channel_index", -1))
                vc = cfg.get("vector_channel_config")
                dn = str(getattr(vc, "name", "Vector"))
                fd = "FD" if cfg.get("supports_fd", False) else "Classic"
                text = f"{dn} | S/N {serial} | CAN {hw+1} | {fd}"
                self.channel.addItem(text, {"channel": int(cfg.get("channel", hw)), "serial": serial, "channel_index": gidx})
            if self.channel.count() == 0:
                self.channel.addItem("No Vector channel detected", None)
        elif name == "PEAK PCAN-USB":
            for n in range(1, 17):
                self.channel.addItem(f"PCAN_USBBUS{n}", f"PCAN_USBBUS{n}")
        else:
            self.channel.addItem("virtual", "virtual")
        self.channel.blockSignals(False)

    def _connection_kwargs(self):
        is_vector = self.interface.currentText().startswith("CANoe")
        is_virtual = self.interface.currentText().startswith("Virtual")
        
        if is_virtual:
            return {"interface": "virtual", "channel": "virtual"}
            
        if is_vector:
            physical = self.channel.currentData()
            if not isinstance(physical, dict):
                raise RuntimeError("No Vector channel detected")
            kwargs = {"interface": "vector", "channel": int(physical["channel"]), "app_name": None, "bitrate": 500000, "receive_own_messages": True}
            if physical.get("serial"): kwargs["serial"] = int(physical["serial"])
            if int(physical.get("channel_index", -1)) >= 0: kwargs["channel_index"] = int(physical["channel_index"])
        else:
            kwargs = {"interface": "pcan", "channel": self.channel.currentText() or "PCAN_USBBUS1", "bitrate": 500000}
        if self.fd_check.isChecked():
            kwargs["fd"] = True
            data_br = self.data_bitrate.value()
            if not is_vector:
                kwargs["timing"] = can.BitTimingFd.from_sample_point(f_clock=80_000_000, nom_bitrate=500000, nom_sample_point=80.0, data_bitrate=data_br, data_sample_point=80.0)
            else:
                kwargs["data_bitrate"] = data_br
        return kwargs

    def connect_bus(self):
        if self.bus is not None: return
        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(False)
        self.status_label.setText("CONNECTING...")
        self.status_label.setProperty("role", "info")
        self.status_label.style().polish(self.status_label)
        QApplication.processEvents()
        try:
            kwargs = self._connection_kwargs()
            raw = can.Bus(**kwargs)
            self.bus = TraceBus(raw, self.trace_bridge)
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
            self.start_btn.setEnabled(True)
            self.interface.setEnabled(False)
            self.channel.setEnabled(False)
            self.status_label.setText("CONNECTED")
            self.status_label.setProperty("role", "ok")
            self.dbc_start_btn.setEnabled(self.dbc_database is not None)
            
            if self.interface.currentText().startswith("Virtual"):
                try:
                    txid = int(self.txid.text(), 0)
                    rxid = int(self.rxid.text(), 0)
                    is_fd = self.fd_check.isChecked()
                    self.vecu_worker = VirtualEcuWorker(rxid=txid, txid=rxid, fd=is_fd)
                    self.vecu_worker.log.connect(self.log_line)
                    self.vecu_worker.start()
                    self.log_line("[CAN] Virtual ECU Simulator auto-started on channel 'virtual'")
                except Exception as e:
                    self.log_line(f"[CAN] Cannot start Virtual ECU: {e}")
                    
        except Exception as e:
            self.bus = None
            self.status_label.setText("CONNECTION ERROR")
            self.status_label.setProperty("role", "err")
            self.log_line(f"[ERROR][CAN] {e}")
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)

    def disconnect_bus(self):
        if self.thread is not None: return
        self.disconnect_btn.setEnabled(False)
        self.status_label.setText("DISCONNECTING...")
        QApplication.processEvents()
        
        if self.vecu_worker is not None:
            self.vecu_worker.stop()
            self.vecu_worker.wait(1000)
            self.vecu_worker = None
            
        try:
            if self.bus is not None: self.bus.shutdown()
        except Exception: pass
        self.bus = None
        self.status_label.setText("DISCONNECTED")
        self.status_label.setProperty("role", "err")
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.interface.setEnabled(True)
        self.channel.setEnabled(True)
        self.dbc_start_btn.setEnabled(False)
        self.stop_sim()

    def start_flash(self):
        if self.thread is not None: return
        order = [x for x in ("Driver", "Bootloader", "Application") if self.file_checks[x].isChecked()]
        if not order or any(x not in self.images for x in order):
            self.log_line("[ERROR] Select valid firmware")
            return
        try:
            txid = int(self.txid.text(), 0)
            rxid = int(self.rxid.text(), 0)
            fid = int(self.fid.text(), 0)
            level = int(self.level.text(), 0)
            block_size = int(self.block_size.currentText(), 0)
        except ValueError as e:
            self.log_line(f"[ERROR] {e}")
            return
        cfg = {
            "fd": self.fd_check.isChecked(), "brs": False,
            "txid": txid, "rxid": rxid, "functional_id": fid,
            "security_level": level, "block_size": block_size,
            "bypass_reset": not self.hard_reset_check.isChecked(),
            "turn_off_hv": self.hv_check.isChecked(),
            "key_dll": self.dll_path.text(),
            "dll_export": self.dll_export.text().strip() or "GenerateKeyEx",
            "python_hint": self.py32_path.text().strip(),
        }
        self.trace_window.suspend()
        self.progress.setValue(0)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_flash_options_enabled(False)
        repeat, delay = self.repeat_spin.value(), self.delay_spin.value()
        if repeat > 1:
            self.log_line(f"[FLASH] {repeat} consecutive runs, {delay}s between runs, "
                          f"stop on first failure: {'yes' if self.stop_on_fail_check.isChecked() else 'no'}")
        self.thread = QThread()
        self.worker = FlashWorker(cfg, [(x, self.images[x]) for x in order], self.bus,
                                  repeat=repeat, delay=delay,
                                  stop_on_fail=self.stop_on_fail_check.isChecked())
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.log.connect(self.log_line)
        self.worker.progress.connect(lambda _, p: self.progress.setValue(p))
        self.worker.run_state.connect(self._on_run_state)
        self.worker.finished.connect(self._on_done)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self._on_cleanup)
        self.thread.start()

    def _set_status(self, text, role):
        self.status_label.setText(text)
        self.status_label.setProperty("role", role)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def _set_flash_options_enabled(self, enabled):
        for w in (self.repeat_spin, self.delay_spin, self.stop_on_fail_check):
            w.setEnabled(enabled)

    def _on_run_state(self, state, n, total, secs):
        if state == "run":
            self.progress.setValue(0)
            self.progress.setFormat(f"Run {n}/{total} - %p%" if total > 1 else "%p%")
            self._set_status(f"FLASHING {n}/{total}" if total > 1 else "FLASHING", "info")
        else:
            self.progress.setFormat(f"Next run {n}/{total} in {secs}s")
            self._set_status(f"WAITING {secs}s - NEXT RUN {n}/{total}", "warn")

    def _on_done(self, ok, msg):
        self.trace_window.resume()
        self.start_btn.setEnabled(self.bus is not None)
        self.stop_btn.setEnabled(False)
        self._set_flash_options_enabled(True)
        self.progress.setFormat("%p%")
        self.log_line(("[SUCCESS] " if ok else "[FAILED] ") + msg)
        if ok: self.progress.setValue(100)
        self._set_status("FLASH OK" if ok else "FLASH FAILED", "ok" if ok else "err")

    def _on_cleanup(self):
        if self.worker is not None: self.worker.deleteLater()
        if self.thread is not None: self.thread.deleteLater()
        self.worker = None
        self.thread = None

    def stop_flash(self):
        if self.worker is not None: self.worker.stop()

    def toggle_trace(self):
        if self.trace_window.isVisible(): self.trace_window.hide()
        else: self.trace_window.show(); self.trace_window.raise_()
        self._update_trace_btn()

    def _update_trace_btn(self):
        self.trace_btn.setText("HIDE TRACE" if self.trace_window.isVisible() else "TRACE")

    def show_did(self):
        self.did_panel.show(); self.did_panel.raise_()

    def log_line(self, text):
        if not text.startswith("["):
            text = f"[{dt.datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {text}"
        cursor = self.log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        if "[RX " in text: fmt.setForeground(QColor("#3fb950"))
        elif "[TX " in text: fmt.setForeground(QColor("#58a6ff"))
        elif "[ERROR" in text or "[FAILED" in text: fmt.setForeground(QColor("#f85149"))
        elif "[SUCCESS" in text: fmt.setForeground(QColor("#3fb950"))
        elif "[SECURITY]" in text: fmt.setForeground(QColor("#d29922"))
        else: fmt.setForeground(QColor("#c0c0d0"))
        cursor.insertText(text + "\n", fmt)
        self.log.setTextCursor(cursor)
        self.log.ensureCursorVisible()

    @property
    def _config_path(self):
        base = _app_dir()
        try:
            probe = base / ".write_test"
            probe.touch(); probe.unlink()
            return base / "ecu_flasher_config.json"
        except OSError:
            appdata = Path(os.environ.get("APPDATA", Path.home()))
            d = appdata / "ECUFlasher"; d.mkdir(parents=True, exist_ok=True)
            return d / "ecu_flasher_config.json"

    CONFIG_VERSION = 2

    @staticmethod
    def _set_combo(combo, text):
        idx = combo.findText(str(text))
        if idx < 0:
            return False
        combo.setCurrentIndex(idx)
        return True

    def _collect_sim_state(self):
        msgs = {}
        for fid, data in self.dbc_messages.items():
            item = data["item"]
            sigs = {}
            for i in range(item.childCount()):
                s = item.child(i)
                w = self.dbc_tree.itemWidget(s, 1)
                sigs[s.text(0)] = w.currentData() if isinstance(w, QComboBox) else s.text(1)
            msgs[str(fid)] = {
                "checked": item.checkState(0) == Qt.CheckState.Checked,
                "cycle": item.text(3),
                "signals": sigs,
            }
        return msgs

    def _collect_config(self):
        return {
            "version": self.CONFIG_VERSION,
            "app_version": VERSION,
            "saved_at": dt.datetime.now().isoformat(timespec="seconds"),
            "window": {
                "width": self.width(), "height": self.height(),
                "tab": self.tabs.currentIndex(),
                "trace_autoscroll": self.trace_window.autoscroll.isChecked(),
            },
            "can": {
                "interface": self.interface.currentText(),
                "channel": self.channel.currentText(),
                "can_mode": self.can_mode.currentText(),
                "data_bitrate": self.data_bitrate.value(),
            },
            "uds": {
                "txid": self.txid.text(), "rxid": self.rxid.text(), "fid": self.fid.text(),
                "level": self.level.text(),
                "block_size": self.block_size.currentText(),
                "hard_reset": self.hard_reset_check.isChecked(),
                "turn_off_hv": self.hv_check.isChecked(),
            },
            "flash": {
                "repeat": self.repeat_spin.value(),
                "delay": self.delay_spin.value(),
                "stop_on_fail": self.stop_on_fail_check.isChecked(),
            },
            "seedkey": {
                "dll_path": self.dll_path.text(),
                "export": self.dll_export.text(),
                "python32": self.py32_path.text(),
            },
            "firmware": {
                name: {"path": self.file_edits[name].text(),
                       "checked": self.file_checks[name].isChecked()}
                for name in self.file_edits
            },
            "simulation": {
                "dbc_path": self.dbc_path.text(),
                "id_filter": self.dbc_id_filter.text(),
                "ecu": self.ecu_combo.currentText(),
                "e2e": self.chk_e2e.isChecked(),
                "messages": self._collect_sim_state(),
            },
        }

    @staticmethod
    def _migrate_config(d):
        try:
            version = int(d.get("version", 1))
        except (TypeError, ValueError):
            version = 1
        if version >= 2:
            return d
        return {
            "version": 2,
            "can": {k: d[k] for k in ("interface", "channel", "can_mode", "data_bitrate") if k in d},
            "uds": {k: d[k] for k in ("txid", "rxid", "fid", "hard_reset", "turn_off_hv") if k in d},
            "seedkey": {"dll_path": d["seed_key_dll"]} if "seed_key_dll" in d else {},
            "simulation": {"dbc_path": d["dbc_path"]} if "dbc_path" in d else {},
        }

    def _clear_firmware(self, name):
        self.images.pop(name, None)
        self.file_edits[name].setText("")
        self.file_checks[name].setChecked(False)
        self.file_info[name].setText("No file")

    def _clear_dbc(self):
        self.dbc_database = None
        self.dbc_messages.clear()
        self.dbc_tree.clear()
        self.dbc_path.setText("")
        self.ecu_combo.clear()
        self.dbc_start_btn.setEnabled(False)
        self.dbc_status.setText("NOT RUNNING")
        self.dbc_status.setProperty("role", "warn")
        self.dbc_status.style().polish(self.dbc_status)

    def _apply_sim_state(self, msgs):
        if not isinstance(msgs, dict):
            return
        for key, st in msgs.items():
            try:
                fid = int(key)
            except (TypeError, ValueError):
                continue
            data = self.dbc_messages.get(fid)
            if data is None or not isinstance(st, dict):
                continue
            item = data["item"]
            item.setCheckState(0, Qt.CheckState.Checked if st.get("checked") else Qt.CheckState.Unchecked)
            if st.get("cycle") not in (None, ""):
                item.setText(3, str(st["cycle"]))
            saved = st.get("signals") or {}
            for i in range(item.childCount()):
                s = item.child(i)
                name = s.text(0)
                if name not in saved:
                    continue
                w = self.dbc_tree.itemWidget(s, 1)
                if isinstance(w, QComboBox):
                    idx = w.findData(saved[name])
                    if idx >= 0:
                        w.setCurrentIndex(idx)
                else:
                    s.setText(1, str(saved[name]))

    def _apply_config(self, d):
        if self.thread is not None:
            raise RuntimeError("Cannot load configuration while flashing")
        d = self._migrate_config(d)

        try:
            win = d.get("window", {})
            tab = win.get("tab")
            if isinstance(tab, int) and 0 <= tab < self.tabs.count():
                self.tabs.setCurrentIndex(tab)
            if "trace_autoscroll" in win:
                self.trace_window.autoscroll.setChecked(bool(win["trace_autoscroll"]))
        except Exception as e:
            self.log_line(f"[WARN][CONFIG] window: {e}")

        try:
            c = d.get("can", {})
            if self.bus is not None:
                if c:
                    self.log_line("[CONFIG] CAN is connected - adapter/channel/mode settings were not changed")
            else:
                iface = c.get("interface")
                if iface:
                    if iface != self.interface.currentText():
                        self.interface.blockSignals(True)
                        found = self._set_combo(self.interface, iface)
                        self.interface.blockSignals(False)
                        if found:
                            self._adapter_changed(self.interface.currentText())
                        else:
                            self.log_line(f"[WARN][CONFIG] Unknown adapter: {iface}")
                if c.get("channel") and not self._set_combo(self.channel, c["channel"]):
                    self.log_line(f"[WARN][CONFIG] Channel not found: {c['channel']}")
                if c.get("can_mode"):
                    self._set_combo(self.can_mode, c["can_mode"])
                if "data_bitrate" in c:
                    self.data_bitrate.setValue(int(c["data_bitrate"]))
        except Exception as e:
            self.log_line(f"[WARN][CONFIG] can: {e}")

        try:
            u = d.get("uds", {})
            for key, edit in (("txid", self.txid), ("rxid", self.rxid),
                              ("fid", self.fid), ("level", self.level)):
                if key in u:
                    edit.setText(str(u[key]))
            if "block_size" in u:
                self._set_combo(self.block_size, u["block_size"])
            if "hard_reset" in u:
                self.hard_reset_check.setChecked(bool(u["hard_reset"]))
            if "turn_off_hv" in u:
                self.hv_check.setChecked(bool(u["turn_off_hv"]))
        except Exception as e:
            self.log_line(f"[WARN][CONFIG] uds: {e}")

        try:
            fl = d.get("flash", {})
            if "repeat" in fl:
                self.repeat_spin.setValue(int(fl["repeat"]))
            if "delay" in fl:
                self.delay_spin.setValue(int(fl["delay"]))
            if "stop_on_fail" in fl:
                self.stop_on_fail_check.setChecked(bool(fl["stop_on_fail"]))
        except Exception as e:
            self.log_line(f"[WARN][CONFIG] flash: {e}")

        try:
            s = d.get("seedkey", {})
            if "export" in s:
                self.dll_export.setText(str(s["export"]) or "GenerateKeyEx")
            if "python32" in s:
                self.py32_path.setText(str(s["python32"]))
            if "dll_path" in s:
                dll = str(s["dll_path"] or "")
                if dll and Path(dll).is_file():
                    self._set_dll(dll)
                else:
                    self.dll_path.setText(dll)
                    if dll:
                        self.log_line(f"[WARN][CONFIG] Seed-Key DLL not found: {dll}")
        except Exception as e:
            self.log_line(f"[WARN][CONFIG] seedkey: {e}")

        fw = d.get("firmware")
        if isinstance(fw, dict):
            for name in self.file_edits:
                try:
                    entry = fw.get(name) or {}
                    path = str(entry.get("path", "") or "")
                    if path and Path(path).is_file():
                        self._load_firmware(name, path, checked=bool(entry.get("checked", True)))
                    else:
                        self._clear_firmware(name)
                        if path:
                            self.log_line(f"[WARN][CONFIG] {name} file not found: {path}")
                except Exception as e:
                    self.log_line(f"[WARN][CONFIG] firmware {name}: {e}")

        try:
            sim = d.get("simulation")
            if isinstance(sim, dict):
                if self.sim_worker is not None:
                    self.stop_sim()
                if "e2e" in sim:
                    self.chk_e2e.setChecked(bool(sim["e2e"]))
                self.dbc_id_filter.setText(str(sim.get("id_filter", "")))
                dbc = str(sim.get("dbc_path", "") or "")
                if dbc and Path(dbc).is_file():
                    if self._load_dbc(dbc):
                        self._apply_sim_state(sim.get("messages"))
                        if sim.get("ecu"):
                            self._set_combo(self.ecu_combo, sim["ecu"])
                else:
                    self._clear_dbc()
                    if dbc:
                        self.log_line(f"[WARN][CONFIG] DBC file not found: {dbc}")
        except Exception as e:
            self.log_line(f"[WARN][CONFIG] simulation: {e}")

    def _write_config_file(self, path):
        path = Path(path)
        text = json.dumps(self._collect_config(), indent=2, ensure_ascii=False, default=str)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)

    @staticmethod
    def _read_config_file(path):
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(d, dict):
            raise ValueError("Config root must be a JSON object")
        return d

    def save_config_as(self):
        default = str(self._config_path.parent / "ecu_flasher_profile.json")
        path, _ = QFileDialog.getSaveFileName(self, "Save configuration", default, "JSON (*.json)")
        if not path:
            return
        if not path.lower().endswith(".json"):
            path += ".json"
        try:
            self._write_config_file(path)
            self.log_line(f"[CONFIG] Saved {path}")
        except Exception as e:
            self.log_line(f"[ERROR][CONFIG] Save failed: {e}")

    def load_config_from(self):
        if self.thread is not None:
            self.log_line("[ERROR][CONFIG] Cannot load configuration while flashing")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Load configuration",
                                              str(self._config_path.parent), "JSON (*.json)")
        if not path:
            return
        try:
            self._apply_config(self._read_config_file(path))
            self.log_line(f"[CONFIG] Loaded {path}")
        except Exception as e:
            self.log_line(f"[ERROR][CONFIG] Load failed: {e}")

    def _save_config(self):
        try:
            self._write_config_file(self._config_path)
        except Exception as e:
            self.log_line(f"[WARN][CONFIG] Save failed: {e}")

    def _load_config(self):
        path = self._config_path
        if not path.exists():
            return
        try:
            self._apply_config(self._read_config_file(path))
        except Exception as e:
            self.log_line(f"[WARN][CONFIG] Load failed: {e}")

    def closeEvent(self, event):
        self._save_config()
        if self.sim_worker is not None:
            self.sim_worker.stop()
            self.sim_worker.wait(1000)
        if self.vecu_worker is not None:
            self.vecu_worker.stop()
            self.vecu_worker.wait(1000)
        if self.worker is not None: self.worker.stop()
        if self.thread is not None: self.thread.quit(); self.thread.wait(5000)
        try:
            if self.bus is not None: self.bus.shutdown()
        except Exception: pass
        super().closeEvent(event)

def _ensure_vendor_dlls():
    base = _resource_dir() if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    dirs = [base, base / "vendor" / "vector", base / "vendor" / "pcan", base / "vendor"]
    for d in dirs:
        if d.is_dir() and hasattr(os, "add_dll_directory"):
            try: os.add_dll_directory(str(d))
            except OSError: pass

def main():
    _ensure_vendor_dlls()
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
'''

# ============================================================
# 3. seedkey_bridge.py
# ============================================================
FILES["seedkey_bridge.py"] = r'''"""Entry point 32-bit cho Seed-Key bridge."""
import sys

if __name__ == "__main__":
    from uds_core import _seedkey_cli
    if len(sys.argv) > 1 and sys.argv[1] == "--seedkey-once":
        sys.exit(_seedkey_cli(sys.argv[2:]))
    sys.stderr.write("Usage: ECUFlasher32.exe --seedkey-once <dll> <export> <level> <seedhex>\n")
    sys.exit(1)
'''

# ============================================================
# 4. rthook_vendor_dlls.py
# ============================================================
FILES["rthook_vendor_dlls.py"] = r'''"""Runtime hook: đảm bảo DLL bundle được tìm thấy."""
import os
import sys
from pathlib import Path

def _add(path):
    if not path.is_dir(): return
    if hasattr(os, "add_dll_directory"):
        try: os.add_dll_directory(str(path))
        except OSError: pass
    cur = os.environ.get("PATH", "")
    s = str(path)
    if s not in cur.split(os.pathsep):
        os.environ["PATH"] = s + os.pathsep + cur

def _install():
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    else:
        base = Path(__file__).resolve().parent
    _add(base)
    for sub in ("vendor/vector", "vendor/pcan", "vendor"):
        _add(base / sub)

_install()
'''

# ============================================================
# 4b. app_version.py / build_version.py
# ============================================================
FILES["app_version.py"] = r'''"""
app_version.py - single source of truth for the application version.
"""
APP_NAME = "UDS ECU Flasher"
COMPANY = "YourCompany"
VERSION = "1.0.0"
'''

FILES["build_version.py"] = r'''"""
build_version.py - version management for ECUFlasher builds.

  python build_version.py --show
  python build_version.py --print
  python build_version.py --print-full
  python build_version.py --bump patch
  python build_version.py --set 1.4.0
  python build_version.py --build
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import runpy
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION_FILE = ROOT / "app_version.py"
BUILD_NUMBER_FILE = ROOT / "build_number.txt"
BUILD_INFO_FILE = ROOT / "_build_info.py"
VERSION_INFO_FILE = ROOT / "version_info.txt"
GENERATED = {BUILD_NUMBER_FILE.name, BUILD_INFO_FILE.name, VERSION_INFO_FILE.name}

_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_VERSION_LINE = re.compile(r'^(VERSION\s*=\s*)(["\'])([^"\']*)\2', re.M)

def fail(msg):
    print(f"[VERSION][ERROR] {msg}", file=sys.stderr)
    sys.exit(1)

def _drop_pyc(path):
    for pyc in (ROOT / "__pycache__").glob(f"{path.stem}.*.pyc"):
        try:
            pyc.unlink()
        except OSError:
            pass

def read_meta():
    ns = runpy.run_path(str(VERSION_FILE))
    version = str(ns.get("VERSION", ""))
    if not _SEMVER.match(version):
        fail(f"VERSION in {VERSION_FILE.name} must look like 1.2.3, got {version!r}")
    return str(ns.get("APP_NAME", "ECUFlasher")), str(ns.get("COMPANY", "")), version

def set_version(new):
    if not _SEMVER.match(new):
        fail(f"version must look like 1.2.3, got {new!r}")
    text = VERSION_FILE.read_text(encoding="utf-8")
    text, count = _VERSION_LINE.subn(lambda m: f'{m.group(1)}"{new}"', text)
    if count != 1:
        fail(f"could not find a single VERSION = \"...\" line in {VERSION_FILE.name}")
    VERSION_FILE.write_text(text, encoding="utf-8")
    _drop_pyc(VERSION_FILE)

def bump(part):
    major, minor, patch = (int(x) for x in read_meta()[2].split("."))
    if part == "major":
        major, minor, patch = major + 1, 0, 0
    elif part == "minor":
        minor, patch = minor + 1, 0
    else:
        patch += 1
    return f"{major}.{minor}.{patch}"

def read_build_number():
    try:
        return int(BUILD_NUMBER_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0

def _git(*args):
    try:
        r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None

def git_info():
    commit = _git("rev-parse", "--short=8", "HEAD")
    if not commit:
        return "", False
    dirty = False
    for line in (_git("status", "--porcelain") or "").splitlines():
        path = Path(line[3:].strip().strip('"'))
        if path.name in GENERATED or {"build", "dist", "__pycache__"} & set(path.parts):
            continue
        dirty = True
        break
    return commit, dirty

def read_build_info():
    try:
        info = runpy.run_path(str(BUILD_INFO_FILE)).get("BUILD_INFO", {})
    except Exception:
        return {}
    return info if info.get("version") == read_meta()[2] else {}

def format_full(version, info):
    if not info.get("build"):
        return f"{version} (dev)"
    parts = [f"build {info['build']}", str(info.get("date", ""))[:16]]
    if info.get("commit"):
        parts.append(info["commit"] + ("+" if info.get("dirty") else ""))
    return f"{version} ({', '.join(p for p in parts if p)})"

def write_build_info(version, build, date, commit, dirty):
    BUILD_INFO_FILE.write_text(
        "# Auto-generated by build_version.py - do not edit.\n"
        "BUILD_INFO = {\n"
        f"    \"version\": {version!r},\n"
        f"    \"build\": {build},\n"
        f"    \"date\": {date!r},\n"
        f"    \"commit\": {commit!r},\n"
        f"    \"dirty\": {dirty},\n"
        "}\n",
        encoding="utf-8",
    )
    _drop_pyc(BUILD_INFO_FILE)

def write_version_info(name, company, version, build):
    major, minor, patch = (int(x) for x in version.split("."))
    b = build % 65536
    VERSION_INFO_FILE.write_text(
        "VSVersionInfo(\n"
        "  ffi=FixedFileInfo(\n"
        f"    filevers=({major}, {minor}, {patch}, {b}),\n"
        f"    prodvers=({major}, {minor}, {patch}, {b}),\n"
        "    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,\n"
        "    date=(0, 0)\n"
        "  ),\n"
        "  kids=[\n"
        "    StringFileInfo([\n"
        "      StringTable('040904B0', [\n"
        f"        StringStruct('CompanyName', {company!r}),\n"
        f"        StringStruct('FileDescription', {name!r}),\n"
        f"        StringStruct('FileVersion', {f'{version}.{b}'!r}),\n"
        "        StringStruct('InternalName', 'ECUFlasher'),\n"
        "        StringStruct('OriginalFilename', 'ECUFlasher.exe'),\n"
        f"        StringStruct('ProductName', {name!r}),\n"
        f"        StringStruct('ProductVersion', {version!r}),\n"
        "      ])\n"
        "    ]),\n"
        "    VarFileInfo([VarStruct('Translation', [1033, 1200])])\n"
        "  ]\n"
        ")\n",
        encoding="utf-8",
    )

def do_build():
    name, company, version = read_meta()
    build = read_build_number() + 1
    commit, dirty = git_info()
    date = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    BUILD_NUMBER_FILE.write_text(f"{build}\n", encoding="utf-8")
    write_build_info(version, build, date, commit, dirty)
    write_version_info(name, company, version, build)
    info = {"build": build, "date": date, "commit": commit, "dirty": dirty}
    print(f"[VERSION] {name} {format_full(version, info)}")

def main():
    ap = argparse.ArgumentParser(description="ECUFlasher version management")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--print", dest="print_version", action="store_true")
    ap.add_argument("--print-full", action="store_true")
    ap.add_argument("--bump", choices=("major", "minor", "patch"))
    ap.add_argument("--set", dest="set_version", metavar="X.Y.Z")
    ap.add_argument("--build", action="store_true")
    args = ap.parse_args()

    if args.bump and args.set_version:
        fail("use either --bump or --set, not both")
    if args.set_version or args.bump:
        old = read_meta()[2]
        new = args.set_version or bump(args.bump)
        set_version(new)
        print(f"[VERSION] {old} -> {new}")
    if args.build:
        do_build()
    if args.print_version:
        print(read_meta()[2])
    if args.print_full:
        print(format_full(read_meta()[2], read_build_info()))
    if args.show or not (args.set_version or args.bump or args.build or args.print_version or args.print_full):
        name, _, version = read_meta()
        print(f"{name} {format_full(version, read_build_info())}")

if __name__ == "__main__":
    main()
'''

# ============================================================
# 5. requirements.txt
# ============================================================
FILES["requirements.txt"] = """python-can>=4.3.0
cantools>=39.0.0
PySide6-Essentials>=6.6.0
pyinstaller>=6.3.0
"""

# ============================================================
# 6. build.spec
# ============================================================
FILES["build.spec"] = r'''# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path

ROOT = Path(SPECPATH)

binaries = []
for src, dst in (
    ("vendor/vector/vxlapi64.dll", "."),
    ("vendor/vector/vxlapi.dll", "."),
    ("vendor/pcan/PCANBasic.dll", "."),
    ("vendor/pcan/PCANBasic_x64.dll", "."),
):
    p = ROOT / src
    if p.is_file(): binaries.append((str(p), dst))

datas = []

hiddenimports = [
    "can.interfaces.vector",
    "can.interfaces.pcan",
    "can.interfaces.virtual",
]

excludes = [
    "numpy", "asammdf", "yaml", "scipy", "pandas", "matplotlib", "PIL", "IPython", "pytest",
    "setuptools", "pkg_resources", "pip", "wheel", "distutils", "lib2to3",
    "unittest", "doctest", "pydoc", "test", "idlelib", "turtle", "tkinter",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
    "PySide6.QtWebChannel", "PySide6.QtWebSockets", "PySide6.QtWebView",
    "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.Qt3DInput", "PySide6.Qt3DLogic",
    "PySide6.Qt3DAnimation", "PySide6.Qt3DExtras",
    "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtQuickWidgets", "PySide6.QtQuick3D",
    "PySide6.QtQuickControls2", "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
    "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtGraphs",
    "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtUiTools",
    "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets",
    "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    "PySide6.QtSql", "PySide6.QtTest",
    "PySide6.QtBluetooth", "PySide6.QtNfc", "PySide6.QtPositioning", "PySide6.QtLocation",
    "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtSerialBus",
    "PySide6.QtNetwork", "PySide6.QtNetworkAuth", "PySide6.QtHttpServer",
    "PySide6.QtSvg", "PySide6.QtSvgWidgets", "PySide6.QtPrintSupport",
    "PySide6.QtXml", "PySide6.QtConcurrent", "PySide6.QtRemoteObjects",
    "PySide6.QtScxml", "PySide6.QtStateMachine", "PySide6.QtTextToSpeech",
    "PySide6.QtSpatialAudio", "PySide6.QtAxContainer", "PySide6.QtDBus",
]

a = Analysis(
    ["ecu_flasher_app.py"],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=["rthook_vendor_dlls.py"],
    excludes=excludes,
    noarchive=False,
)

_DROP_LIBS = {
    "opengl32sw", "d3dcompiler_47",
    "qt6pdf", "qt6svg", "qt6network", "qt6opengl", "qt6quick", "qt6qml",
    "qt6qmlmodels", "qt6virtualkeyboard",
}
_KEEP_PLUGINS = {
    "platforms": {"qwindows", "qoffscreen", "qxcb", "qcocoa"},
    "imageformats": set(),
    "styles": None,
}

def _stem(name):
    base = name.rsplit("/", 1)[-1].split(".")[0]
    return base[3:] if base.startswith("lib") else base

def _keep(entry):
    name = str(entry[0]).replace("\\", "/").lower()
    parts = name.split("/")
    stem = _stem(name)
    if stem in _DROP_LIBS:
        return False
    if "pyside6" in parts and "plugins" in parts:
        i = parts.index("plugins")
        if i + 2 < len(parts):
            allowed = _KEEP_PLUGINS.get(parts[i + 1], set())
            if allowed is not None and stem not in allowed:
                return False
    if name.endswith(".qm") and "translations" in parts:
        return False
    return True

def _prune(toc, label):
    kept, dropped = [], []
    for entry in toc:
        (kept if _keep(entry) else dropped).append(entry)
    saved = 0
    for entry in dropped:
        try: saved += os.path.getsize(entry[1])
        except OSError: pass
    print(f"[SIZE] {label}: pruned {len(dropped)} files, {saved / 1048576:.1f} MB")
    return kept

a.binaries = _prune(a.binaries, "binaries")
a.datas = _prune(a.datas, "datas")

pyz = PYZ(a.pure, a.zipped_data)

UPX_EXCLUDE = [
    "vcruntime*.dll", "msvcp*.dll", "ucrtbase.dll", "python3*.dll",
    "Qt6*.dll", "qwindows.dll", "pyside6*.dll", "shiboken6*.dll",
    "vxlapi*.dll", "PCANBasic*.dll",
]

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="ECUFlasher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon="NONE",
    version="version_info.txt",
)

coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False,
    upx=True,
    upx_exclude=UPX_EXCLUDE,
    name="ECUFlasher",
)
'''

# ============================================================
# 7. build32.spec
# ============================================================
FILES["build32.spec"] = r'''# -*- mode: python ; coding: utf-8 -*-
a = Analysis(
    ["seedkey_bridge.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PySide6", "cantools", "numpy", "can", "yaml", "tkinter", "IPython",
        "setuptools", "pkg_resources", "pip", "wheel", "distutils", "lib2to3",
        "unittest", "doctest", "pydoc", "test", "idlelib", "turtle", "curses",
        "ssl", "sqlite3", "xml", "http",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="ECUFlasher32",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    icon="NONE",
)

coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False,
    upx=True,
    upx_exclude=["vcruntime*.dll", "msvcp*.dll", "ucrtbase.dll", "python3*.dll"],
    name="ECUFlasher32",
)
'''

# ============================================================
# 8. version_info.txt
# ============================================================
FILES["version_info.txt"] = r'''VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName', 'YourCompany'),
        StringStruct('FileDescription', 'UDS ECU Flasher'),
        StringStruct('FileVersion', '1.0.0.0'),
        StringStruct('InternalName', 'ECUFlasher'),
        StringStruct('OriginalFilename', 'ECUFlasher.exe'),
        StringStruct('ProductName', 'UDS ECU Flasher'),
        StringStruct('ProductVersion', '1.0.0.0'),
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
'''

# ============================================================
# 9. build_all.bat
# ============================================================
FILES["build_all.bat"] = r'''@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "BUMP=%~1"

echo ==================================================
echo   ECUFlasher Build Script (Optimized Size)
echo ==================================================
echo.

python -c "import struct,sys; assert struct.calcsize('P')*8==64, 'Need 64-bit'" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 64-bit required.
    exit /b 1
)

echo [1/8] Installing dependencies...
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet
if errorlevel 1 exit /b 1

echo [2/8] Checking vendor DLLs and UPX...
set "MISSING=0"
if not exist "vendor\vector\vxlapi64.dll" set "MISSING=1"
if not exist "vendor\pcan\PCANBasic.dll" set "MISSING=1"
if "%MISSING%"=="1" echo [WARN] Missing vendor DLLs. Build continues.
where upx >nul 2>&1 && echo [INFO] UPX found, it will compress safe files. || echo [INFO] UPX not found, extra compression skipped. Optional: https://upx.github.io

echo [3/8] Updating version...
if not "%BUMP%"=="" (
    python build_version.py --bump %BUMP%
    if errorlevel 1 exit /b 1
)
python build_version.py --build
if errorlevel 1 exit /b 1
for /f "usebackq delims=" %%v in (`python build_version.py --print`) do set "APP_VERSION=%%v"

echo [4/8] Cleaning...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [5/8] Building seed-key bridge (32-bit)...
py -3-32 -c "import struct;assert struct.calcsize('P')*8==32" >nul 2>&1
if errorlevel 1 (
    echo [WARN] Python 32-bit not found. Bridge will not be built.
    goto :build_main
)
py -3-32 -m pip install pyinstaller --quiet
py -3-32 -m PyInstaller --clean --noconfirm build32.spec
if errorlevel 1 goto :build_main
echo [OK] Bridge32 built.

:build_main

echo [6/8] Building main EXE (64-bit)...
pyinstaller --clean --noconfirm build.spec
if errorlevel 1 exit /b 1

echo [7/8] Assembling...
if exist dist\ECUFlasher32 (
    if not exist dist\ECUFlasher\bridge32 mkdir dist\ECUFlasher\bridge32
    xcopy /E /I /Y /Q dist\ECUFlasher32\* dist\ECUFlasher\bridge32\ >nul
    rmdir /s /q dist\ECUFlasher32
)

if exist assets\THIRD_PARTY_NOTICES.txt copy /Y /Q assets\THIRD_PARTY_NOTICES.txt dist\ECUFlasher\ >nul
if exist README.md copy /Y /Q README.md dist\ECUFlasher\ >nul
python build_version.py --print-full > dist\ECUFlasher\VERSION.txt

echo [8/8] Packing and reporting size...
powershell -NoProfile -Command "$s=(Get-ChildItem 'dist\ECUFlasher' -Recurse -File | Measure-Object Length -Sum).Sum/1MB; Write-Host ('[SIZE] Folder: {0:N1} MB' -f $s)"
where 7z >nul 2>&1 && (7z a -t7z -mx=9 -bso0 -bsp0 dist\ECUFlasher_v%APP_VERSION%.7z dist\ECUFlasher) || (powershell -NoProfile -Command "Compress-Archive -Path 'dist\ECUFlasher' -DestinationPath 'dist\ECUFlasher_v%APP_VERSION%.zip' -Force")
if exist dist\ECUFlasher_v%APP_VERSION%.7z powershell -NoProfile -Command "Write-Host ('[SIZE] dist\ECUFlasher_v%APP_VERSION%.7z: {0:N1} MB' -f ((Get-Item 'dist\ECUFlasher_v%APP_VERSION%.7z').Length/1MB))"
if exist dist\ECUFlasher_v%APP_VERSION%.zip powershell -NoProfile -Command "Write-Host ('[SIZE] dist\ECUFlasher_v%APP_VERSION%.zip: {0:N1} MB' -f ((Get-Item 'dist\ECUFlasher_v%APP_VERSION%.zip').Length/1MB))"

echo.
echo ==================================================
echo   BUILD COMPLETE - version %APP_VERSION%
echo ==================================================
echo   Output: dist\ECUFlasher\ECUFlasher.exe
echo.
endlocal
'''

# ============================================================
# 10. THIRD_PARTY_NOTICES.txt
# ============================================================
FILES["assets/THIRD_PARTY_NOTICES.txt"] = """ECUFlasher — Third-Party Notices"""

# ============================================================
# 11. README.md
# ============================================================
FILES["README.md"] = r"""# ECUFlasher

## Build

    build_all.bat            build the current version
    build_all.bat patch      1.0.0 -> 1.0.1, then build   (also: minor, major)

The version is stored in `app_version.py`. Every build gets a build number
(`build_number.txt`) and, when the folder is a git repository, the commit hash.
The result is shown in the app header, the window title, the
Windows file properties of `ECUFlasher.exe` and `dist\ECUFlasher\VERSION.txt`.
Running the app from source shows `(dev)` instead of a build number.

Other commands:

    python build_version.py --show
    python build_version.py --set 1.4.0

## Consecutive flashing

On the Flashing tab, `Consecutive runs` repeats the whole flash sequence N times and
`Delay between runs` is the wait before the next run. `Stop on first failure` ends
the series at the first failed run; untick it to continue anyway. Both settings are
saved with the configuration.
"""

def _write_placeholder_dlls():
    for path in (
        "vendor/vector/vxlapi64.dll",
        "vendor/vector/vxlapi.dll",
        "vendor/pcan/PCANBasic.dll",
        "vendor/pcan/PCANBasic_x64.dll",
    ):
        p = ROOT / path
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.with_suffix(p.suffix + ".README.txt").write_text(f"Place {p.name} here.\n", encoding="utf-8")

def main():
    if ROOT.exists():
        print(f"[WARN] {ROOT} already exists. Overwrite? [y/N] ", end="")
        if input().strip().lower() != "y":
            sys.exit(0)
    ROOT.mkdir(parents=True, exist_ok=True)

    for name, content in FILES.items():
        p = ROOT / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        print(f"  wrote {name}")

    _write_placeholder_dlls()

    print("\nProject created:", ROOT)
    print("Next: Copy vendor DLLs and run build_all.bat")

if __name__ == "__main__":
    main()