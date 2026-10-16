#!/usr/bin/env python3
"""Общий модуль диагностических скриптов термостенда.

Что умеет (только стандартная библиотека, без зависимостей):
  - читать PCAP classic (все эндианы, usec/nsec) и PCAPNG (SHB/IDB/EPB/SPB);
  - писать PCAP classic и PCAPNG (одна секция, один интерфейс, usec);
  - разбирать Ethernet + IPv4 (без фрагментации, как в кейсе) + TCP;
  - считать и чинить IP/TCP-чексуммы;
  - собирать направленные TCP-потоки по sequence numbers с явными
    гэпами и перекрытиями (никаких догадок: дырка остаётся дыркой);
  - резать поток на кадры A6 5C и декодировать запросы/ответы/измерения;
  - грузить action_journal.csv и выбирать строки записи.

Контракт термостенда (выведено из research/03_combined_messages.pcap):
  запрос клиента:  A6 5C | 00 CMD 00 ID | тело
      CMD 00 = read-config (тело 00 10), 01 = read-values (тело 00 30 COUNT),
      0B = set-config (тело 00 20 КОНФИГ)
  конфиг:          ENA(1) | PERIOD u16BE мс | THRESH i16BE сотые °C | LABLEN(1) | метка
  ответ сервера:   A6 5C | LEN u16BE = длина_кадра-8 | SEQ | 01 CMD' 00 | данные
      CMD' 20 = конфиг (эхо), 30 = измерения
  измерение (7 Б): TIME u32BE мс | TEMP i16BE сотые °C | ALARM u8
"""

import csv
import json
import struct
import sys
from pathlib import Path

# Каталог набора: diagnostics/ -> fixtures/. Все пути считаются от него,
# абсолютных путей в скриптах нет (R5: переносимость).
# Если скрипты запускают не из набора (копия в другом месте) — указать явно:
#   PL_FIXTURES=/путь/к/fixtures python3 08_bad_checksum.py
import os as _os

FIXTURES_DIR = Path(_os.environ['PL_FIXTURES']) if _os.environ.get('PL_FIXTURES') else Path(__file__).resolve().parent.parent
BASE_CAPTURE = 'research/03_combined_messages.pcap'
JOURNAL_NAME = 'action_journal.csv'

CLIENT_IP = (10, 77, 0, 10)
SERVER_IP = (10, 77, 0, 20)
SERVER_PORT = 46123


# --------------------------------------------------------------------------
# PCAP classic
# --------------------------------------------------------------------------

class PcapRecord:
    """Один кадр захвата: метка времени (мкс), байты линка, длины."""

    __slots__ = ('ts_us', 'data', 'incl_len', 'orig_len')

    def __init__(self, ts_us, data, incl_len, orig_len):
        self.ts_us = ts_us
        self.data = data
        self.incl_len = incl_len
        self.orig_len = orig_len

    @property
    def truncated(self):
        return self.incl_len < self.orig_len


def read_classic(path):
    """Читает PCAP classic. Возвращает (records, {'endian', 'nsec'})."""
    blob = Path(path).read_bytes()
    magic = blob[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        endian, nsec = '<', False
    elif magic == b'\xa1\xb2\xc3\xd4':
        endian, nsec = '>', False
    elif magic == b'\x4d\x3c\xb2\xa1':
        endian, nsec = '<', True
    elif magic == b'\xa1\xb2\x3c\x4d':
        endian, nsec = '>', True
    else:
        raise ValueError(f'не PCAP classic: {path}')
    off = 24
    out = []
    while off + 16 <= len(blob):
        ts_sec, ts_frac, incl, orig = struct.unpack(endian + 'IIII', blob[off:off + 16])
        off += 16
        data = blob[off:off + incl]
        off += incl
        frac = ts_frac if not nsec else ts_frac // 1000
        out.append(PcapRecord(ts_sec * 1_000_000 + frac, bytes(data), incl, orig))
    return out, {'endian': endian, 'nsec': nsec}


def write_classic(path, records):
    """Пишет PCAP classic, LE, usec. Усечения (incl<orig) сохраняет как есть."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for r in records:
            sec, usec = divmod(r.ts_us, 1_000_000)
            f.write(struct.pack('<IIII', sec, usec, r.incl_len, r.orig_len))
            f.write(r.data)


# --------------------------------------------------------------------------
# PCAPNG (минимум для кейса: SHB + IDB + EPB/SPB, usec)
# --------------------------------------------------------------------------

def read_pcapng(path):
    """Читает PCAPNG. Возвращает (records, {'resolutions': [...]})."""
    blob = Path(path).read_bytes()
    if blob[:4] != b'\x0a\x0d\x0d\x0a':
        raise ValueError(f'не PCAPNG: {path}')
    endian = '<'
    off = 0
    out = []
    resolutions = []
    ts_mul = 1  # множитель к микросекундам
    while off + 12 <= len(blob):
        btype, blen = struct.unpack(endian + 'II', blob[off:off + 8])
        if blen < 12 or off + blen > len(blob):
            break
        body = blob[off + 8:off + blen - 4]
        if btype == 0x0A0D0D0A and len(body) >= 12:  # SHB
            bom = struct.unpack('<I', body[0:4])[0]
            if bom == 0x1A2B3C4D:
                endian = '<'
            elif bom == 0x4D3C2B1A:
                endian = '>'
            else:
                break  # битый SHB — дальше не идём, молчать не будем ниже
        elif btype == 0x00000001:  # IDB
            if len(body) >= 8:
                tsresol = body[8]
                exp = tsresol & 0x7F
                msb = bool(tsresol & 0x80)
                base = 2 if msb else 10
                # сколько единиц разрешения в микросекунде
                units_per_us = base ** exp / 1_000_000
                resolutions.append(units_per_us)
                ts_mul = units_per_us
        elif btype == 0x00000006 and len(body) >= 20:  # EPB
            _if, ts_high, ts_low, caplen, origlen = struct.unpack(endian + 'IIIII', body[:20])
            ts = ((ts_high << 32) | ts_low)
            ts_us = int(ts / ts_mul) if ts_mul else ts
            out.append(PcapRecord(ts_us, bytes(body[20:20 + caplen]), caplen, origlen))
        elif btype == 0x00000003 and len(body) >= 4:  # SPB
            (origlen,) = struct.unpack(endian + 'I', body[:4])
            data = body[4:]
            # паддинг до 32 бит
            caplen = min(len(data), origlen)
            out.append(PcapRecord(0, bytes(data[:caplen]), caplen, origlen))
        off += ((blen + 3) // 4) * 4
    return out, {'resolutions': resolutions}


def write_pcapng(path, records):
    """Пишет PCAPNG: SHB + один IDB (Ethernet, usec) + EPB на запись."""
    with open(path, 'wb') as f:
        shb_body = struct.pack('<IIQQI', 0x1A2B3C4D, 1, 0, 0, 0)
        shb_len = 12 + len(shb_body)
        f.write(struct.pack('<II', 0x0A0D0D0A, shb_len) + shb_body
                + struct.pack('<I', shb_len))
        idb_body = struct.pack('<HHI', 1, 0, 0)  # Ethernet, usec
        idb_len = 12 + len(idb_body)
        f.write(struct.pack('<II', 1, idb_len) + idb_body + struct.pack('<I', idb_len))
        for r in records:
            epb = struct.pack('<IIIII', 0, (r.ts_us >> 32) & 0xFFFFFFFF,
                              r.ts_us & 0xFFFFFFFF, r.incl_len, r.orig_len)
            epb += r.data
            pad = (-len(epb)) % 4
            epb += b'\x00' * pad
            total = 12 + len(epb)
            f.write(struct.pack('<II', 6, total) + epb + struct.pack('<I', total))


def read_any(path):
    """Читает PCAP или PCAPNG — по магии. Возвращает (records, meta)."""
    with open(path, 'rb') as f:
        magic = f.read(4)
    if magic == b'\x0a\x0d\x0d\x0a':
        return read_pcapng(path)
    return read_classic(path)


# --------------------------------------------------------------------------
# IPv4 / TCP
# --------------------------------------------------------------------------

def ip_checksum(header):
    s = sum(struct.unpack('!%dH' % (len(header) // 2), header))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_checksum(src, dst, tcp):
    pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(tcp))
    data = pseudo + tcp
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


class TcpPacket:
    """Разобранный TCP-пакет (без опций в리스овании не нуждается — кейс без них,
    но data offset читаем честно)."""

    __slots__ = ('ts_us', 'index', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
                 'seq', 'ack', 'flags', 'payload', 'ip_ok', 'tcp_ok',
                 'ip_total', 'tcp_doff')

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def syn(self):
        return bool(self.flags & 0x02)

    @property
    def fin(self):
        return bool(self.flags & 0x01)

    @property
    def rst(self):
        return bool(self.flags & 0x04)

    def direction(self):
        """'c2s' если отправитель — клиент стенда, иначе 's2c'."""
        if tuple(self.src_ip) == CLIENT_IP:
            return 'c2s'
        if tuple(self.dst_ip) == CLIENT_IP:
            return 's2c'
        return 'other'


def parse_tcp(rec, index):
    """Разбирает кадр Ethernet+IPv4+TCP. Возвращает TcpPacket или None."""
    buf = rec.data
    if len(buf) < 14:
        return None
    ip = buf[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack('!H', ip[2:4])[0]
    if len(ip) < total:
        return None  # обрезан ниже IP — не наш случай, такое помечаем отдельно
    src_ip = tuple(ip[12:16])
    dst_ip = tuple(ip[16:20])
    ip_ok = ip_checksum(ip[:ihl]) == 0
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        return None
    sport, dport = struct.unpack('!HH', tcp[:4])
    (seq,) = struct.unpack('!I', tcp[4:8])
    (ack,) = struct.unpack('!I', tcp[8:12])
    doff = (tcp[12] >> 4) * 4
    flags = tcp[13]
    payload = bytes(tcp[doff:])
    tcp_ok = tcp_checksum(src_ip, dst_ip, tcp) == 0
    return TcpPacket(ts_us=rec.ts_us, index=index, src_ip=src_ip, src_port=sport,
                     dst_ip=dst_ip, dst_port=dport, seq=seq, ack=ack, flags=flags,
                     payload=payload, ip_ok=ip_ok, tcp_ok=tcp_ok,
                     ip_total=total, tcp_doff=doff)


def build_tcp(ts_us, src_ip, src_port, dst_ip, dst_port, seq, ack, flags,
              payload, fix_checksums=True):
    """Собирает кадр Ethernet+IPv4+TCP с корректными длинами и чексуммами."""
    eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01' + struct.pack('!H', 0x0800)
    total = 20 + 20 + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0x4000, 64, 6, 0,
                     bytes(src_ip), bytes(dst_ip))
    ip = ip[:10] + struct.pack('!H', ip_checksum(ip)) + ip[12:]
    tcp = struct.pack('!HHIIBBHHH', src_port, dst_port, seq & 0xFFFFFFFF,
                      ack & 0xFFFFFFFF, 0x50, flags, 64240, 0, 0)
    if fix_checksums:
        csum = tcp_checksum(src_ip, dst_ip, tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', csum) + tcp[18:]
    return PcapRecord(ts_us, eth + ip + tcp + bytes(payload),
                      14 + total, 14 + total)


# --------------------------------------------------------------------------
# Потоки: сборка по sequence numbers
# --------------------------------------------------------------------------

class Gap:
    def __init__(self, start_seq, length):
        self.start_seq = start_seq
        self.length = length


class Overlap:
    def __init__(self, start_seq, first, second, identical):
        self.start_seq = start_seq
        self.first = first      # байты первого варианта
        self.second = second    # байты второго варианта
        self.identical = identical


def reassemble(packets, policy='latest'):
    """Собирает поток из пакетов одного направления по seq.

    policy: 'latest' — при перекрытии побеждает поздний пакет,
            'first' — ранний. Одинаковые перекрытия схлопываются молча,
    конфликтующие и гэпы возвращаются явно — никаких догадок в байтах.
    Возвращает (stream, gaps, overlaps).
    """
    chunks = sorted(
        ((p.seq, bytes(p.payload), p.index) for p in packets if p.payload),
        key=lambda c: (c[0], c[2]),
    )
    if not chunks:
        return b'', [], []
    base = chunks[0][0]
    stream = bytearray()
    gaps, overlaps = [], []

    def ensure_end(pos):
        if pos > len(stream):
            gaps.append(Gap(base + len(stream), pos - len(stream)))
            stream.extend(b'\x00' * (pos - len(stream)))

    for seq, data, _idx in chunks:
        pos = seq - base
        if pos < 0:
            # Старые дубли из эпохи до начала (редкость) — обрезаем слева.
            data = data[-pos:]
            pos = 0
            if not data:
                continue
        ensure_end(pos)
        cur = bytes(stream[pos:pos + len(data)])
        if cur == data:
            continue  # одинаковая ретрансмиссия — схлопываем молча
        if any(cur):
            # Поверх реальных байтов легли другие — конфликт. Нули здесь
            # бывают только от ensure_end (заглушка гэпа), их не считаем.
            overlaps.append(Overlap(base + pos, cur, data, identical=False))
        if policy == 'latest' or not any(cur):
            stream[pos:pos + len(data)] = data
        # при policy='first' занятые байты не трогаем, но факт фиксируем выше
    return bytes(stream), gaps, overlaps


# --------------------------------------------------------------------------
# Кадры A6 5C и декодер термостенда
# --------------------------------------------------------------------------

def split_a65c(stream):
    """Режет поток на кадры по магии A6 5C. Возвращает [(offset, body)].

    body — байты после магии. Хвост без магии и мусор до первой магии
    возвращаются как есть вызывателю не нужны — здесь только целые кадры.
    """
    out = []
    start = 0
    while True:
        at = stream.find(b'\xa6\x5c', start)
        if at < 0:
            break
        nxt = stream.find(b'\xa6\x5c', at + 2)
        end = nxt if nxt >= 0 else len(stream)
        out.append((at, stream[at + 2:end]))
        start = end
    return out


def decode_config(data):
    """Конфиг: ENA | PERIOD u16BE | THRESH i16BE/100 | LABLEN | метка."""
    if len(data) < 6:
        return None
    lablen = data[5]
    label = data[6:6 + lablen]
    if len(label) < lablen:
        return None  # обрезан (привет, missing_segment)
    return {
        'enabled': bool(data[0]),
        'period_ms': struct.unpack('!H', data[1:3])[0],
        'threshold_c': struct.unpack('!h', data[3:5])[0] / 100.0,
        'label': label.decode('utf-8', errors='replace'),
    }


def decode_measurements(data):
    """Серия замеров по 7 Б: TIME u32BE | TEMP i16BE/100 | ALARM."""
    out = []
    for off in range(0, len(data) // 7 * 7, 7):
        chunk = data[off:off + 7]
        out.append({
            'device_time_ms': struct.unpack('!I', chunk[0:4])[0],
            'temperature_c': struct.unpack('!h', chunk[4:6])[0] / 100.0,
            'alarm': bool(chunk[6]),
        })
    tail = len(data) % 7
    return out, tail


# --------------------------------------------------------------------------
# Журнал и сверка
# --------------------------------------------------------------------------

def load_journal_rows(capture_subpath):
    """Строки журнала для записи (capture — путь относительно fixtures/)."""
    path = FIXTURES_DIR / JOURNAL_NAME
    with open(path, encoding='utf-8') as f:
        rows = [r for r in csv.DictReader(f) if r['capture'] == capture_subpath]
    for r in rows:
        r['parameters'] = json.loads(r['parameters'])
        r['observed_result'] = json.loads(r['observed_result'])
    return rows


def load_base():
    """Базовая запись research/03: разобранные TCP-пакеты."""
    return load_capture('research/../' + BASE_CAPTURE)


def load_capture(name):
    """Разобранные TCP-пакеты записи fixtures/<name>. None — кадр не TCP."""
    if name.startswith('research/../'):
        name = name.split('/', 2)[-1]
    records, _meta = read_any(FIXTURES_DIR / name)
    return [parse_tcp(r, i) for i, r in enumerate(records)]


def check(cond, ok_text, fail_text):
    """Печатает [OK]/[FAIL] и возвращает bool. Мелочь, а приятно."""
    print(('  [OK] ' if cond else '  [FAIL] ') + (ok_text if cond else fail_text))
    return cond


def main_guard(name):
    """Заготовка main'а скриптов: verify по умолчанию, --regen для сборки."""
    regen = '--regen' in sys.argv
    out = None
    for a in sys.argv[1:]:
        if a.startswith('--out='):
            out = a[len('--out='):]
    return regen, out
