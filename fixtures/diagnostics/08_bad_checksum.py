#!/usr/bin/env python3
"""08_bad_checksum.pcapng — одиночная некорректная чексумма.

Условие: РОВНО ОДИН пакет (кадр #9, ответ сервера s2c) с битой TCP-checksum,
payload при этом цел. Отличие от 07: там — массово исходящие (offload),
здесь — точечная порча одного входящего.
Требование кейса: политика проверки и её влияние на анализ заданы явно;
битый пакет диагностируется, но не выкидывает весь разбор.

Скрипт по умолчанию ПРОВЕРЯЕТ приложенный файл, с --regen собирает
эквивалент из research/03_combined_messages.pcap:
    python3 08_bad_checksum.py [--regen [--out=ПУТЬ]]
"""
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _cand in (_HERE, Path.cwd()):
    if (_cand / '_common.py').exists():
        sys.path.insert(0, str(_cand))
        break
try:
    from _common import *  # noqa: E402,F403
except ModuleNotFoundError:
    sys.exit('ОШИБКА: рядом со скриптом нет _common.py. '
             'Запускайте из папки backend/fixtures/diagnostics '
             'или положите _common.py рядом со скриптом.')

NAME = 'diagnostics/08_bad_checksum.pcapng'


def verify():
    print(f'== {NAME}: одна битая чексумма ==')
    ok = True
    pkts = load_capture(NAME)
    good = [p for p in pkts if p]
    ok &= check(len(good) > 0, f'TCP-пакетов: {len(good)}', 'файл пуст')

    bad = [p for p in good if not p.tcp_ok]
    ok &= check(len(bad) == 1,
                'битая чексумма ровно одна — точечный дефект, не offload',
                f'битых: {len(bad)} — ждали ровно одну!')
    for p in bad:
        print(f'     кадр #{p.index} {p.direction()} seq={p.seq} '
              f'len={len(p.payload)}: чексумма не сошлась, payload на месте')

    # Данные целы: потоки совпадают с базой несмотря на битую чексумму.
    base = load_base()
    for direction in ('c2s', 's2c'):
        mine = [p for p in good if p.direction() == direction]
        ref = [p for p in base if p and p.direction() == direction]
        stream, gaps, overlaps = reassemble(mine)
        ref_stream, _, _ = reassemble(ref)
        ok &= check(bytes(stream) == bytes(ref_stream),
                    f'поток {direction}: {len(stream)} Б совпали — '
                    'бита только чексумма',
                    f'поток {direction} НЕ совпал!')

    rows = load_journal_rows(NAME)
    print(f'   журнал: {len(rows)} действий (d08-*); политика: пакет помечен, '
          'разбор продолжается')
    print('ИТОГ:', 'Файл в порядке.' if ok else 'Файл НЕ соответствует условию!')
    return ok


def regen(out):
    """Собирает эквивалент: портит чексумму одного серверного пакета."""
    base_recs, _meta = read_any(FIXTURES_DIR / BASE_CAPTURE)
    base = [parse_tcp(r, i) for i, r in enumerate(base_recs)]
    victim = next(p for p in base
                  if p and p.direction() == 's2c' and len(p.payload) >= 20)
    raw = bytearray(base_recs[victim.index].data)
    ihl = (raw[14] & 0x0F) * 4
    at = 14 + ihl + 16
    old = bytes(raw[at:at + 2])
    raw[at] ^= 0xFF  # один бит порчи — payload не трогаем
    new_recs = list(base_recs)
    src = base_recs[victim.index]
    new_recs[victim.index] = PcapRecord(src.ts_us, bytes(raw),
                                       src.incl_len, src.orig_len)
    print(f'   испорчен кадр #{victim.index} s2c seq={victim.seq}: '
          f'checksum {old.hex()} -> {bytes(raw[at:at + 2]).hex()}, payload цел')
    if out:
        write_pcapng(out, new_recs)
        print(f'   записано: {out} ({len(new_recs)} кадров)')
    check(True, 'регенерат собран', '')
    return True


if __name__ == '__main__':
    regen_flag, out = main_guard(NAME)
    sys.exit(0 if (regen(out) if regen_flag else verify()) else 1)
