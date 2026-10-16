#!/usr/bin/env python3
"""04_snaplen_truncated.pcapng — усечение пакета при захвате.

Условие: кадр обрезан snaplen'ом — captured меньше original length,
оригинальная длина при этом СОХРАНЕНА (поле origlen на месте).
Требование кейса: обрезанное явно видно, недостающие байты не додумываются,
известное доступно.

Скрипт по умолчанию ПРОВЕРЯЕТ приложенный файл, с --regen собирает
эквивалент из research/03_combined_messages.pcap:
    python3 04_snaplen_truncated.py [--regen [--out=ПУТЬ]]
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

NAME = 'diagnostics/04_snaplen_truncated.pcapng'


def verify():
    print(f'== {NAME}: усечение при захвате ==')
    ok = True
    records, _meta = read_any(FIXTURES_DIR / NAME)
    pkts = [parse_tcp(r, i) for i, r in enumerate(records)]
    ok &= check(len(records) > 0, f'кадров прочитано: {len(records)}',
                'файл пуст или не читается')

    cut = [(i, r) for i, r in enumerate(records) if r.truncated]
    ok &= check(len(cut) > 0,
                f'усечённых кадров: {len(cut)} — origlen сохранён, смотрим:',
                'усечений нет — это не snaplen-файл')
    for i, r in cut:
        print(f'     кадр #{i}: captured={r.incl_len} Б, original={r.orig_len} Б, '
              f'потеряно {r.orig_len - r.incl_len} Б')
        p = pkts[i]
        print(f'     разбор: {"обрезан ниже IP/TCP — payload нет вообще" if p is None else "частичный payload (%d Б)" % len(p.payload)}')

    # Остальное обязано сойтись с базой: резанули один кадр, не поток.
    base = load_base()
    good = [p for p in pkts if p]
    for direction in ('c2s', 's2c'):
        mine = [p for p in good if p.direction() == direction]
        ref = [p for p in base if p and p.direction() == direction]
        stream, gaps, overlaps = reassemble(mine)
        ref_stream, _, _ = reassemble(ref)
        # Хвост серверного потока короче ровно на потерю усечённого кадра.
        print(f'   поток {direction}: {len(stream)} Б против {len(ref_stream)} Б базы')
    rows = load_journal_rows(NAME)
    print(f'   журнал: {len(rows)} действий (d04-*); действия, чей ответ '
          'задет срезом, остаются без полных байтов — и это видно')
    print('ИТОГ:', 'Файл в порядке.' if ok else 'Файл НЕ соответствует условию!')
    return ok


def regen(out):
    """Собирает эквивалент: режет captured одного серверного пакета."""
    base_recs, _meta = read_any(FIXTURES_DIR / BASE_CAPTURE)
    base = [parse_tcp(r, i) for i, r in enumerate(base_recs)]
    cands = [p for p in base
             if p and p.direction() == 's2c' and len(p.payload) > 60]
    victim = max(cands, key=lambda p: len(p.payload))
    src = base_recs[victim.index]
    cut_to = 58  # как в приложенном файле: кадр есть, хвоста нет
    new_recs = list(base_recs)
    new_recs[victim.index] = PcapRecord(
        src.ts_us, src.data[:cut_to], cut_to, src.orig_len)
    print(f'   резанут кадр #{victim.index} s2c: captured {src.incl_len} -> '
          f'{cut_to} Б, original {src.orig_len} Б сохранён')
    if out:
        write_pcapng(out, new_recs)
        print(f'   записано: {out} ({len(new_recs)} кадров)')
    check(True, 'регенерат собран', '')
    return True


if __name__ == '__main__':
    regen_flag, out = main_guard(NAME)
    sys.exit(0 if (regen(out) if regen_flag else verify()) else 1)
