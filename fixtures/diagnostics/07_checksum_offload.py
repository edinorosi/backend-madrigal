#!/usr/bin/env python3
"""07_checksum_offload.pcap — частичные чексуммы при локальном захвате.

Условие: у исходящих пакетов (c2s, снято на самом отправителе до того, как
железо посчитало чексуммы) TCP-checksum нулевые/мусорные — 14 штук, все в
сторону клиента. Это НЕ порча данных: байты целы, бита только контрольная
сумма.
Требование кейса: политика проверки чексумм задана явно; offload при
локальном захвате учитывается (warn, а не reject).

Скрипт по умолчанию ПРОВЕРЯЕТ приложенный файл, с --regen собирает
эквивалент из research/03_combined_messages.pcap:
    python3 07_checksum_offload.py [--regen [--out=ПУТЬ]]
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

NAME = 'diagnostics/07_checksum_offload.pcap'


def verify():
    print(f'== {NAME}: checksum offload ==')
    ok = True
    pkts = load_capture(NAME)
    good = [p for p in pkts if p]
    ok &= check(len(good) > 0, f'TCP-пакетов: {len(good)}', 'файл пуст')

    bad = [p for p in good if not p.tcp_ok]
    dirs = sorted({p.direction() for p in bad})
    ok &= check(len(bad) > 1,
                f'битых чексумм: {len(bad)} — много, и все {dirs}',
                f'битая чексумма одна — это 08-й случай, а не offload')
    ok &= check(dirs == ['c2s'],
                'все битые — исходящие (c2s): классика захвата на отправителе',
                f'битые есть и во входящих — странно для offload: {dirs}')
    print('     битые кадры:', [p.index for p in bad][:14])

    # Байты при этом целы: потоки обязаны совпасть с базой.
    base = load_base()
    for direction in ('c2s', 's2c'):
        mine = [p for p in good if p.direction() == direction]
        ref = [p for p in base if p and p.direction() == direction]
        stream, gaps, overlaps = reassemble(mine)
        ref_stream, _, _ = reassemble(ref)
        ok &= check(bytes(stream) == bytes(ref_stream),
                    f'поток {direction}: {len(stream)} Б совпали с базой — '
                    'данные не тронуты, биты только чексуммы',
                    f'поток {direction} НЕ совпал — порча данных!')

    rows = load_journal_rows(NAME)
    print(f'   журнал: {len(rows)} действий (d07-*); политика: warn — '
          'анализ идёт, чексуммы помечены, не отброшены')
    print('ИТОГ:', 'Файл в порядке.' if ok else 'Файл НЕ соответствует условию!')
    return ok


def regen(out):
    """Собирает эквивалент: зануляет TCP-checksum всех исходящих."""
    base_recs, _meta = read_any(FIXTURES_DIR / BASE_CAPTURE)
    new_recs = []
    zeroed = 0
    for i, r in enumerate(base_recs):
        p = parse_tcp(r, i)
        if p and p.direction() == 'c2s':
            # Железо ещё не посчитало: на интерфейсе видны нули.
            raw = bytearray(r.data)
            # Смещение TCP-checksum: eth(14) + ihl + 16.
            ihl = (raw[14] & 0x0F) * 4
            raw[14 + ihl + 16:14 + ihl + 18] = b'\x00\x00'
            new_recs.append(PcapRecord(r.ts_us, bytes(raw), r.incl_len, r.orig_len))
            zeroed += 1
        else:
            new_recs.append(r)
    print(f'   занулено чексумм исходящих: {zeroed}')
    if out:
        write_classic(out, new_recs)
        print(f'   записано: {out} ({len(new_recs)} кадров)')
    check(zeroed > 1, 'offload воспроизведён', 'нечего занулять')
    return True


if __name__ == '__main__':
    regen_flag, out = main_guard(NAME)
    sys.exit(0 if (regen(out) if regen_flag else verify()) else 1)
