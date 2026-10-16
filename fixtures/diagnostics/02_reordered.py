#!/usr/bin/env python3
"""02_reordered.pcapng — изменение порядка наблюдения сегментов.

Условие: пакеты в файле лежат НЕ по sequence numbers (перемешаны при
наблюдении), сами seq и байты не тронуты.
Требование кейса: прикладные байты соответствуют порядку TCP sequence numbers,
а не порядку кадров в файле.

Скрипт по умолчанию ПРОВЕРЯЕТ приложенный файл, с --regen собирает
эквивалент из research/03_combined_messages.pcap:
    python3 02_reordered.py [--regen [--out=ПУТЬ]]
"""
import random
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

NAME = 'diagnostics/02_reordered.pcapng'


def inversions(packets):
    """Пары кадров, где файловый порядок противоречит seq (внутри направлений)."""
    inv = 0
    for direction in ('c2s', 's2c'):
        seqs = [p.seq for p in packets if p and p.payload and p.direction() == direction]
        inv += sum(1 for a, b in zip(seqs, seqs[1:]) if b < a)
    return inv


def verify():
    print(f'== {NAME}: изменение порядка ==')
    ok = True
    records, meta = read_any(FIXTURES_DIR / NAME)
    pkts = [parse_tcp(r, i) for i, r in enumerate(records)]
    ok &= check(len(pkts) > 0, f'кадров прочитано: {len(pkts)}',
                'файл пуст или не читается')

    inv = inversions(pkts)
    ok &= check(inv > 0, f'инверсий порядка в файле: {inv} — пакеты перемешаны',
                'файл идёт строго по seq — это не reordered-файл')

    # Порядок кадров не должен влиять на потоки: собираем по seq.
    base = load_base()
    for direction in ('c2s', 's2c'):
        mine = [p for p in pkts if p and p.direction() == direction]
        ref = [p for p in base if p and p.direction() == direction]
        stream, gaps, overlaps = reassemble(mine)
        ref_stream, _, _ = reassemble(ref)
        ok &= check(bytes(stream) == bytes(ref_stream),
                    f'поток {direction}: {len(stream)} Б — совпал с базой '
                    'несмотря на перемешивание',
                    f'поток {direction} НЕ совпал с базой!')
        ok &= check(not gaps, f'поток {direction}: пропусков нет',
                    f'поток {direction}: есть гэпы — лишний дефект')

    rows = load_journal_rows(NAME)
    print(f'   журнал: {len(rows)} действий (d02-*); окна действий привязаны '
          'ко времени наблюдения, а не к порядку кадров')
    print('ИТОГ:', 'Файл в порядке.' if ok else 'Файл НЕ соответствует условию!')
    return ok


def regen(out):
    """Собирает эквивалент: тасует кадры с данными, метки времени на месте."""
    base_recs, _meta = read_any(FIXTURES_DIR / BASE_CAPTURE)
    rng = random.Random(203)
    order = list(range(len(base_recs)))
    # Тасуем только середину (handshake оставляем: диагностика про порядок данных).
    middle = order[2:]
    rng.shuffle(middle)
    recs = [base_recs[i] for i in order[:2] + middle]
    if out:
        write_pcapng(out, recs)
        print(f'   записано: {out} ({len(recs)} кадров)')
    inv = inversions([parse_tcp(r, i) for i, r in enumerate(recs)])
    check(inv > 0, f'регенерат перемешан: инверсий {inv}', 'тасование не сработало')
    return True


if __name__ == '__main__':
    regen_flag, out = main_guard(NAME)
    sys.exit(0 if (regen(out) if regen_flag else verify()) else 1)
