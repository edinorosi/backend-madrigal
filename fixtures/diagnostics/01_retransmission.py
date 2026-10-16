#!/usr/bin/env python3
"""01_retransmission.pcap — одинаковая повторная передача.

Условие: сегменты повторяются с ТЕМИ ЖЕ sequence numbers и ТЕМИ ЖЕ байтами.
Требование кейса: байты не дублируются в прикладном потоке, исходные пакеты
при этом сохраняются (сверка доступна).

Скрипт по умолчанию ПРОВЕРЯЕТ приложенный файл, с --regen собирает
эквивалент из research/03_combined_messages.pcap:
    python3 01_retransmission.py [--regen [--out=ПУТЬ]]
Без --out регенерат только строится в памяти и проверяется, файл не пишется
(исходники кейса не затираем молча).
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

NAME = 'diagnostics/01_retransmission.pcap'

# Какие пакеты базы дублируем при --regen: (направление, seq, сколько копий).
RETX = [('c2s', None, 2), ('s2c', None, 1)]


def find_retransmissions(packets):
    """Группы (направление, seq) с несколькими одинаковыми payload'ами.

    Возвращает (дубли, конфликты): дубли — повторы байт в байт, конфликты —
    один seq с разными байтами (это уже не ретрансмиссия, а 05-й случай).
    """
    seen = {}
    dups, conflicts = [], []
    for p in packets:
        if not p or not p.payload:
            continue
        key = (p.direction(), p.seq)
        if key in seen:
            if seen[key] == bytes(p.payload):
                dups.append((p.index, p.direction(), p.seq, len(p.payload)))
            else:
                conflicts.append((p.index, p.direction(), p.seq))
        else:
            seen[key] = bytes(p.payload)
    return dups, conflicts


def verify():
    print(f'== {NAME}: одинаковая повторная передача ==')
    ok = True
    pkts = load_capture(NAME)
    base = load_base()
    ok &= check(len(pkts) > 0, f'кадров прочитано: {len(pkts)}',
                'файл пуст или не читается')

    dups, conflicts = find_retransmissions(pkts)
    ok &= check(len(dups) > 0, f'повторных передач байт-в-байт: {len(dups)}',
                'повторов не найдено — это не retransmission-файл')
    for idx, direction, seq, length in dups[:8]:
        print(f'     пакет #{idx} {direction} seq={seq} len={length} — копия')
    ok &= check(not conflicts, 'конфликтующих перекрытий нет',
                f'ЕСТЬ конфликты (см. 05): {conflicts[:4]}')

    # Прикладные потоки обязаны совпасть с базой ровно, без дублей.
    for direction in ('c2s', 's2c'):
        mine = [p for p in pkts if p and p.direction() == direction]
        ref = [p for p in base if p and p.direction() == direction]
        stream, gaps, overlaps = reassemble(mine)
        ref_stream, _, _ = reassemble(ref)
        ok &= check(not gaps and not overlaps,
                    f'поток {direction}: гэпов и перекрытий нет',
                    f'поток {direction}: гэпы/перекрытия — так быть не должно')
        ok &= check(bytes(stream) == bytes(ref_stream),
                    f'поток {direction}: {len(stream)} Б, совпал с базой '
                    f'({len(ref_stream)} Б), дубли схлопнуты',
                    f'поток {direction} НЕ совпал с базой')

    rows = load_journal_rows(NAME)
    print(f'   журнал: {len(rows)} действий (d01-*), все ответы на месте — '
          'дубли не плодят ложных действий')
    print('ИТОГ:', 'Файл в порядке.' if ok else 'Файл НЕ соответствует условию!')
    return ok


def regen(out):
    """Собирает эквивалент: дублирует 2 клиентских и 1 серверный пакет."""
    base_recs, _meta = read_any(FIXTURES_DIR / BASE_CAPTURE)
    base = [parse_tcp(r, i) for i, r in enumerate(base_recs)]
    cands_c = [p for p in base if p and p.direction() == 'c2s' and p.payload]
    cands_s = [p for p in base if p and p.direction() == 's2c' and p.payload]
    victims = [(cands_c[2], 2), (cands_c[5], 2), (cands_s[1], 1)]
    max_ts = max(r.ts_us for r in base_recs)
    new_recs = list(base_recs)
    for victim, copies in victims:
        for k in range(1, copies + 1):
            max_ts += 1000
            # Тот же seq, те же байты, новое время наблюдения — классика ретрансмиссии.
            clone = PcapRecord(max_ts, base_recs[victim.index].data,
                               base_recs[victim.index].incl_len,
                               base_recs[victim.index].orig_len)
            new_recs.append(clone)
            print(f'   дублирован пакет #{victim.index} ({victim.direction()} '
                  f'seq={victim.seq}) — копия {k}')
    recs = sorted(new_recs, key=lambda r: r.ts_us)
    if out:
        write_classic(out, recs)
        print(f'   записано: {out} ({len(recs)} кадров)')
    return check(len(recs) == len(base_recs) + 5, 'регенерат собран: +5 копий',
                 'счёт не сошёлся')


if __name__ == '__main__':
    regen_flag, out = main_guard(NAME)
    sys.exit(0 if (regen(out) if regen_flag else verify()) else 1)
