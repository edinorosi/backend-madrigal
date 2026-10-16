#!/usr/bin/env python3
"""03_missing_segment.pcap — пропуск сегмента в записи.

Условие: кусок серверного потока отсутствует в захвате (первые 35 байт:
ответы на действия 001 read-config и 002 read-values).
Требование кейса: неизвестные данные обозначаются явно и НЕ подменяются
нулями или догадками; известные участки доступны для исследования.
Журнал при этом описывает исходный эксперимент — строки 001/002 в нём есть,
а байтов нет (ловушка для наивной привязки).

Скрипт по умолчанию ПРОВЕРЯЕТ приложенный файл, с --regen собирает
эквивалент из research/03_combined_messages.pcap:
    python3 03_missing_segment.py [--regen [--out=ПУТЬ]]
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

NAME = 'diagnostics/03_missing_segment.pcap'

# Что вырезано в приложенном файле (факт, сверен с базой): начало серверного
# потока, seq 900001..900035 включительно (35 Б).
MISSING_SEQ_START = 900001
MISSING_SEQ_LEN = 35


def locate_head_cut(mine, ref):
    """Ищет, с какого смещения серверный поток совпадает с базой.

    Возвращает (пропущено_байт, seq_первого_известного). Если поток совпал
    целиком — (0, seq начала).
    """
    for skip in range(len(ref) + 1):
        if bytes(mine) == bytes(ref[skip:]):
            first_seq = None
            return skip, first_seq
    return None, None


def verify():
    print(f'== {NAME}: пропуск сегмента ==')
    ok = True
    pkts = load_capture(NAME)
    base = load_base()
    good = [p for p in pkts if p]
    ok &= check(len(good) > 0, f'TCP-пакетов: {len(good)}', 'файл пуст')

    mine_s = [p for p in good if p.direction() == 's2c']
    ref_s = [p for p in base if p and p.direction() == 's2c']
    stream, gaps, overlaps = reassemble(mine_s)
    ref_stream, _, _ = reassemble(ref_s)

    skipped, _ = locate_head_cut(stream, ref_stream)
    ok &= check(skipped is not None and skipped > 0,
                f'серверный поток короче базы на {skipped} Б спереди: '
                f'seq {MISSING_SEQ_START}..{MISSING_SEQ_START + skipped - 1} '
                'неизвестны',
                'срез не найден — файл не похож на missing_segment')
    ok &= check(not gaps and not overlaps,
                'внутри известного хвоста гэпов и конфликтов нет',
                'в хвосте дыры — лишний дефект')

    mine_c = [p for p in good if p.direction() == 'c2s']
    ref_c = [p for p in base if p and p.direction() == 'c2s']
    cstream, _, _ = reassemble(mine_c)
    cref, _, _ = reassemble(ref_c)
    ok &= check(bytes(cstream) == bytes(cref),
                f'клиентский поток цел: {len(cstream)} Б совпали с базой',
                'клиентский поток тоже повреждён — лишний дефект')

    # Что именно потеряно: декодируем вырезанный кусок базы.
    lost = bytes(ref_stream[:skipped]) if skipped else b''
    frames = split_a65c(lost)
    print(f'   потеряно кадров сервера: {len(frames)}')
    for off, body in frames:
        print(f'     +{off}: {body[:24].hex()}{"..." if len(body) > 24 else ""} '
              f'({len(body)} Б тела)')

    rows = load_journal_rows(NAME)
    orphaned = [r for r in rows if r['action_id'] in ('d03-03-01-001', 'd03-03-01-002')]
    print(f'   журнал: {len(rows)} действий; строки без байтов (ловушка): '
          + ', '.join(r['action_id'] for r in orphaned))
    ok &= check(len(orphaned) == 2, 'журнал помнит оба потерянных ответа',
                'журнал не покрывает потерю')
    print('ИТОГ:', 'Файл в порядке.' if ok else 'Файл НЕ соответствует условию!')
    return ok


def regen(out):
    """Собирает эквивалент: выкидывает серверные пакеты диапазона потерь."""
    base_recs, _meta = read_any(FIXTURES_DIR / BASE_CAPTURE)
    base = [parse_tcp(r, i) for i, r in enumerate(base_recs)]
    ref_s = [p for p in base if p and p.direction() == 's2c']
    stream, _, _ = reassemble(ref_s)
    first_seq = ref_s[0].seq if ref_s else MISSING_SEQ_START
    cut_end = first_seq + MISSING_SEQ_LEN
    kept = []
    dropped = 0
    for i, r in enumerate(base_recs):
        p = base[i]
        if (p and p.direction() == 's2c' and p.payload
                and p.seq < cut_end and p.seq + len(p.payload) > first_seq):
            dropped += 1
            print(f'   вырезан пакет #{i} s2c seq={p.seq} len={len(p.payload)}')
            continue
        kept.append(r)
    if out:
        write_classic(out, kept)
        print(f'   записано: {out} ({len(kept)} кадров)')
    check(dropped > 0, f'вырезано пакетов: {dropped}', 'нечего вырезать')
    return True


if __name__ == '__main__':
    regen_flag, out = main_guard(NAME)
    sys.exit(0 if (regen(out) if regen_flag else verify()) else 1)
