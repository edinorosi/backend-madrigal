#!/usr/bin/env python3
"""06_missing_beginning.pcapng — запись началась после установления соединения.

Условие: в захвате нет handshake (ни одного SYN) и нет первых байтов потоков.
Требование кейса: недоступные данные и неопределённые роли сторон НЕ
объявляются установленными. Кто клиент — выводится только эвристикой
по адресам, начало потоков неизвестно.

Скрипт по умолчанию ПРОВЕРЯЕТ приложенный файл, с --regen собирает
эквивалент из research/03_combined_messages.pcap:
    python3 06_missing_beginning.py [--regen [--out=ПУТЬ]]
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

NAME = 'diagnostics/06_missing_beginning.pcapng'


def verify():
    print(f'== {NAME}: нет начала соединения ==')
    ok = True
    pkts = load_capture(NAME)
    good = [p for p in pkts if p]
    ok &= check(len(good) > 0, f'TCP-пакетов: {len(good)}', 'файл пуст')

    syns = [p for p in good if p.syn]
    ok &= check(not syns, 'SYN/SYN-ACK нет вообще — handshake не наблюдался',
                f'есть SYN-пакеты: {[p.index for p in syns]} — начало на месте?')

    # Роли сторон: handshake нет, так что клиент — только эвристика по IP.
    print('   роли: handshake отсутствует, клиент определён эвристикой '
          f'(меньший IP {CLIENT_IP} шлёт первым) — не объявляем установленным')

    base = load_base()
    for direction in ('c2s', 's2c'):
        mine = [p for p in good if p.direction() == direction]
        ref = [p for p in base if p and p.direction() == direction]
        stream, gaps, overlaps = reassemble(mine)
        ref_stream, _, _ = reassemble(ref)
        # Начало потока неизвестно: ищем, с какого смещения базы совпало.
        skipped = None
        for k in range(len(ref_stream) + 1):
            if bytes(stream) == bytes(ref_stream[k:]):
                skipped = k
                break
        if skipped:
            first = mine[0]
            print(f'   поток {direction}: первые {skipped} Б базы отсутствуют '
                  f'(начинается с seq={first.seq}), дальше — {len(stream)} Б совпали')
            ok &= check(True, f'поток {direction}: хвост цел', '')
        else:
            ok &= check(bytes(stream) == bytes(ref_stream),
                        f'поток {direction}: цел ({len(stream)} Б)',
                        f'поток {direction}: расходится с базой не только в начале!')
    rows = load_journal_rows(NAME)
    print(f'   журнал: {len(rows)} действий (d06-*); ранние действия '
          'привязать не к чему — начала нет')
    print('ИТОГ:', 'Файл в порядке.' if ok else 'Файл НЕ соответствует условию!')
    return ok


def regen(out):
    """Собирает эквивалент: отрезает всё до первого полного запроса.

    seq НЕ трогаем (сниффер опоздал — пакеты раньше просто не видел, их seq
    настоящие). Первый kept-пакет — 12-байтовый клиентский запрос, handshake
    и два коротких пакета начала потока остаются за бортом, как в файле.
    """
    base_recs, _meta = read_any(FIXTURES_DIR / BASE_CAPTURE)
    base = [parse_tcp(r, i) for i, r in enumerate(base_recs)]
    anchor = next(p for p in base
                  if p and p.direction() == 'c2s' and len(p.payload) >= 12)
    kept = [r for i, r in enumerate(base_recs)
            if base[i] and (base[i].ts_us, i) >= (anchor.ts_us, anchor.index)]
    dropped = len(base_recs) - len(kept)
    print(f'   отрезано ранних кадров: {dropped}, первый kept #{anchor.index} '
          f'c2s seq={anchor.seq} (handshake и 5 Б начала клиентского потока потеряны)')
    if out:
        write_pcapng(out, kept)
        print(f'   записано: {out} ({len(kept)} кадров)')
    nosyn = not any(p.syn for p in base if p and p.ts_us >= anchor.ts_us)
    check(nosyn, 'в хвосте SYN нет', 'SYN просочился в регенерат')
    return True


if __name__ == '__main__':
    regen_flag, out = main_guard(NAME)
    sys.exit(0 if (regen(out) if regen_flag else verify()) else 1)
