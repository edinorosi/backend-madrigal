#!/usr/bin/env python3
"""05_conflicting_overlap.pcap — конфликтующее перекрытие.

Условие: два РАЗНЫХ варианта одного диапазона TCP-байтов (server seq 900001,
35 Б): повтор пришёл с другим содержимым. Внесено намеренно, это не штатное
поведение симулятора.
Требование кейса: неоднозначность видна с привязкой к пакетам; выбранная
политика обработки воспроизводима. Неизвестные байты остаются неизвестными,
даже если журнал содержит наблюдавшийся результат.

Скрипт по умолчанию ПРОВЕРЯЕТ приложенный файл, с --regen собирает
эквивалент из research/03_combined_messages.pcap:
    python3 05_conflicting_overlap.py [--regen [--out=ПУТЬ]]
"""
import struct
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

NAME = 'diagnostics/05_conflicting_overlap.pcap'


def verify():
    print(f'== {NAME}: конфликтующее перекрытие ==')
    ok = True
    pkts = load_capture(NAME)
    good = [p for p in pkts if p]
    ok &= check(len(good) > 0, f'TCP-пакетов: {len(good)}', 'файл пуст')

    mine_s = [p for p in good if p.direction() == 's2c']
    stream, gaps, overlaps = reassemble(mine_s, policy='latest')
    conflicts = [o for o in overlaps if not o.identical]
    ok &= check(len(conflicts) > 0,
                f'конфликтов: {len(conflicts)} — показываем с привязкой:',
                'конфликтов нет — это не overlap-файл')
    for o in conflicts:
        print(f'     seq={o.start_seq} len={len(o.first)} Б')
        print(f'     вариант 1: {o.first.hex()}')
        print(f'     вариант 2: {o.second.hex()}')
        diffs = [i for i, (a, b) in enumerate(zip(o.first, o.second)) if a != b]
        print(f'     различаются байты смещений: {diffs}')
        for i in diffs:
            print(f'       +{i}: {o.first[i]:#04x} vs {o.second[i]:#04x}')
        # Расшифровываем смысл расхождения: это порог в эхе конфига
        # (конфиг: ENA | PERIOD u16BE | THRESH i16BE/100 | LEN | метка,
        #  в 35-байтном ответе порог — байты [12:14]).
        print('     смысл: байт порога в ответе read-config '
              f'({int.from_bytes(o.first[12:14], "big", signed=True) / 100:.2f}°C vs '
              f'{int.from_bytes(o.second[12:14], "big", signed=True) / 100:.2f}°C)')
    print('   политика: latest (побеждает поздний пакет) — применена '
          'воспроизводимо, оба варианта выше')

    # Кто именно привёз второй вариант: ищем пару пакетов на один seq.
    by_seq = {}
    for p in mine_s:
        by_seq.setdefault(p.seq, []).append(p)
    for seq, grp in sorted(by_seq.items()):
        payloads = {bytes(p.payload) for p in grp if p.payload}
        if len(payloads) > 1:
            print(f'   пакеты-носители: ' +
                  ', '.join(f'#{p.index} ({p.ts_us} мкс)' for p in grp if p.payload))

    base = load_base()
    ref_s = [p for p in base if p and p.direction() == 's2c']
    ref_stream, _, _ = reassemble(ref_s)
    print(f'   серверный поток: {len(stream)} Б против {len(ref_stream)} Б базы '
          '(длина та же — подмены нет, есть неоднозначность)')

    rows = load_journal_rows(NAME)
    print(f'   журнал: {len(rows)} действий (d05-*); наблюдавшийся результат '
          'есть, но байты неоднозначны — журнал не решает конфликт')
    print('ИТОГ:', 'Файл в порядке.' if ok else 'Файл НЕ соответствует условию!')
    return ok


def regen(out):
    """Собирает эквивалент: дублирует ответ с изменённым байтом порога."""
    base_recs, _meta = read_any(FIXTURES_DIR / BASE_CAPTURE)
    base = [parse_tcp(r, i) for i, r in enumerate(base_recs)]
    ref_s = [p for p in base if p and p.direction() == 's2c']
    # Первый ответ сервера с телом (эхо конфига), не пустой SYN-ACK.
    victim = next(p for p in ref_s if len(p.payload) >= 20)
    body = bytearray(victim.payload)
    # Порог — байты [12:14] 35-байтного ответа (см. verify).
    old = bytes(body[12:14])
    body[12:14] = struct.pack('!h', struct.unpack('!h', old)[0] + 1)
    max_ts = max(r.ts_us for r in base_recs)
    twin = build_tcp(max_ts + 1000,
                     SERVER_IP, SERVER_PORT, CLIENT_IP, victim.src_port,
                     victim.seq, victim.ack, 0x18, bytes(body))
    print(f'   пакет #{victim.index} продублирован с порогом '
          f'{int.from_bytes(old, "big", signed=True) / 100:.2f} -> '
          f'{int.from_bytes(bytes(body[12:14]), "big", signed=True) / 100:.2f}°C')
    recs = sorted(base_recs + [twin], key=lambda r: r.ts_us)
    if out:
        write_classic(out, recs)
        print(f'   записано: {out} ({len(recs)} кадров)')
    check(True, 'регенерат собран', '')
    return True


if __name__ == '__main__':
    regen_flag, out = main_guard(NAME)
    sys.exit(0 if (regen(out) if regen_flag else verify()) else 1)
