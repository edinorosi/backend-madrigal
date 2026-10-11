use protocol_lab_core::pcap::types::{RawPacket, TcpFlags}; // Импортируем типы
use protocol_lab_core::tcp::reassembler::TcpReassembler;    // Импортируем reassembler
use protocol_lab_core::tcp::stream::StreamChunk;            // Импортируем тип куска

fn make_packet(index: usize, seq: u32, payload: Vec<u8>) -> RawPacket { // Хелпер для создания тестовых пакетов
    RawPacket {
        index,                      // Индекс пакета
        timestamp_us: 0,            // Время не важно для теста
        src_ip: [192, 168, 1, 1],   // Тестовый IP источника
        dst_ip: [192, 168, 1, 2],   // Тестовый IP получателя
        src_port: 12345,            // Тестовый порт
        dst_port: 80,               // Тестовый порт
        seq,                        // Sequence number (параметр)
        ack: 0,                     // ACK не важен
        flags: TcpFlags { syn: false, fin: false, rst: false, ack: true }, // Обычный ACK-пакет
        payload,                    // Данные (параметр)
    }
}

#[test]                             // Атрибут теста
fn test_normal_reassembly() {       // Тест нормальной сборки (без дыр)
    let packets = vec![             // Два пакета подряд
        make_packet(0, 1000, vec![1, 2, 3]), // Пакет 0: seq=1000, 3 байта
        make_packet(1, 1003, vec![4, 5]),    // Пакет 1: seq=1003 (1000+3), 2 байта
    ];
    let chunks = TcpReassembler::reassemble(&packets); // Собираем поток
    assert_eq!(chunks.len(), 2);    // Должно быть 2 куска (оба Data)
}

#[test]
fn test_gap_detection() {           // Тест обнаружения дыры
    let packets = vec![
        make_packet(0, 1000, vec![1, 2, 3]), // Пакет 0: seq=1000, 3 байта (покрывает 1000-1002)
        make_packet(1, 1010, vec![4, 5]),    // Пакет 1: seq=1010 (дыра 1003-1009 = 7 байт)
    ];
    let chunks = TcpReassembler::reassemble(&packets);
    assert_eq!(chunks.len(), 3);    // Data, Gap, Data
    assert!(matches!(chunks[1], StreamChunk::Gap { missing_bytes: 7, .. })); // Эта хуетень проверяет типо что чанк является gap с длинной missing_bytes: 7
}

#[test]
fn test_retransmit_ignored() {      // Тест игнорирования дубликатов
    let packets = vec![
        make_packet(0, 1000, vec![1, 2, 3]), // Первый пакет
        make_packet(1, 1000, vec![1, 2, 3]), // Дубликат (тот же seq)
    ];
    let chunks = TcpReassembler::reassemble(&packets);
    assert_eq!(chunks.len(), 1);    // Должен быть только 1 кусок (дубликат проигнорирован)
}