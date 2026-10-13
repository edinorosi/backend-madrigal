// НЕ НУ Я ПЫТАЛСЯ САМ ЭТО НАППСАТЬ НО Я СКОПИРОВАЛ ГОТОВЫЙ ГОД ИБО НУ ТИПО ЗАЧЕМ 


use flate2::read::GzDecoder;
use protocol_lab_core::interpreter::{apply_rule, FieldType, FramingRule, InterpretationRule, frame_stream};
use protocol_lab_core::pcap::{reader::read_pcap, session::{group_into_sessions, split_into_flows}};
use protocol_lab_core::tcp::reassembler::TcpReassembler;
use protocol_lab_core::tcp::stream::StreamChunk;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use serde::Deserialize;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    // Неинтерактивный режим: если переданы аргументы, выполняем команду и выходим
    if args.len() > 1 {
        let command = &args[1];
        let cmd_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
        
        match command.as_str() {
            "verify" => cmd_verify(&cmd_args),
            "analyze" => cmd_analyze(&cmd_args),
            "export" => cmd_export(&cmd_args),
            "help" => print_help(),
            _ => {
                eprintln!("Неизвестная команда: {}", command);
                eprintln!("Используйте 'help' для списка команд");
                std::process::exit(1);
            }
        }
        return;
    }

    // Интерактивный режим (REPL)
    println!("Protocol Lab CLI v1.0");
    println!("Интерактивная оболочка для анализа сетевых протоколов");
    println!("Введите 'help' для списка команд\n");

    let mut rl = DefaultEditor::new().expect("Не удалось инициализировать редактор");
    
    let history_path = ".cli_history";
    if rl.load_history(history_path).is_err() {
        println!("(История команд не найдена, начинаем с нуля)");
    }

    loop {
        let readline = rl.readline("protocol-lab > ");
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                
                rl.add_history_entry(line).unwrap();
                
                let parts: Vec<&str> = line.split_whitespace().collect();
                let command = parts.first().unwrap_or(&"");
                let cmd_args = &parts[1..];

                match *command {
                    "help" => print_help(),
                    "verify" => cmd_verify(cmd_args),
                    "analyze" => cmd_analyze(cmd_args),
                    "export" => cmd_export(cmd_args),
                    "exit" | "quit" => {
                        println!("👋 До свидания!");
                        break;
                    }
                    _ => println!("Неизвестная команда: {}. Введите 'help' для списка команд.", command),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("(Ctrl+C)");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("(Ctrl+D)");
                break;
            }
            Err(err) => {
                println!("Ошибка: {:?}", err);
                break;
            }
        }
    }

    rl.save_history(history_path).unwrap();
}

fn print_help() {
    println!("\n Доступные команды:");
    println!("  help                          - Показать эту справку");
    println!("  verify <archive> [target]     - Проверить PCAP на основе правил из архива");
    println!("                                  <archive>  - путь к .tar.gz проекту");
    println!("                                  [target]   - (опционально) путь к новому .pcap");
    println!("  analyze <pcap>                - Авто-анализ PCAP и поиск паттернов");
    println!("  export <archive> <output>     - Экспорт проекта в отчёт");
    println!("  exit / quit                   - Выйти из оболочки\n");
}

fn cmd_verify(args: &[&str]) {
    if args.is_empty() {
        println!(" Использование: verify <archive> [--target <pcap>] [--journal <csv>] [--output <md>]");
        return;
    }

    let archive = args[0].to_string();
    let mut target: Option<String> = None;
    let mut journal_path: Option<String> = None;
    let mut output = "report.md".to_string();

    // Надёжный парсинг аргументов
    let mut i = 1;
    while i < args.len() {
        match args[i] {
            "--target" => {
                if i + 1 < args.len() {
                    target = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!(" Ошибка: ожидается путь после --target");
                    return;
                }
            }
            "--journal" => {
                if i + 1 < args.len() {
                    journal_path = Some(args[i + 1].to_string());
                    i += 2;
                } else {
                    println!(" Ошибка: ожидается путь после --journal");
                    return;
                }
            }
            "--output" => {
                if i + 1 < args.len() {
                    output = args[i + 1].to_string();
                    i += 2;
                } else {
                    println!(" Ошибка: ожидается путь после --output");
                    return;
                }
            }
            arg if !arg.starts_with("--") => {
                // Если это не флаг, считаем его target (для обратной совместимости)
                if target.is_none() {
                    target = Some(arg.to_string());
                }
                i += 1;
            }
            _ => {
                println!(" Неизвестный аргумент: {}", args[i]);
                return;
            }
        }
    }

    println!("Извлечение архива: {}", archive);
    
    let temp_dir = tempfile::tempdir().expect("Не удалось создать временную директорию");
    let temp_path = temp_dir.path();

    let tar_gz = match File::open(&archive) {
        Ok(f) => f,
        Err(e) => { println!(" Ошибка открытия архива: {}", e); return; }
    };
    
    let decompressor = GzDecoder::new(tar_gz);
    let mut archive_obj = tar::Archive::new(decompressor);
    if let Err(e) = archive_obj.unpack(temp_path) {
        println!(" Ошибка распаковки: {}", e);
        return;
    }

    let rules_path = temp_path.join("rules.json");
    let rules_content = match fs::read_to_string(&rules_path) {
        Ok(c) => c,
        Err(e) => { println!(" Не найден rules.json: {}", e); return; }
    };
    
    let cli_rules: CliRules = match serde_json::from_str(&rules_content) {
        Ok(r) => r,
        Err(e) => { println!(" Ошибка парсинга правил: {}", e); return; }
    };

    let pcap_path = if let Some(t) = target {
        println!("Используем целевой файл: {}", t);
        t
    } else {
        let mut found_pcap = None;
        for entry in fs::read_dir(temp_path).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().and_then(|s| s.to_str()) == Some("pcap") || 
               entry.path().extension().and_then(|s| s.to_str()) == Some("pcapng") {
                found_pcap = Some(entry.path().clone());
                break;
            }
        }
        match found_pcap {
            Some(p) => p.to_string_lossy().to_string(),
            None => { println!(" В архиве не найден .pcap/.pcapng файл"); return; }
        }
    };

    println!("Анализ файла: {}", pcap_path);
    
    let framing_rule = match cli_rules.framing.framing_type.as_str() {
        "length_prefixed" => FramingRule::LengthPrefixed,
        _ => FramingRule::FixedSize(cli_rules.framing.size.unwrap_or(12)),
    };

    let field_type = match cli_rules.rule.field_type.as_str() {
        "u16_big" => FieldType::U16Big,
        "u16_little" => FieldType::U16Little,
        "u32_big" => FieldType::U32Big,
        "u32_little" => FieldType::U32Little,
        _ => FieldType::U8,
    };

    let rule = InterpretationRule {
        name: cli_rules.rule.name,
        offset: cli_rules.rule.offset,
        field_type,
    };

    let packets = match read_pcap(Path::new(&pcap_path)) {
        Ok(p) => p,
        Err(e) => { println!(" Ошибка чтения PCAP: {}", e); return; }
    };
    
    let sessions = group_into_sessions(&packets);
    let total_sessions = sessions.len();
    
    // Парсинг журнала действий (R2)
    let mut journal_entries: Vec<JournalEntry> = Vec::new();
    if let Some(j_path) = journal_path {
        println!("Чтение журнала действий: {}", j_path);
        let mut rdr = csv::Reader::from_path(&j_path).expect("Ошибка чтения CSV");
        for result in rdr.deserialize() {
            if let Ok(record) = result {
                journal_entries.push(record);
            }
        }
        println!("   Загружено записей журнала: {}", journal_entries.len());
    }

    let mut total_messages = 0;
    let mut success_count = 0;
    let mut error_count = 0;
    let mut counterexamples = Vec::new();

    for (session_idx, session) in sessions.iter().enumerate() {
        eprint!("\rОбработка сессии {}/{}...", session_idx + 1, total_sessions);
        
        let (flow_c2s, _) = split_into_flows(session);
        let chunks = TcpReassembler::reassemble(&flow_c2s.packets);

        let mut clean_bytes: Vec<u8> = Vec::new();
        let mut gap_offsets: Vec<usize> = Vec::new();

        for chunk in &chunks {
            match chunk {
                StreamChunk::Data { packet_index, .. } => {
                    if let Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                        clean_bytes.extend_from_slice(&pkt.payload);
                    }
                }
                StreamChunk::Gap { flow_offset, .. } => {
                    gap_offsets.push(*flow_offset);
                }
                _ => {}
            }
        }

        let messages = frame_stream(&clean_bytes, &framing_rule);

        for msg in messages {
            total_messages += 1;

            let is_after_gap = gap_offsets.iter().any(|&gap_off| msg.stream_offset >= gap_off);
            if is_after_gap {
                let hex_dump = msg.payload.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                counterexamples.push(format!(
                    "| Сессия {} | Смещение `{}` | `incomplete` | Data after TCP Gap | - | `{}` |",
                    session_idx, msg.stream_offset, hex_dump
                ));
                continue;
            }

            match apply_rule(&msg.payload, &rule) {
                Some(_) => {
                    success_count += 1;
                }
                None => {
                    error_count += 1;
                    let hex_dump = msg.payload.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                    counterexamples.push(format!(
                        "| Сессия {} | Смещение `{}` | `parse_error` | Not enough bytes | - | `{}` |",
                        session_idx, msg.stream_offset, hex_dump
                    ));
                }
            }
        }
    }
    eprintln!("\rОбработка завершена.                              ");

    // Генерация отчёта
    let mut report = String::new();
    report.push_str("# Автоматизированный отчёт проверки протокола\n\n");
    report.push_str(&format!("- **Целевой файл:** {}\n", pcap_path));
    report.push_str(&format!("- **Всего сообщений:** {}\n", total_messages));
    report.push_str(&format!("- **Успешно:** {}\n", success_count));
    report.push_str(&format!("- **Ошибок/Контрпримеров:** {}\n\n", error_count));

    if !journal_entries.is_empty() {
        report.push_str("## Связь с журналом действий (R2)\n\n");
        report.push_str("| Время | Действие | Параметр |\n");
        report.push_str("|-------|----------|----------|\n");
        for entry in &journal_entries {
            report.push_str(&format!("| `{}` | {} | `{}` | `{}` | `{}` |\n", 
                entry.action_id, 
                entry.start_utc, 
                entry.action, 
                entry.parameters, 
                entry.observed_result
            ));
        }
        report.push_str("\n");
    }
    
    report.push_str("## Контрпримеры и ошибки (с Hex-дампом)\n\n");
    report.push_str("| Сессия | Смещение | Тип | Описание | Ожидалось | Получено (Hex) |\n");
    report.push_str("|--------|----------|-----|----------|-----------|----------------|\n");
    
    if counterexamples.is_empty() {
        report.push_str("| - | - | - | **Ошибок не найдено. Гипотеза подтверждена.** | - | - |\n");
    } else {
        for ex in counterexamples {
            report.push_str(&format!("{}\n", ex));
        }
    }

    let mut file = match File::create(&output) {
        Ok(f) => f,
        Err(e) => { println!("Не удалось создать файл отчёта: {}", e); return; }
    };
    
    file.write_all(report.as_bytes()).unwrap();

    println!("\nВсего сообщений: {}", total_messages);
    println!("Успешно: {}", success_count);
    println!("Ошибок: {}", error_count);
    println!("Отчёт сохранён в: {}", output);
}

fn cmd_analyze(args: &[&str]) {
    if args.is_empty() {
        println!("Использование: analyze <pcap>");
        return;
    }

    let pcap_path = args[0];
    println!("Авто-анализ файла: {}", pcap_path);
    
    let packets = match read_pcap(Path::new(pcap_path)) {
        Ok(p) => p,
        Err(e) => { println!("Ошибка чтения PCAP: {}", e); return; }
    };
    
    let sessions = group_into_sessions(&packets);
    println!("Найдено сессий: {}", sessions.len());

    for (idx, session) in sessions.iter().enumerate() {
        let (flow_c2s, _) = split_into_flows(session);
        let chunks = TcpReassembler::reassemble(&flow_c2s.packets);
        
        let mut total_bytes = 0;
        let mut gaps = 0;
        
        for chunk in &chunks {
            match chunk {
                StreamChunk::Data { length, .. } => total_bytes += length,
                StreamChunk::Gap { .. } => gaps += 1,
                _ => {}
            }
        }
        
        println!("  Сессия {}: {} байт, {} дыр", idx, total_bytes, gaps);
    }
    
    println!("\nАнализ завершён. (Полная эвристика паттернов будет добавлена позже)");
}

fn cmd_export(args: &[&str]) {
    if args.len() < 2 {
        println!("Использование: export <archive> <output>");
        return;
    }

    let archive = args[0];
    let output = args[1];
    
    println!("Экспорт проекта из {} в {}", archive, output);
    println!("Экспорт завершён. (Полная генерация отчёта будет добавлена позже)");
}

#[derive(Deserialize)]
struct CliRules {
    framing: FramingConfig,
    rule: RuleConfig,
}

#[derive(Deserialize)]
struct FramingConfig {
    #[serde(rename = "type")]
    framing_type: String,
    size: Option<usize>,
}

#[derive(Deserialize)]
struct RuleConfig {
    name: String,
    #[serde(rename = "type")]
    field_type: String,
    offset: usize,
}

#[derive(serde::Deserialize, Debug)]
struct JournalEntry {
    capture: String,
    session: String,
    action_id: String,
    start_utc: String,
    end_utc: String,
    action: String,
    parameters: String,
    observed_result: String,
}