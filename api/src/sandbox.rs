/// Песочница серверных скриптов (`POST /api/v1/scripts/run`).
///
/// Уровни (`--scripts-sandbox` / `SCRIPTS_SANDBOX`):
/// - `auto` — bwrap если есть, иначе rlimit + варнинг в stderr (дефолт);
/// - `rlimit` — только зачистка env и лимиты, сеть и файлы как у сервера;
/// - `bwrap` — bubblewrap: свой корень, нет сети, падает вместе с сервером;
/// - `off` — как раньше (для отладки; в лог предупреждение).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sandbox {
    Off,
    Rlimit,
    Bwrap,
}

/// Разбор флага + env. Возвращает уровень и варнинг для stderr (если есть).
pub(crate) fn resolve(flag: &str) -> (Sandbox, Option<String>) {
    let raw = std::env::var("SCRIPTS_SANDBOX").unwrap_or_else(|_| flag.to_string());
    match raw.trim().to_lowercase().as_str() {
        "off" => (Sandbox::Off, Some("песочница скриптов выключена".to_string())),
        "rlimit" => (Sandbox::Rlimit, None),
        "bwrap" => {
            if bwrap_works() {
                (Sandbox::Bwrap, None)
            } else {
                (
                    Sandbox::Rlimit,
                    Some("bwrap не работает тут, слабый режим rlimit".to_string()),
                )
            }
        }
        _ => {
            // auto и мусор: лучшее доступное
            if bwrap_works() {
                (Sandbox::Bwrap, None)
            } else {
                (
                    Sandbox::Rlimit,
                    Some("bwrap не работает тут, слабый режим rlimit".to_string()),
                )
            }
        }
    }
}

fn bwrap_binary() -> Option<String> {
    for cand in ["/usr/bin/bwrap", "/bin/bwrap"] {
        if std::path::Path::new(cand).exists() {
            return Some(cand.to_string());
        }
    }
    None
}

/// Честная проверка: бинарь есть И реально выполняет.
/// Кэш на процесс — проба один раз на старте (resolve зовётся раз).
fn bwrap_works() -> bool {
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        let Some(bin) = bwrap_binary() else {
            return false;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let ok = std::process::Command::new(bin)
                .args([
                    "--ro-bind", "/usr", "/usr",
                    "--tmpfs", "/tmp",
                    "--unshare-net",
                    "--clearenv",
                    "/usr/bin/true",
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            let _ = tx.send(ok);
        });
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap_or(false)
    })
}

/// Лимиты дочернего процесса (pre_exec, Unix): CPU 30с, память 512МБ,
/// файлы 64, процессы без форк-бомб. Ошибки игнорируются — лучше слабый
/// лимит, чем упавший запуск.
#[cfg(unix)]
pub(crate) fn apply_rlimits() {
    unsafe {
        // libc уже в дереве через tokio; прямых вызовов достаточно
        let cpu = libc::rlimit { rlim_cur: 30, rlim_max: 30 };
        libc::setrlimit(libc::RLIMIT_CPU, &cpu);
        let mem: u64 = 512 * 1024 * 1024;
        let as_ = libc::rlimit { rlim_cur: mem, rlim_max: mem };
        libc::setrlimit(libc::RLIMIT_AS, &as_);
        let files = libc::rlimit { rlim_cur: 64, rlim_max: 64 };
        libc::setrlimit(libc::RLIMIT_NOFILE, &files);
        // NPROC щедро: лимит считается на всех детей юзера (у деда их и так
        // сотня), режет только форк-бомбы; CPU/таймаут додушат остальное
        let procs = libc::rlimit { rlim_cur: 256, rlim_max: 256 };
        libc::setrlimit(libc::RLIMIT_NPROC, &procs);
    }
}

/// Команда bubblewrap для tmpdir скрипта.
/// Внутри видно только /work (наш tmpdir) + ro /usr; сети нет.
/// Пути env переводятся на /work-аналоги.
/// rlimit вешать на bwrap-родителя НЕЛЬЗЯ (NPROC роняет его fork) —
/// лимиты ставит бутстрап внутри (см. bwrap_bootstrap).
pub(crate) fn bwrap_command(
    tmp: &std::path::Path,
    env: &[(String, String)],
) -> (String, Vec<String>) {
    let bin = bwrap_binary().unwrap_or_else(|| "/usr/bin/bwrap".to_string());
    let work = tmp.to_string_lossy().to_string();
    let mut args = vec![
        "--ro-bind".to_string(), "/usr".to_string(), "/usr".to_string(),
        "--tmpfs".to_string(), "/tmp".to_string(),
        "--bind".to_string(), work.clone(), "/work".to_string(),
        "--chdir".to_string(), "/work".to_string(),
        "--unshare-net".to_string(),
        "--die-with-parent".to_string(),
        "--clearenv".to_string(),
        "--setenv".to_string(), "PATH".to_string(), "/usr/bin:/bin".to_string(),
    ];
    for (k, v) in env {
        let v = v.replace(&work, "/work");
        args.push("--setenv".to_string());
        args.push(k.clone());
        args.push(v);
    }
    args.push("python3".to_string());
    args.push("-c".to_string());
    args.push(bwrap_bootstrap().to_string());
    (bin, args)
}

/// Бутстрап внутри песочницы: sys.path + rlimit + запуск script.py
/// с честным __file__ (runpy) — трейсбеки показывают /work/script.py.
fn bwrap_bootstrap() -> &'static str {
    concat!(
        "import resource, runpy, sys; ",
        "sys.path.insert(0, '/work'); ",
        "resource.setrlimit(resource.RLIMIT_CPU, (30, 30)); ",
        "resource.setrlimit(resource.RLIMIT_AS, (536870912, 536870912)); ",
        "resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64)); ",
        "resource.setrlimit(resource.RLIMIT_NPROC, (256, 256)); ",
        "runpy.run_path('/work/script.py', run_name='__main__')",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_levels() {
        // env в тестах не трогаем: проверяем только явные уровни мимо auto
        assert_eq!(resolve("off").0, Sandbox::Off);
        assert_eq!(resolve("rlimit").0, Sandbox::Rlimit);
        // bwrap/auto зависят от машины — только что не падают
        let _ = resolve("bwrap");
        let _ = resolve("auto");
    }

    #[test]
    fn bwrap_cmd_shape() {
        let (bin, args) = bwrap_command(
            std::path::Path::new("/tmp/xyz"),
            &[("LAB_CONTEXT".to_string(), "/tmp/xyz/context.json".to_string())],
        );
        assert!(bin.ends_with("bwrap"));
        assert!(args.contains(&"--unshare-net".to_string()));
        assert!(args.contains(&"-c".to_string()));
        let i = args.iter().position(|a| a == "LAB_CONTEXT").unwrap();
        assert_eq!(args[i + 1], "/work/context.json");
        assert!(bwrap_bootstrap().contains("runpy"));
    }
}
