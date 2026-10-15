## Стадия сборки: Rust workspace (core + api)
FROM rust:1.99-bookworm AS build
WORKDIR /build

# Манифесты отдельным слоем — чтобы пересборка кэшировала зависимости,
# пока не изменился код. Path-зависимость protocol-lab-core тянет core/.
COPY Cargo.toml Cargo.lock ./
COPY core/Cargo.toml core/
COPY api/Cargo.toml api/

# Заглушки исходников: собираем только зависимости (слой кэша).
# api/Cargo.toml объявляет два бинарника (protocol-lab-api и protocol-lab-cli),
# поэтому нужны заглушки под оба.
RUN mkdir -p core/src api/src/bin \
    && printf '' > core/src/lib.rs \
    && printf 'fn main() {}\n' > api/src/main.rs \
    && printf 'fn main() {}\n' > api/src/bin/cli.rs \
    && cargo build --release -p protocol-lab-api --bin protocol-lab-api

# Настоящие исходники поверх заглушек; touch сбрасывает mtime, чтобы cargo
# пересобрал пакеты, а не принял заглушки за актуальные.
COPY core/ core/
COPY api/ api/
RUN touch core/src/lib.rs api/src/main.rs api/src/bin/cli.rs \
    && cargo build --release -p protocol-lab-api --bin protocol-lab-api

## Стадия рантайма: только бинарь и рабочие каталоги
FROM debian:bookworm-slim
WORKDIR /app

# curl — только для HEALTHCHECK в docker-compose (в slim его нет).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Бэк биндится на 0.0.0.0:8080 (cli-флаги --host/--port/--data-dir).
COPY --from=build /build/target/release/protocol-lab-api /app/protocol-lab-api

# Фикстуры и реестр паттернов читаются по относительным путям от cwd.
COPY fixtures/ /app/fixtures/
COPY patterns/ /app/patterns/

# Персистентные каталоги; пробрасываются volume-ами в docker-compose.
RUN mkdir -p /app/data /app/uploads

EXPOSE 8080

# Запуск строго из /app — иначе fixtures/, data/, uploads/ не находятся.
CMD ["./protocol-lab-api"]
