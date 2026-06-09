# CLAUDE.md — контекст проекта (для продолжения работы)

## Что это
R&D-**измерялка** устойчивости транспортного слоя туннеля к поведенческому DPI
(ТСПУ/GFW-класс) на изолированном стенде. **Не** средство обхода в проде, **не**
«необнаружимый протокол» (их не бывает). Цель — *измерить*, что и как палится, и
какой ценой маскируется. Крипто руками НЕ пишем — только аудированные Noise/TLS.

Дисциплина проекта: **measure-first** (дорогой шаг оправдывают данные детектора,
не интуиция), честные gaps (документируем, не прячем), не подделывать данные.

## Статус (2026-06-09)
Этапы 1–4 + 4.5 реализованы. **30 тестов**, `python -m pytest -q tests/` → зелёные.
VPS развёрнут, идёт первый реальный лабораторный прогон (plain).

## Архитектура / пакеты
- `tunnel/` — Этап 2, крипто-ядро Noise IK (TCP+UDP). Единственный рукописный
  крипто-смежный код — `record.py` (UDP counter-nonce + replay-window), прибит KAT.
- `transport/` — Этап 3, обёртки как переключаемые **Carrier** (`base.py`):
  `plain_tcp` (эталон), `padding` (c), `reality` (a, настоящий TLS + relay зондов
  на донор), `quic_h3` (b, настоящий aioquic). `carrier_tunnel` — Noise поверх любого carrier.
- `transports.py` — **ЕДИНСТВЕННЫЙ источник сборки carrier** (фабрика). Её зовут
  и `tunnel/cli.py`, и `detect/generate.py` — провод обязан совпадать с лабораторией.
- `detect/` — Этап 4, офлайн-детектор: `features` (V1–V7 из pcap, dpkt),
  `metrics` (TPR@FPR), `classifier` (RandomForest + importances + временной сплит),
  `cost_curve`, `capture` (dumpcap/tshark), `connect_proxy`, `generate`, `run_experiment`.
- `field/` — Этап 4.5, ПОЛЕВОЙ замер удушения: `runner` (timeseries доставки),
  `server_log` (сырые факты коннектов из pcap, без вердикта «зонд»), `selfprobe`
  (quic помечен INCONCLUSIVE — TCP-зонд на UDP неинформативен), `correlate`
  (порог удушения параметрами, маппинг с curve.json, вывод за человеком).
- `tools/` — `socks5.py` (локальный SOCKS5-выход для FoxyProxy), `localsite.py`
  (локальный HTTPS-сайт для loopback-смоука). `logconf.py` — единый логгер `obf.*`.

## Ключевые решения (и почему)
- **(a) Reality-lite**: настоящий TLS 1.3 + стиринг по ClientHello (MSG_PEEK) →
  зонд видит донор. Gaps (findings, не баги): covert-SNI вместо SessionID-auth
  (stdlib `ssl` не даёт кастомный ClientHello), JA3 = OpenSSL, не браузер.
  Клиент **пиннит** cert сервера (verify НЕ отключаем).
- **(b) QUIC**: настоящий aioquic. Gap: один стрим = нетипичный h3-профиль (V7-внутри-QUIC).
- **Метрика — TPR@FPR=1e-3/1e-4**, не ROC-AUC (рабочая точка цензора). Для 1e-4
  нужно ≥10⁴ фона; при per-session-захвате это непрактично (часы) → точный 1e-4
  ждёт режима «один захват + демукс по портам» (НЕ реализован).
- **Negative-класс** = реальный браузинг; контроль конфаундов: один захватчик,
  payload-identity (тот же URL в фоне и туннеле), чередование классов.
- **Lab валиден только `--remote` к VPS** (carrier пересекает реальный NIC рядом с
  фоном). `--paired` = loopback → carrier на loopback, фон на NIC → НЕ сопоставить,
  только смоук механики. На loopback фичи вырождаются (MTU 64К, IAT≈0) → AUC≈0.5
  это среда, НЕ маскировка.
- **V7**: `unique_dests` структурно=1 у одноэндпоинтного туннеля; **mux НЕ лечит**,
  только многоэндпоинтность (domain fronting). `max_concurrent` надувается, но бьёт
  в фильтр >3 параллельных TLS.
- **4.5 = симптом** (душат ли), причину даёт ТОЛЬКО детектор Этапа 4.

## Как запускать (ключевое)
- Тесты: `python -m pytest -q tests/` (Windows: `set PYTHONUTF8=1` для кириллицы).
- **Браузинг (FoxyProxy)**: VPS `tunnel.cli run --role server --transport X` (по
  умолчанию `--exit socks`, `target:null`); клиент `--role socks --transport X`;
  FoxyProxy SOCKS5 → 127.0.0.1:1080.
- **Лаборатория (валидно)**: VPS `tunnel.cli run --role server --transport X --exit
  connect`; клиент `detect.generate --remote --config <cfg> --transport X --iface
  <NIC> --out-root data_X --urls urls.txt --rounds N --timeout 6 --max-bytes 120000`;
  затем `detect.run_experiment --background data_plain/background ...`.
- **Loopback-смоук (без ТСПУ)**: `tools/localsite.py --port 8443` + `detect.generate
  --paired --iface <LOOPBACK> --urls config/urls.local.txt`.
- Скорость: `--timeout`/`--max-bytes`/`--settle`. TLS-верификация в генераторе ВЫКЛ
  (traffic-генератор, как curl -k; `--verify-tls` вернуть). Фетч шлёт браузерный UA.

## Операционное состояние
- VPS: `89.125.25.250` (jija.online, hostname ReverentShed0), server_public `3caccfb9…`.
- Клиент: Windows, `.venv`, реальный NIC = **iface 5**, loopback = **iface 6**.
- `config/bench.socks.json` — client-секция смотрит на VPS; plain/padded работают
  как есть; reality/quic нужен transport-блок (`config/transport.example.json`) +
  скопировать `config/reality.crt`/`quic.crt` с VPS на клиент (клиент пиннит).
- VPS код подтянут (`git pull`, коммит `3826b54`). На VPS нужен **aioquic** (новый
  `cli` импортит `transports`→quic). `requirements-server.txt` для этого НЕ хватает
  → `pip install aioquic` или полный `requirements.txt`.
- Первый loopback-смоук: AUC≈0.5 у всех (loopback вырождает фичи — ожидаемо).
  Первый реальный plain-прогон — в процессе; ждём AUC>0.5 у plain с V1/V4 в топе.

## Гочи (что уже кусало — не повторять диагностику)
- **pcapng vs pcap**: dumpcap по умолчанию pcapng, dpkt читает только классический
  → `capture.py` пишет с `-P`; старые конверти `editcap -F pcap`.
- **google.com/youtube** через CONNECT-прокси флаки (HTTP/2/consent) → 20-сек
  зависания. Убраны из urls.
- **403 Forbidden** без User-Agent → добавлен браузерный UA в фетч.
- **`"target":"null"` строкой** ≠ JSON `null` (динамический режим).
- **`v6_duration_s` в топе** = артефакт латентности хопа (proxy-ness), не carrier.
- **Ctrl+C на Windows**: `Event().wait()` не прерывается → используем `time.sleep`-цикл.
- Свой сервер/VPS **не** клади в urls (это не фон).

## Конвенции
- НЕ трогать `tunnel/` крипто-ядро и `transport/*.py` модули без явной нужды (под
  тестами, регресс ломать нельзя). Новый код — рядом.
- Carrier собирать ТОЛЬКО через `transports.py` (один источник для cli и detect).
- Не подделывать данные; loopback / сеть без ТСПУ — только смоук, не findings.
- Опсек (поле): расходный IP, только свой трафик, канал гасить после замера.
- Репозиторий: `github.com/AlexGDEvelop/test` (public). Не коммить реальные ключи
  (`config/server.vps.json`, `*.key/*.crt`, `data/` — в `.gitignore`).

## Открытые решения (measure-first — по данным детектора)
- **Faithful Reality** (мини-uTLS: браузерный ClientHello + SessionID-auth) — если V5 доминирует.
- **Domain fronting / WS-за-CDN** — если V7/IP доминирует (mux не поможет).
- **Сверка детектора с nDPI/CensorLab** — первый шаг после реальных данных.
- **Один-захват+демукс** — для практичного TPR@1e-4.

## Документы
`README.md` (операционка), `stage1..4_*.md` (обоснования этапов),
`measurement_runbook.md` (полный полевой runbook), `memory/` (контекст между сессиями).
