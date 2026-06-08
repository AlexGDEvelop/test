# Транспорт-обфускатор для туннеля — R&D-стенд

Экспериментальный прототип для **измерения устойчивости транспортного слоя
туннеля к поведенческому DPI** (паттерн-анализ потока, тайминги, отпечаток
рукопожатия) на изолированном стенде между двумя своими хостами.

> **Назначение.** Это исследовательская измерялка, а не средство обхода в
> проде. Цель — понять и *измерить*, что и как детектируется, а не выпустить
> «необнаружимый» протокол (их не бывает). Крипто-ядро не изобретаем — только
> аудированные Noise/TLS. Запуск только на своём изолированном стенде.

Дизайн-обоснование каждого этапа — в отдельных документах:
[stage1_threat_model.md](stage1_threat_model.md) ·
[stage2_crypto_core.md](stage2_crypto_core.md) ·
[stage3_transport_wrapper.md](stage3_transport_wrapper.md) ·
[stage4_detection_lab.md](stage4_detection_lab.md).
Этот README — операционная точка входа: как поставить, запустить и проверить.

---

## 1. Архитектура (4 слоя)

```
   приложение (браузер/urllib)
        │  plaintext
        ▼
  ┌─────────────────┐   общий контракт Carrier (transport/base.py)
  │ транспорт-модуль │   (a) reality  (b) quic  (c) padding  + plain (эталон)
  └─────────────────┘
        │  фреймы на проводе различаются ТОЛЬКО здесь
        ▼
  ┌─────────────────┐
  │  Noise-туннель   │   Noise IK, шифрование/аутентификация (tunnel/)
  └─────────────────┘
        │  ciphertext
        ▼
        сеть  ──►  сервер  ──►  upstream (target / CONNECT-прокси / реальный сайт)

  Параллельно: detect/ — DPI-детектор-эмулятор, меряет, насколько ПЛОХО
  атакующий отличает туннель от реального фона (метрика TPR@FPR vs цена).
```

Ключевой принцип: Noise-туннель работает поверх **любого** carrier одинаково,
поэтому модули (a)/(b)/(c) сравниваются честно — различается только обёртка.

---

## 2. Карта файлов

```
tunnel/              Этап 2 — крипто-ядро (Noise IK)
  cli.py             CLI: keygen + запуск базового туннеля (tcp/udp)
  keys.py            X25519 keygen / hex
  noise_session.py   обёртка Noise IK (initiator/responder)
  record.py          UDP record (counter-nonce + replay-window) — KAT-прибит
  framing.py         TCP-кадрирование Noise-сообщений
  tcp_tunnel.py      базовый TCP-туннель (Этап 2)
  udp_tunnel.py      базовый UDP-туннель (Этап 2)

transport/           Этап 3 — переключаемые обёртки
  base.py            контракт Carrier + CostStats (ось стоимости)
  plain_tcp.py       эталон «голого» ядра
  padding.py         (c) padding/fragmentation/jitter + крутилки
  reality.py         (a) Reality-lite: настоящий TLS 1.3 + relay зондов на донор
  tls_util.py        самоподписанные cert + парсер SNI из ClientHello
  quic_h3.py         (b) туннель внутри настоящего QUIC (aioquic, ALPN h3)
  carrier_tunnel.py  Noise-туннель поверх любого carrier

detect/              Этап 4 — лаборатория обнаружения
  features.py        экстрактор фич V1–V7 из pcap (dpkt, офлайн)
  metrics.py         TPR@FPR (главная метрика), ROC-AUC (вспомогательно)
  classifier.py      RandomForest атакующего + важности фич + временной сплит
  cost_curve.py      сборка «детектируемость vs цена»
  capture.py         захват pcap одним инструментом (dumpcap/tshark)
  connect_proxy.py   CONNECT-прокси (чтобы туннель нёс реальный веб-ворклоад)
  generate.py        парный размеченный датасет: фон + туннель каждого модуля
  run_experiment.py  финал: прогон через детектор -> кривая

config/bench.example.json   конфиг loopback-стенда
tests/                      6 наборов тестов (23 теста)
requirements.txt
```

---

## 3. Установка

Требуется **Python 3.10+**.

```bash
pip install -r requirements.txt
```

Это ставит `noiseprotocol`, `cryptography`, `aioquic`, `numpy`, `scipy`,
`scikit-learn`, `dpkt`.

**Захват трафика — НЕ pip-пакет.** Для Этапа 4 (сбор pcap) поставь **Wireshark**
(даёт `dumpcap`/`tshark` + драйвер **Npcap**). Установщик GUI, нужны права
администратора, при установке Npcap отметь «поддержка loopback», если будешь
снимать loopback-стенд. `scapy` для live-захвата на Windows не используем —
ненадёжно (решение ревью Этапа 3).

Проверка, что захватчик виден:
```bash
python -m detect.generate --list-ifaces
```

---

## 4. Быстрый старт (loopback, базовый туннель за 2 минуты)

Проверить, что крипто-ядро работает, без всякого захвата:

```bash
# 1) поднять простой upstream-приёмник (то, куда туннель доставляет), напр. эхо:
#    в одном терминале — любой TCP-сервис на 127.0.0.1:9000

# 2) сервер туннеля (читает config/bench.example.json, target=127.0.0.1:9000)
python -m tunnel.cli run --config config/bench.example.json --role server --proto tcp

# 3) клиент туннеля (слушает 127.0.0.1:1080, шифрует на сервер)
python -m tunnel.cli run --config config/bench.example.json --role client --proto tcp

# теперь всё, что подключится на 127.0.0.1:1080, идёт ШИФРОВАННЫМ на сервер и
# форвардится в target. Для UDP — то же с --proto udp.
```

Сгенерировать свои ключи (вместо демонстрационных из конфига):
```bash
python -m tunnel.cli keygen   # печатает private/public X25519
```

---

## 5. Запуск компонентов

### 5.1. Базовый туннель (Этап 2) — два хоста

Конфиг — JSON с секциями `server` и `client` ([config/bench.example.json](config/bench.example.json)):

```jsonc
{
  "server": { "static_private": "<hex>", "bind": "0.0.0.0:5555", "target": "127.0.0.1:9000" },
  "client": { "static_private": "<hex>", "server_public": "<hex серверного public>",
              "server_addr": "<IP сервера>:5555", "local_bind": "127.0.0.1:1080" }
}
```

Для двух реальных хостов разнеси секции: **серверу** нужен только свой
`static_private`; **клиенту** — свой `static_private` и `server_public`
(публичный ключ сервера). Сгенерируй по паре на каждый хост через `keygen`.

```bash
# на сервере:
python -m tunnel.cli run --config bench.json --role server --proto tcp   # или udp
# на клиенте:
python -m tunnel.cli run --config bench.json --role client --proto tcp
```

### 5.2. Транспорт-модули Этапа 3 (a)/(b)/(c)

У модулей нет отдельного CLI — они подключаются программно через общий контракт
или гоняются через лабораторию (`detect.generate`, см. 5.3). Минимальный запуск
модуля вручную (пример — padding):

```python
from tunnel import keys
from transport.carrier_tunnel import CarrierTunnelClient, CarrierTunnelServer
from transport.padding import PaddedTcpClient, PaddedTcpServer, PaddingPolicy

s, c = keys.generate(), keys.generate()
pol = PaddingPolicy(max_fragment_payload=600, min_size=600, max_size=1400, max_delay_s=0.002)

server = CarrierTunnelServer(
    make_server=lambda h: PaddedTcpServer("0.0.0.0:5555", h, pol),
    target="127.0.0.1:9000", static_private=s.private).start()

client = CarrierTunnelClient(
    local_bind="127.0.0.1:1080",
    carrier_client=PaddedTcpClient("SERVER_IP:5555", pol),
    static_private=c.private, server_public=s.public).start()
```

- (a) `reality` — `RealityServer(..., donor=..., cert=..., key=..., tunnel_sni=...)`
  + `RealityClient(server_addr, tunnel_sni, server_cert)`; нужен донор
  (`ControlTlsDonor`) и самоподписанные cert/key (`transport.tls_util.generate_self_signed`).
- (b) `quic` — `QuicServer(bind, h, cert, key)` + `QuicClient(server_addr, cert, server_name)`.

Готовые сборки всех модулей с нужной обвязкой — в `detect/generate.py:TunnelBench`.

### 5.3. Лаборатория обнаружения (Этап 4)

Финальный артефакт — кривая «детектируемость vs цена». Сначала собрать pcap,
потом прогнать детектор.

```bash
# 0) номер интерфейса
python -m detect.generate --list-ifaces

# 1) ПАРНЫЙ датасет: один URL за раунд тянется и напрямую (фон), и через туннель
#    каждого модуля; порядок раундов перемешан; один захватчик
python -m detect.generate --paired --iface N --out-root data --urls urls.txt \
    --modules plain,padded,reality,quic --rounds 3000
#    -> data/background, data/tunnel_plain, data/tunnel_padded, data/tunnel_reality, data/tunnel_quic

# 2) детектор + кривая
python -m detect.run_experiment --background data/background --json-out curve.json \
    plain=data/tunnel_plain padded=data/tunnel_padded \
    reality=data/tunnel_reality quic=data/tunnel_quic
```

`urls.txt` — по одному URL в строке (строки с `#` игнорируются); образец —
[config/urls.example.txt](config/urls.example.txt). Вывод `run_experiment` —
таблица overhead / TPR@1e-3 / TPR@1e-4 / AUC + топ-фичи детектора по каждому
модулю.

### 5.4. Логи работы

Единый логгер ([logconf.py](logconf.py), namespace `obf.*`). По умолчанию
библиотека **молчит** (тесты не шумят); логи включаются при запуске CLI/скриптов.

```bash
# туннель: --log-level (по умолчанию INFO)
python -m tunnel.cli run --config config/bench.example.json --role server --proto tcp --log-level INFO
python -m tunnel.cli run --config config/bench.example.json --role client --proto tcp --log-level DEBUG

# SOCKS5-выход (логирует, какие хосты запрашиваются)
python tools/socks5.py --port 8888 --log-level INFO
```

Что пишется (INFO): жизненный цикл соединения с id (`C0001` клиент, `S0002`
сервер, `A*` Reality-стиринг, `I*/R*` carrier-модули, `P*` CONNECT, `X*` SOCKS5):

```
10:24:35 INFO  obf.tcp    | conn C0001 accepted from 127.0.0.1:49952
10:24:35 INFO  obf.tcp    | conn C0001 handshake ok -> server 127.0.0.1:49950
10:24:35 INFO  obf.socks5 | X0001 CONNECT example.com:443 ok
10:24:35 INFO  obf.tcp    | conn C0001 closed: net→plain 20B, plain→net 27B, 0.0s
```

- **WARNING** — отказы: handshake failed, upstream недоступен, не-CONNECT-запрос.
- **Reality-стиринг** логирует решение `SNI -> ТУННЕЛЬ` или `-> ДОНОР relay (зонд)`
  — видно, что зонды действительно уходят на донор.
- **Приватность.** На INFO в SOCKS5/CONNECT пишутся **запрашиваемые хосты** (это
  и есть журнал посещений). Сам полезный трафик зашифрован и в логи не попадает.
  Хочешь тише — `--log-level WARNING` (только отказы).

### 5.5. Браузинг через FoxyProxy (локальный SOCKS5)

Правильная схема (как shadowsocks): SOCKS5 терминируется **локально в клиенте**,
по сети идёт **только Noise** — SOCKS5 на провод не выходит, его блокировки нас
не касаются. Адрес сайта клиент передаёт серверу внутри туннеля; сервер набирает.
Нужно **два процесса** (клиент + сервер), без отдельного socks-процесса.

1. **Конфиг:** серверу включить ДИНАМИЧЕСКИЙ режим — `target: null` (или убрать поле):
   ```jsonc
   "server": { "static_private": "...", "bind": "0.0.0.0:5555", "target": null }
   ```
2. **На сервере (VPS, это и есть выход в интернет):**
   ```bash
   python -m tunnel.cli run --config bench.json --role server
   ```
3. **На локальном ПК:**
   ```bash
   python -m tunnel.cli run --config bench.json --role socks
   # локальный SOCKS5 на client.local_bind (напр. 127.0.0.1:1080)
   ```
4. **FoxyProxy:** тип **SOCKS5**, `127.0.0.1`, порт `1080`, галка
   **«Proxy DNS when using SOCKS v5»** (DNS резолвится на выходе, без утечки).

Проверка из терминала (надёжнее кнопки Test):
```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me   # вернёт IP сервера
```

Нюансы:
- **Сервер обязан быть в динамическом режиме** (`target: null`). Если задан
  фиксированный `target`, сервер игнорирует адрес от клиента — браузинг не выйдет.
- Поддержан **CONNECT (TCP)**; SOCKS5 UDP-associate не реализован (для QUIC/h3 в
  браузере это ограничение — основной HTTPS-браузинг работает).
- `tools/socks5.py` остаётся как самостоятельный SOCKS5 для других сценариев; для
  FoxyProxy он больше не нужен — локальный `--role socks` его заменяет.
- На **loopback**-стенде «выход» — твоя же машина (IP не сменится); реальная смена
  IP — когда сервер на удалённом хосте.

---

## 6. Тестирование

Тесты самодостаточны (loopback/синтетика), **tshark и интернет не нужны**.
На Windows для корректного вывода кириллицы — `set PYTHONUTF8=1`.

```bash
set PYTHONUTF8=1                       # Windows (cmd);  PowerShell: $env:PYTHONUTF8=1
python tests/test_tunnel.py           # Этап 2: record/replay/KAT, TCP+UDP туннель (8)
python tests/test_transport.py        # Этап 3: (c) padding, ось стоимости, переключаемость (6)
python tests/test_reality.py          # (a): «зонд видит донор», Noise внутри TLS 1.3 (3)
python tests/test_quic.py             # (b): Noise внутри настоящего QUIC (1)
python tests/test_detection.py        # Этап 4: метрика, фичи, детектор, кривая (4)
python tests/test_payload_identity.py # блокер Э4: нагрузка через туннель == прямая (1)
```

Итого 23 теста. Что проверяет ключевое:
- **`test_tunnel`** — UDP record прибит **KAT** (раскладка nonce), окно повтора не
  сдвигается до AEAD-верификации, на проводе нет плейнтекста.
- **`test_reality`** — `test_probe_sees_real_donor`: зонд получает **сертификат и
  страницу донора**, а не наш сервер (граница «настоящий TLS vs мёртвый попугай»).
- **`test_payload_identity`** — через туннель и напрямую приходит **идентичное
  тело** во всех 4 модулях (иначе детектор делил бы классы по приложению).

---

## 7. Стенд: пошагово (два хоста + захват)

1. **Подготовь два своих хоста** в изолированной сети (или loopback на одном —
   тогда Npcap с loopback-адаптером).
2. **Ключи:** `keygen` на каждом; обменяйтесь публичными.
3. **Сервер:** открой порт, задай `target` (куда доставлять). Для Этапа 4
   `target` = CONNECT-прокси (его поднимает `generate` автоматически).
4. **Поставь Wireshark+Npcap** на хосте, где снимаешь трафик (обычно клиент).
5. **Собери датасет** `generate --paired` (см. 5.3) — он сам поднимает туннели и
   прокси, ходит по `urls.txt` и пишет pcap **одним** захватчиком, чередуя классы.
6. **Прогони** `run_experiment` → кривая + топ-фичи.
7. **Прочитай топ-фичи** — они скажут, что именно палит каждый модуль.

---

## 8. Нюансы и подводные камни (читать перед стендом)

### Окружение / Windows
- **Кодировка консоли.** Без `PYTHONUTF8=1` кириллица в выводе превратится в
  кракозябры (сами тесты при этом проходят — это только отображение).
- **IDE «пакет не установлен».** Если VS Code показывает, что `noiseprotocol`/
  `aioquic` не установлены, а CLI/тесты работают — у IDE выбран другой
  интерпретатор (venv), а пакеты стоят в системном Python 3.10. Выбери в IDE тот
  же интерпретатор или игнорируй подсказку.
- **Захват loopback** на Windows требует Npcap с поддержкой loopback-адаптера;
  для двух хостов снимай реальный NIC.

### Крипто
- **Руками не написано ничего, кроме UDP-record** (`record.py`): счётчик-nonce +
  replay-window поверх ChaCha20-Poly1305 из `cryptography` — модель WireGuard.
  Это место прибито **KAT** (литеральный nonce) и тестами на повтор/порчу.
- **TLS-порядок vs UDP.** TCP-туннель использует штатный счётчик noiseprotocol
  (порядок гарантирован); UDP — явный счётчик (датаграммы теряются/переставляются).
- **2^64 nonce.** Для очень долгих сессий нужен rekey (помечен `OverflowError`);
  для сбора датасета Этапа 4 не упрётся.

### Модуль (a) Reality-lite — документированные gaps (это findings, не баги)
- **Стиринг по covert-SNI**, а не по аутентификатору в SessionID: stdlib `ssl` не
  даёт клиенту задать SessionID/ClientHello. Фиксированный `tunnel_sni` — сам по
  себе признак (V5). Свойство «зонд видит настоящий донор» при этом сохраняется.
- **JA3/JA4 клиента = отпечаток OpenSSL stdlib, не браузера** (V5).
- Внешний TLS — камуфляж; **настоящая аутентификация = внутренний Noise**.
- **Донор держи на стенде** (свой `ControlTlsDonor`), не бей по чужому публичному
  сайту — воспроизводимо и без паразитной нагрузки.
- Закрытие gaps = faithful Reality (мини-uTLS) — отдельный объём, по данным.

### Модуль (b) QUIC
- **Настоящий QUIC** (aioquic), не «похожие на QUIC» датаграммы.
- **Один QUIC-стрим = нетипичный h3-профиль** (браузер открывает много стримов) —
  это V7-fan-out внутри QUIC. Если детектор ловит (b), проверь, не из-за
  одностримовости ли, а не самого QUIC.
- **CostStats не видит QUIC-overhead** (заголовки/ACK/MTU-паддинг) — строгий
  overhead для (b) берётся из pcap в `run_experiment`.

### Захват и контроль конфаундов (самое важное для честности замера)
- **Один захватчик для обоих классов.** Фон и туннель — один dumpcap/tshark, одна
  машина, одна сеть. Иначе классификатор выучит артефакт инструмента, а не
  протокол.
- **Идентичная нагрузка.** Через туннель и напрямую тянется ТОТ ЖЕ веб-ворклоад
  (`--paired` + CONNECT-прокси). Если туннель несёт служебный трафик (echo) —
  детектор разделит классы по приложению, и «туннель спалился» будет ложью.
- **Чередование, не блоки.** `--paired` снимает классы вперемежку короткими
  сессиями. Большие последовательные блоки → утечка через сетевой контекст/время.
- **Объём фона.** Для измеримого FPR=1e-4 нужно **≥10 000** фоновых примеров
  (`metrics.min_negatives_for_fpr`), иначе TPR@1e-4 упрётся в гранулярность и даст
  ложно-оптимистичный ноль. На малом фоне читай TPR@1e-3.
- **Золотой стандарт фона** — настоящая браузерная сессия под тем же Capture;
  `--paired` по реальным URL — воспроизводимый прокси этого.

### Метрика
- **TPR при FPR=1e-3/1e-4, а не ROC-AUC.** Рабочая точка cost-bounded цензора. AUC
  считается, но вспомогательно. Можно иметь AUC≈0.6 и быть пойманным при FPR=1e-4.
- **V4 (энтропия) — знак нейтрален.** Цель не «максимум энтропии», а близость к
  донор-профилю; голый Noise «слишком случайный» с первого байта — это признак.
- **Классификатор намеренно простой** (RandomForest): если простой ловит, сложный
  тем более.

### V7 (граф/fan-out) — не перепутать починку
- `v7_unique_dests` **структурно =1** для одноэндпоинтного туннеля (весь трафик на
  сервер); у браузинга — десятки CDN. **mux/несколько стримов это НЕ лечат** —
  только многоэндпоинтность (**domain fronting**).
- `v7_max_concurrent_flows` можно надуть параллельными коннектами, но это бьёт в
  отдельный фильтр (**>3 параллельных TLS** к одному серверу → заморозка).
- Если `v7_*` в топе фич — это аргумент за **fronting**, НЕ за mux.

---

## 9. Границы эксперимента (что НЕ закрываем)

Из [stage1_threat_model.md](stage1_threat_model.md) §6:
- **Активное зондирование** — модуль (a) даёт зонду настоящий донор, но мы не
  имитируем живой сайт на сервере полностью.
- **Репутация IP/ASN** — зарубежный «чистый» IP остаётся признаком, транспорт это
  не лечит.
- **Корреляция таймингов на двух концах** — атака глобального наблюдателя, вне scope.
- **Блокировка «всего неопознанного»** на отдельных направлениях — против неё
  мимикрия (a)/(b) сильнее «голого» ядра.

### Открытые решения (measure-first — только по данным детектора)
- **Domain fronting** — если V7/`unique_dests` доминирует.
- **Faithful Reality (мини-uTLS)** — если V5 (covert-SNI/stdlib-JA3) доминирует у (a).
- **Сверка детектора с nDPI/CensorLab** — рекомендованный первый шаг после сбора
  реальных данных, чтобы простой RF не дал ложно-оптимистичный результат.
- **Adversarial-петля** (Этап 5) — крутить параметры модулей против детектора.

---

## 10. Лицензия и ответственность

R&D на собственном изолированном стенде. Не предназначено для обхода сетевых
ограничений в проде или против чужих сетей. Криптография — только аудированные
библиотеки.
