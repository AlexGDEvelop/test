---
name: transport-obfuscator-project
description: R&D-проект транспорт-обфускатора (DPI-устойчивость) в Desktop/test — статус и решения
metadata:
  type: project
---

R&D-прототип транспорт-обёртки для туннеля, изучение устойчивости к поведенческому DPI на изолированном стенде (НЕ продакшен-обход). Каталог `c:\Users\Kolotushkin.AM.PARTNER\Desktop\test`. Крипто руками НЕ пишем — только аудированные либы.

По состоянию на 2026-06-08 Этапы 1–4 закрыты, 22/22 тестов:
- Э1 — threat model + метрики ([stage1_threat_model.md]); метрика успеха = TPR@FPR=1e-3/1e-4, не ROC-AUC.
- Э2 — крипто-ядро Noise IK (TCP+UDP), record-слой WireGuard-стиля для UDP ([tunnel/]).
- Э3 — обёртки как переключаемые модули через общий `Carrier` ([transport/]): (c) padding/frag, (a) **Reality-lite** (настоящий TLS 1.3 + relay зондов на свой контрольный донор, стиринг по covert-SNI), (b) **настоящий QUIC** через aioquic.
- Э4 — детектор-эмулятор ([detect/]): фичи V1–V7 из pcap (dpkt), RandomForest, кривая «детектируемость vs цена». Захват tshark/dumpcap — code-complete, исполняется на стенде (в dev-окружении tshark нет).

Блокер ревью Э4 закрыт: датасет генерится ПАРНО — тот же реальный веб-ворклоад через туннель (как CONNECT-прокси, [detect/connect_proxy.py]) и напрямую; различается только транспорт; захват чередуется (`generate --paired`), не блоками.

Боевой запуск: `tunnel.cli` умеет `--role server|client|socks` и `--transport plain|padded|reality|quic`. Обёртки выведены в боевой путь через ОБЩУЮ фабрику [transports.py] (один источник: её зовут и cli, и detect/generate). Браузинг: локальный SOCKS5 (`--role socks`) + сервер; для обёрток — серверный SOCKS5/ConnectProxy-выход. Деплой на VPS: [deploy/], [requirements-server.txt]. Рабочий VPS-сетап подтверждён пользователем (FoxyProxy SOCKS5).

Этап 4.5 (поле, [field/]): полевой замер удушения через живой ТСПУ — runner (timeseries доставки), server_log (сырые факты коннектов из pcap, БЕЗ вердикта «зонд»), selfprobe (quic помечен INCONCLUSIVE), correlate (порог удушения параметрами, маппинг с curve.json без вердикта). 29/29 тестов (pytest).

Открытые решения (measure-first): faithful Reality (мини-uTLS) — при необходимости; сверка детектора с CensorLab/nDPI — рекомендована, не сделана (первый шаг после реальных данных). Реальный negative-класс (живой браузинг) — стенд-сайд.

V7 УТОЧНЁН (важно): `v7_unique_dests` структурно=1 для одноэндпоинтного туннеля, mux его НЕ лечит — только многоэндпоинтность/domain-fronting; `v7_max_concurrent_flows` надувается параллельными коннектами, но бьёт в фильтр >3 параллельных TLS. Т.е. «V7 доминирует» = аргумент за fronting, НЕ за mux.

Окружение: Windows, Python 3.10 (системный, НЕ venv выбранный в IDE — отсюда IDE-подсказки «не установлено»). Связано с [[user-review-style]].
