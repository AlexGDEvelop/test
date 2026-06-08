"""Захват трафика в pcap ОДНИМ инструментом для обоих классов (контроль конфаундов).

Пишем pcap через dumpcap/tshark (надёжный захват + корректная диссекция QUIC/h3),
а разбираем офлайн через dpkt (detect/features.py). Это удовлетворяет требованию
Этапа 1 (§3): фон И туннель снимаются ОДНИМ захватчиком, на одной машине/сети,
вперемежку — иначе классификатор выучит артефакт инструмента, а не протокол.

tshark в этом окружении не установлен (нужен Wireshark+Npcap, admin) — поэтому
модуль code-complete и проверяется на стенде. Функции бросают CaptureError с
понятным сообщением, если инструмент не найден.

Глубокие QUIC-фичи (число стримов для V7-внутри-QUIC) при необходимости берутся
через `tshark -T json` — расширение поверх транспортных V1–V7, которые считаются
из pcap напрямую.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from typing import List, Optional


class CaptureError(Exception):
    pass


def find_tool(preferred: Optional[str] = None) -> str:
    """Найти захватчик: dumpcap (легче) либо tshark. Бросает CaptureError если нет."""
    candidates = [preferred] if preferred else ["dumpcap", "tshark"]
    for name in candidates:
        if name and shutil.which(name):
            return shutil.which(name)
    raise CaptureError(
        "не найден dumpcap/tshark в PATH. Установи Wireshark (вкл. Npcap) на стенде; "
        "это обязателен — захват scapy на Windows ненадёжен (см. решение ревью Этапа 3)."
    )


def list_interfaces(tool: Optional[str] = None) -> str:
    exe = find_tool(tool)
    return subprocess.run([exe, "-D"], capture_output=True, text=True).stdout


class Capture:
    """Контекст-менеджер фонового захвата в pcap-файл.

    Пример:
        with Capture(out="bg.pcap", iface="5", bpf="tcp or udp"):
            do_browsing_or_tunnel_traffic()
        # на выходе pcap дописан и закрыт
    """

    def __init__(self, out: str, iface: str, bpf: Optional[str] = None,
                 tool: Optional[str] = None, settle_s: float = 0.7):
        self._out = out
        self._iface = iface
        self._bpf = bpf
        self._exe = find_tool(tool)
        self._settle = settle_s
        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "Capture":
        cmd = [self._exe, "-i", self._iface, "-w", self._out, "-q"]
        if self._bpf:
            cmd += ["-f", self._bpf]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE)
        time.sleep(self._settle)  # дать захватчику подняться до начала трафика
        if self._proc.poll() is not None:
            err = self._proc.stderr.read().decode(errors="replace") if self._proc.stderr else ""
            raise CaptureError(f"захватчик не стартовал: {err.strip()}")
        return self

    def __exit__(self, *exc):
        if self._proc and self._proc.poll() is None:
            time.sleep(self._settle)  # дать долететь хвостовым пакетам
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        return False
