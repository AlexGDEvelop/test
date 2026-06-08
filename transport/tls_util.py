"""TLS-утилиты для модуля (a): самоподписанные сертификаты и парсер SNI.

Сертификаты генерируются `cryptography` (не катаем крипто). SNI-парсер нужен
серверу Reality для стиринга «тоннель vs зонд» на уровне ClientHello — до
терминации TLS, чтобы зонд получил НАСТОЯЩИЙ донор.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import tempfile
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed(common_name: str) -> Tuple[str, str]:
    """Сгенерировать самоподписанный cert+key, вернуть пути к PEM-файлам (temp)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    d = tempfile.mkdtemp(prefix="tunnel_tls_")
    cert_path = os.path.join(d, "cert.pem")
    key_path = os.path.join(d, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    return cert_path, key_path


def parse_sni(data: bytes) -> Optional[str]:
    """Извлечь SNI (host_name) из TLS ClientHello. None при любой ошибке/неполноте.

    Намеренно строгий и без исключений наружу: при сбое сервер Reality считает
    соединение зондом и проксирует на донор (безопасный дефолт).
    """
    try:
        # TLS record header
        if len(data) < 5 or data[0] != 0x16:  # 0x16 = handshake
            return None
        # пропускаем record(5): type(1) version(2) length(2)
        pos = 5
        if len(data) < pos + 4:
            return None
        if data[pos] != 0x01:  # 0x01 = ClientHello
            return None
        # handshake header: type(1) length(3)
        pos += 4
        pos += 2  # client_version(2)
        pos += 32  # random(32)
        if len(data) < pos + 1:
            return None
        sid_len = data[pos]; pos += 1 + sid_len  # session_id
        if len(data) < pos + 2:
            return None
        cs_len = int.from_bytes(data[pos:pos + 2], "big"); pos += 2 + cs_len
        if len(data) < pos + 1:
            return None
        comp_len = data[pos]; pos += 1 + comp_len
        if len(data) < pos + 2:
            return None
        ext_total = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(data):
            etype = int.from_bytes(data[pos:pos + 2], "big")
            elen = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0x0000:  # server_name
                # server_name_list(2) | entry: type(1) | len(2) | name
                if pos + 2 > len(data):
                    return None
                list_len = int.from_bytes(data[pos:pos + 2], "big")
                p = pos + 2
                list_end = min(p + list_len, len(data))
                while p + 3 <= list_end:
                    ntype = data[p]
                    nlen = int.from_bytes(data[p + 1:p + 3], "big")
                    p += 3
                    if ntype == 0x00:  # host_name
                        if p + nlen > len(data):
                            return None
                        # SNI host_name всегда ASCII (IDNA A-label/punycode).
                        return data[p:p + nlen].decode("ascii", errors="replace")
                    p += nlen
                return None
            pos += elen
        return None
    except Exception:
        return None
