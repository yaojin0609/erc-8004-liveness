"""TLS 证书失败归类的回归测试。

背景：校验可能由 OpenSSL 做，也可能由 truststore 转交系统验证器做，
两套措辞完全不同。原来只认 OpenSSL 的写法，在 macOS 上跑实测得到：

    self-signed.badssl.com   → error_kind='other'   （应为自签名一类）
    expired.badssl.com       → error_kind='expired' （碰巧两边都含 "expired"）
    wrong.host.badssl.com    → error_kind='hostname_mismatch' （碰巧含 "not match"）

「证书有问题但服务是活的」是 L3 要单独识别的情形，归进 'other' 就丢了。
"""

import pytest

from e8004.probe.layers import _tls_error_kind

# 两套验证器对同一种失败的真实报错文本（macOS 那组为本机实测抓取）
OPENSSL = [
    ("certificate verify failed: certificate has expired (_ssl.c:1010)", "expired"),
    ("certificate verify failed: self-signed certificate (_ssl.c:1010)", "self_signed"),
    ("certificate verify failed: unable to get local issuer certificate", "untrusted_ca"),
    ("Hostname mismatch, certificate is not valid for 'x.test'", "hostname_mismatch"),
]
MACOS = [
    ("(“*.badssl.com” certificate is expired,)", "expired"),
    ("(“*.badssl.com” certificate is not trusted,)", "untrusted_ca"),
    ("(“*.badssl.com” certificate name does not match input,)", "hostname_mismatch"),
]


@pytest.mark.parametrize("msg,expected", OPENSSL + MACOS)
def test_tls_error_kind_covers_both_verifiers(msg, expected):
    assert _tls_error_kind(msg) == expected


def test_unknown_message_falls_back_to_other():
    assert _tls_error_kind("something nobody predicted") == "other"


def test_no_cert_failure_is_ever_silently_expired():
    """'expired' 是最常被引用的一类，不能被别的措辞误伤。"""
    assert _tls_error_kind("certificate is not trusted") != "expired"
    assert _tls_error_kind("certificate name does not match input") != "expired"
