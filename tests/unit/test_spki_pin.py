"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Unit tests for RemotedSimulator's SPKI pin helpers and its certificate exposure.

The pin is the SHA-256 of a certificate's DER SubjectPublicKeyInfo (RFC 7469 section
2.4) -- the value an enrollment token's `pin` field carries. This is the manager/mint
side of that computation; the agent computes the same value in C++
(wazuh/wazuh: src/client-agent/https_client/src/spkiPin.cpp).

The fixtures below and every expected constant are THE SAME ones the C++ suite
(spkiPin_test.cpp) uses, which is the point: the two implementations are proven to
hash identical bytes to identical values, so an integration test can mint a token on
this side that the agent will actually accept. Reproduce any of them by hand with:

    openssl x509 -in ca1.pem -noout -pubkey | openssl pkey -pubin -outform der \\
      | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='

Run with:  PYTHONPATH=src python3 -m pytest tests/unit/test_spki_pin.py -v
"""
import base64
import binascii
import socket
import ssl
import threading

import pytest

from wazuh_testing.tools.simulators.remoted_simulator import (RemotedSimulator, load_certificate,
                                                              spki_pin, spki_pin_hex, spki_sha256)


# RSA-2048 self-signed CA, CN=Wazuh Test CA RSA, serial 1.
RSA_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAcMRowGAYDVQQDDBFXYXp1
aCBUZXN0IENBIFJTQTAeFw0yNjA5MDgyMDU1NTdaFw0zNjA5MDUyMDU1NTdaMBwx
GjAYBgNVBAMMEVdhenVoIFRlc3QgQ0EgUlNBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA3RHf+NbNSvrAYce0BkxiWKT9RB7m35wC7K2EVaxzVCRUm15c
U8w52iAVQowEzS9YvWuwWg+HlvJxapIyRdf661v/jiqichaEZs4z1IwdvwdDZpKb
0tmlpT6San57LX7Y+RuqZ/YNdctYwunG9AiSJDKnqOjYfZ9i1YkyAsf8SJb1RILq
QE2m5ffJr+LM4uaIfH5dq0w25G3o2lAonnb/cRLS2dDUGBsnsmW0flrm12P2pMcl
mviEHwqIaJcQ7DK2Lh+OioqYTapjG6/YDcRzUCnHJbXBhHHfFD0mjUTWGPbTIvpZ
9fSp21A74Nl63b7M5kMc86Wlq8T2JxszEbQ2XwIDAQABo1MwUTAdBgNVHQ4EFgQU
VK6zm2Yiqy0N6yBHUojeyqIlT/gwHwYDVR0jBBgwFoAUVK6zm2Yiqy0N6yBHUoje
yqIlT/gwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAad9VCQ88
KtE5TCrCurf5Nv2ShvcWGS7fyoyOgHq+PBVl3IzENw83zq/whQdcJOUuu12zlc4J
x4zDUFey0FzLlpIrKg9F9UFmFA8RIpZ3zF/SgiezexQW7mJwxtke78m5PEuks5HX
FWXl6Kd6ZNIl7+S5+lBGqidT6RaJtzMrc2i+CWZvlKA3vuGfFzuyRdfrq8E2GETz
0GBR12GdVirwYPC6xO4c7NFHupnDRttIECGXQw/TbYfqycMxbREmADtKPMsfJbK2
OGU1K32wI9/ecJiwYOJwmDaURj/0RnQFxhJDJ5/ZGoLQ941mX7cpA8EmiSuysacA
6y81YLGrpuwMkA==
-----END CERTIFICATE-----
"""

# The SAME RSA key, reissued: different subject, serial, validity and extensions.
RSA_REISSUED_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDYzCCAkugAwIBAgICEJIwDQYJKoZIhvcNAQELBQAwQjELMAkGA1UEBhMCRVMx
DjAMBgNVBAoMBVdhenVoMSMwIQYDVQQDDBpXYXp1aCBUZXN0IENBIFJTQSBSZWlz
c3VlZDAeFw0yNjA5MDgyMDU1NTdaFw0yNjEwMDgyMDU1NTdaMEIxCzAJBgNVBAYT
AkVTMQ4wDAYDVQQKDAVXYXp1aDEjMCEGA1UEAwwaV2F6dWggVGVzdCBDQSBSU0Eg
UmVpc3N1ZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdEd/41s1K
+sBhx7QGTGJYpP1EHubfnALsrYRVrHNUJFSbXlxTzDnaIBVCjATNL1i9a7BaD4eW
8nFqkjJF1/rrW/+OKqJyFoRmzjPUjB2/B0NmkpvS2aWlPpJqfnstftj5G6pn9g11
y1jC6cb0CJIkMqeo6Nh9n2LViTICx/xIlvVEgupATabl98mv4szi5oh8fl2rTDbk
bejaUCiedv9xEtLZ0NQYGyeyZbR+WubXY/akxyWa+IQfCoholxDsMrYuH46KiphN
qmMbr9gNxHNQKccltcGEcd8UPSaNRNYY9tMi+ln19KnbUDvg2XrdvszmQxzzpaWr
xPYnGzMRtDZfAgMBAAGjYzBhMB0GA1UdDgQWBBRUrrObZiKrLQ3rIEdSiN7KoiVP
+DAfBgNVHSMEGDAWgBRUrrObZiKrLQ3rIEdSiN7KoiVP+DAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwICBDANBgkqhkiG9w0BAQsFAAOCAQEAYc57zE517thZ
IOfCwAA+Na9YPeNM07GDWDwlfxQkF4gb/gzUwpYcvnvupuFhnVuKDdxho2S9xWaK
rGiEvCjTRrTE03X56XTMIImlSLLnRtATotR54MXzpn2CHCG+xkOBsM40C9FVz09J
+PnNthF/HpvP7McgZfUTLLbiv7SJ6t+YVX2KiSNEmSeLk1ofLaWwAArM/o+7pXeH
kWI9GEUNpAnexd19VxSfPtPkjrWisC80NOUvPNDxczCAen6Fs5jpJT4l1ntGX2vg
F/egfaQI3CxPBzVwMW3yrEdmXu0ue1mJGPoSrLJ9gMnw/t5KWNNLj99+X+u5dq1S
ii4lUv1rsg==
-----END CERTIFICATE-----
"""

# The private key for both of the above, so an injected-TLS-material test can serve them.
RSA_KEY_PEM = """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdEd/41s1K+sBh
x7QGTGJYpP1EHubfnALsrYRVrHNUJFSbXlxTzDnaIBVCjATNL1i9a7BaD4eW8nFq
kjJF1/rrW/+OKqJyFoRmzjPUjB2/B0NmkpvS2aWlPpJqfnstftj5G6pn9g11y1jC
6cb0CJIkMqeo6Nh9n2LViTICx/xIlvVEgupATabl98mv4szi5oh8fl2rTDbkbeja
UCiedv9xEtLZ0NQYGyeyZbR+WubXY/akxyWa+IQfCoholxDsMrYuH46KiphNqmMb
r9gNxHNQKccltcGEcd8UPSaNRNYY9tMi+ln19KnbUDvg2XrdvszmQxzzpaWrxPYn
GzMRtDZfAgMBAAECggEAaZP21j2nz85PgKNCa9uhAFrThewIMPSuROBdmhkA/0dW
jNkU2QRpAK5f2OdMB7478EL09x4BkGp7Ff16Ovb6I9tNAlWEPV5Zn0uNX04Hisrq
Opt8BcfiHzfx7yA2rbSt5NJ8oKfXJ9GUs4m4daV+PgFfJwEFG4G6Tub11nQyHWvv
M8GpFDbZMMCihaAiXuIw9sZjdxJAIgHV+5ShCLte7i5wIEi3kcVY+dy3vU6uGvdP
Oqc8R25ZtL4EM0+7j0mq+K4wvmitZBT80pBJc+jeJG+mu+igcNRCpzgdyzc6Qhjs
7vFoFmZwidTylpSYwN6jWa+Q2YcZTjFiCB0jjiN76QKBgQD+4EWRwu5Zo1EK9NFC
QIwe02IC0GRNOlnOUC72ViQ8zFATNeGLQQwB8reTyEk91MZ1D4LVezmjU6kVgawU
xvqdkCIxwbbR3lyDSzWHV92EokA6TpoApRAO8EECBF8G7o20w5Hv+lbVwaap14tI
g+0Isa22RtPa+t+n3KelT6V8OwKBgQDeC3B/48z5GZOzoSSye6UMiGQkPS5XipKW
JeWloWY82jE44e8jdQ6VzT5nTBq2DxOxlCrDBQTkBkPKp1mTnYhuDdBl5jxyF9U/
oxc1RI+FZP8kTDLS8eCtITjlw9pe8dmhkVbFcamIjh8mnWuuDIPK5LCqgyvrYXp9
/NqpwuIgLQKBgD0jvWyGzzhPdfxj1+LFqxcl6+fy52yjJ7HXCDztUwoGlNrW3QDT
nLbG64SW0gL0DJs+GkttoNjuE6xmC8p8JNgxIBLBfkJ/zb9tBi0uRaQwa6nQ+x5W
ejCrL1z1gXofNXz8QQDJE5V5O6qYWwANLYodXSdRfDaWYZpZ0xlTrsXLAoGBAMUt
92s6ig0zT1yW3xW4gysL+5HK2tpWbjHz2WkqWLX1NPzEdi5QhvE0YBQvGxFNdjmd
0BN644rynUTbM8rIfBzvG39B46+VxoNKexOMnL7in0hGemOk89YKyJIRSFxD/PVj
MWEIvHpNaxBJfxQCfQ6x4sioz1mpKLO01SEntNLJAoGAXodyQH8VczwLnJwkCfqW
qCWoh92ua4j4O0MgeHaQxlJjVC36ZU3rEu80E042q7YmND0eFwUZWeJiVyCdeYJt
stBAyzjSwGaD4/J3616vwK63CFqJA7KgnI1rz/M4vMjbAxhG67rethTObZTEFCUc
rgmnb1sqOBVc/gATuM4bcyw=
-----END PRIVATE KEY-----
"""

# EC P-256 named-curve self-signed CA.
EC_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUI6SSL/onOo3VgnPxqbSqkedq5KAwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQV2F6dWggVGVzdCBDQSBFQzAeFw0yNjA5MDgyMDU1NTdaFw0z
NjA5MDUyMDU1NTdaMBsxGTAXBgNVBAMMEFdhenVoIFRlc3QgQ0EgRUMwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARTtB3js9Tc/oYbfaUChZDLoN5gcS2iHypfm2FS
NLPMD9b36JfDq6szFKR0jWtdkTAhs2f04PABxuOLsulYpFkCo1MwUTAdBgNVHQ4E
FgQU/NA4KJqMsykyK5I9yLQa1r9sEOswHwYDVR0jBBgwFoAU/NA4KJqMsykyK5I9
yLQa1r9sEOswDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAXZ6K6
qmpfpBxPhgdQbMme6mfP1NVsdWrbNsqxkFc5VgIhANik3C8qTxfAMxAdYPt3blUB
8ZDE5FgX9kvQG65e522x
-----END CERTIFICATE-----
"""

# A DIFFERENT EC P-256 key, same subject CN -- the wrong-pin counterparty.
EC_OTHER_KEY_PEM = """\
-----BEGIN CERTIFICATE-----
MIIBijCCATGgAwIBAgIUC2ZHXbHBCKoAptlSUXTG96ArookwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQV2F6dWggVGVzdCBDQSBFQzAeFw0yNjA5MDgyMDU1NTdaFw0z
NjA5MDUyMDU1NTdaMBsxGTAXBgNVBAMMEFdhenVoIFRlc3QgQ0EgRUMwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARPvYvHaRAJNKxQifZkz99UNenUXVTj5T/yEcVz
CR7mUWHaaTyMKdltkl7JiOuELQkHu/43uURs9kyr6ykGosCZo1MwUTAdBgNVHQ4E
FgQUI2uEecdbVwOoL8WSubp7oHsHP5EwHwYDVR0jBBgwFoAUI2uEecdbVwOoL8WS
ubp7oHsHP5EwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBRTvA9
gTQBndRBjkvFlOj7B40mqO0xRd9Yf5akEMAKtQIgLjrAjTJgYyX5j3l2uIBKoYAr
0F/2hZNaSIyRJfNdY90=
-----END CERTIFICATE-----
"""

RSA_SPKI_HEX = 'fec81ce2566fa87091c419035cbccecffcc6f33803b778880ce8f3ea7c958df7'
RSA_SPKI_PIN = '_sgc4lZvqHCRxBkDXLzOz_zG8zgDt3iIDOjz6nyVjfc'
RSA_CERT_DER_SHA256_HEX = '1f2bd8df82f936f5b0a03713fe2823879c963feb7bd2ecc22b015f4001a8da4c'
EC_SPKI_HEX = '6496b4b63d812a00153aa6fdd29938bd8f81cf33cbe27a4fe6dc72bc0c3d5de0'
EC_SPKI_PIN = 'ZJa0tj2BKgAVOqb90pk4vY-BzzPL4npP5txyvAw9XeA'
EC_OTHER_SPKI_PIN = 'PtKvnGxrw6cpQGNmqQgVgsLp76OQHKsyNCslZkkheZ8'


# ---------------------------------------------------------------------------
# The pin computation.
# ---------------------------------------------------------------------------

def test_rsa_pin_matches_the_pinned_constant():
    assert spki_pin(RSA_CERT_PEM) == RSA_SPKI_PIN


def test_rsa_hex_matches_the_pinned_constant():
    assert spki_pin_hex(RSA_CERT_PEM) == RSA_SPKI_HEX


def test_ec_pin_and_hex_match_the_pinned_constants():
    assert spki_pin(EC_CERT_PEM) == EC_SPKI_PIN
    assert spki_pin_hex(EC_CERT_PEM) == EC_SPKI_HEX


def test_pin_is_43_unpadded_urlsafe_chars():
    for pem in (RSA_CERT_PEM, EC_CERT_PEM):
        pin = spki_pin(pem)
        assert len(pin) == 43
        # None of the three characters that would mean the standard alphabet
        # or padding leaked in.
        assert not set(pin) & set('=+/')


def test_hex_is_64_lowercase_hex_chars():
    for pem in (RSA_CERT_PEM, EC_CERT_PEM):
        value = spki_pin_hex(pem)
        assert len(value) == 64
        assert set(value) <= set('0123456789abcdef')


def test_pin_and_hex_encode_the_same_32_bytes():
    raw = spki_sha256(RSA_CERT_PEM)
    assert len(raw) == 32
    assert binascii.unhexlify(spki_pin_hex(RSA_CERT_PEM)) == raw
    # '=' padding restored so the standard decoder accepts the 43-char form.
    assert base64.urlsafe_b64decode(spki_pin(RSA_CERT_PEM) + '=') == raw


def test_same_key_different_certificate_same_pin():
    """The whole reason a token pins an SPKI and not a certificate."""
    assert spki_pin(RSA_CERT_PEM) == spki_pin(RSA_REISSUED_PEM) == RSA_SPKI_PIN
    # ...while the two certificates really are different documents.
    first = load_certificate(RSA_CERT_PEM)
    second = load_certificate(RSA_REISSUED_PEM)
    assert first.serial_number != second.serial_number
    assert first.subject != second.subject


def test_different_key_different_pin():
    assert spki_pin(EC_CERT_PEM) != spki_pin(EC_OTHER_KEY_PEM)
    assert spki_pin(EC_OTHER_KEY_PEM) == EC_OTHER_SPKI_PIN


def test_spki_digest_is_not_the_certificate_der_digest():
    """Both answers pinned, so hashing the wrong one cannot pass."""
    import hashlib
    from cryptography.hazmat.primitives import serialization

    certificate = load_certificate(RSA_CERT_PEM)
    der = certificate.public_bytes(serialization.Encoding.DER)
    assert hashlib.sha256(der).hexdigest() == RSA_CERT_DER_SHA256_HEX
    assert spki_pin_hex(RSA_CERT_PEM) == RSA_SPKI_HEX
    assert RSA_SPKI_HEX != RSA_CERT_DER_SHA256_HEX


def test_pem_der_and_certificate_object_inputs_agree(tmp_path):
    """load_certificate() accepts every form, and the digest does not care which."""
    from cryptography.hazmat.primitives import serialization

    certificate = load_certificate(RSA_CERT_PEM)
    der = certificate.public_bytes(serialization.Encoding.DER)

    assert spki_pin(certificate) == RSA_SPKI_PIN          # already parsed
    assert spki_pin(RSA_CERT_PEM) == RSA_SPKI_PIN          # PEM str
    assert spki_pin(RSA_CERT_PEM.encode()) == RSA_SPKI_PIN  # PEM bytes
    assert spki_pin(der) == RSA_SPKI_PIN                   # DER bytes


def test_pem_file_path_input_agrees(tmp_path):
    path = tmp_path / 'ca.pem'
    path.write_text(EC_CERT_PEM)
    assert spki_pin(path) == EC_SPKI_PIN       # pathlib.Path
    assert spki_pin(str(path)) == EC_SPKI_PIN  # str path


def test_garbage_and_empty_input_raise():
    for bad in (b'', b'not a certificate', RSA_KEY_PEM):
        with pytest.raises(Exception):
            spki_pin(bad)


def test_chain_hashes_the_first_certificate():
    """Must agree with the C++ side's AChainHashesTheFirstCertificate."""
    assert spki_pin((RSA_CERT_PEM + EC_CERT_PEM).encode()) == RSA_SPKI_PIN
    assert spki_pin((EC_CERT_PEM + RSA_CERT_PEM).encode()) == EC_SPKI_PIN


# ---------------------------------------------------------------------------
# The simulator's certificate exposure. No agent involved.
# ---------------------------------------------------------------------------

def test_tls_pin_is_readable_before_start():
    """The ordering the whole token flow depends on: pin first, then launch."""
    simulator = RemotedSimulator(port=44890)
    assert not simulator.running
    pin = simulator.tls_pin
    assert len(pin) == 43
    assert simulator.tls_pin_hex == binascii.hexlify(base64.urlsafe_b64decode(pin + '=')).decode()
    # And it is genuinely the certificate this instance will serve.
    assert spki_pin(simulator.tls_certificate_pem) == pin


def test_cacerts_certificate_is_distinct_from_the_listeners():
    simulator = RemotedSimulator(port=44891)
    assert simulator.cacerts_pem != simulator.tls_certificate_pem
    assert simulator.cacerts_pin != simulator.tls_pin
    assert len(simulator.cacerts_pin) == 43


def test_tls_pin_is_stable_across_restart():
    """A restart silently rotating the key would break every pin-based test."""
    simulator = RemotedSimulator(port=44892)
    before = simulator.tls_pin
    simulator.start()
    try:
        assert simulator.tls_pin == before
    finally:
        simulator.destroy()

    simulator.start()
    try:
        assert simulator.tls_pin == before
    finally:
        simulator.destroy()


def test_injected_tls_certificate_is_reported_and_served():
    """The hook the negative tests need: serve a certificate of our choosing."""
    simulator = RemotedSimulator(port=44893)
    simulator.tls_certificate = (RSA_CERT_PEM.encode(), RSA_KEY_PEM.encode())

    assert simulator.tls_pin == RSA_SPKI_PIN

    simulator.start()
    try:
        served = ssl.get_server_certificate(('127.0.0.1', 44893))
    finally:
        simulator.destroy()

    # What actually came off the wire is what tls_pin promised.
    assert spki_pin(served) == RSA_SPKI_PIN


def test_injected_cacerts_certificate_is_reported():
    simulator = RemotedSimulator(port=44894)
    simulator.cacerts_certificate = EC_CERT_PEM.encode()
    assert simulator.cacerts_pin == EC_SPKI_PIN
