"""M8, FR-03 (part): a management controller's session is trusted by a CA, a pin, or the certificate
seen first, recorded, and no credential is sent to a controller that fails it."""

import base64
import datetime
import hashlib
import http.server
import ipaddress
import json
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pqch.scout import redfish
from pqch.scout.normalize import platform_facts


def _cert(tmp_path, *, expired=False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idrac.test")])
    now = datetime.datetime.now(datetime.UTC)
    start, end = (now - datetime.timedelta(days=30), now - datetime.timedelta(days=1)) if expired else \
        (now - datetime.timedelta(days=1), now + datetime.timedelta(days=30))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(start).not_valid_after(end)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    c, k = tmp_path / "c.pem", tmp_path / "k.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return c, k, cert


@pytest.fixture
def controller(tmp_path):
    def start(expired=False):
        c, k, cert = _cert(tmp_path, expired=expired)
        seen = {"auth": 0}

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get("Authorization"):
                    seen["auth"] += 1
                body = json.dumps({"RedfishVersion": "1.0", "Model": "test"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(c, k)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv.server_address[1], cert, seen, c
    servers = []
    yield start
    for s in servers:
        s.shutdown()


def _settings(monkeypatch, tmp_path, **kv):
    f = tmp_path / "controller.env"
    f.write_text("REDFISH_USER=u\nREDFISH_PASSWORD=p\n" + "".join(f"{k}={v}\n" for k, v in kv.items()))
    monkeypatch.setattr(redfish, "CRED", f)


def test_without_a_setting_the_read_is_as_before_and_says_it_verified_nothing(controller, monkeypatch, tmp_path):
    port, cert, _seen, _ = controller()
    _settings(monkeypatch, tmp_path)
    doc = redfish.read("127.0.0.1", port)
    assert doc["authenticated"] is True and doc["trust"]["mode"] == "none"
    assert doc["trust"]["observed_sha256"] == hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def test_observed_holds_the_session_to_the_certificate_seen_and_the_ledger_carries_it(controller, monkeypatch, tmp_path):
    port, cert, _seen, _ = controller()
    _settings(monkeypatch, tmp_path, REDFISH_TRUST="observed")
    doc = redfish.read("127.0.0.1", port)
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    assert doc["authenticated"] is True and doc["trust"] == {"mode": "observed", "observed_sha256": fp, "pinned_sha256": fp}
    facts = platform_facts(json.dumps(doc).encode(), {"tool": "pqch-controller-redfish",
                                                      "target": {"controller": "127.0.0.1", "of": "box"}})
    assert facts["controller"]["trust"]["pinned_sha256"] == fp


def test_a_pin_the_controller_does_not_match_sends_no_credential(controller, monkeypatch, tmp_path):
    port, _, seen, _ = controller()
    _settings(monkeypatch, tmp_path, REDFISH_TRUST="pin", REDFISH_PIN_SHA256="0" * 64)
    doc = redfish.read("127.0.0.1", port)
    assert doc["authenticated"] is False and "not the pinned" in doc["trust"]["refused"] and seen["auth"] == 0


def test_a_ca_file_verifies_the_session_hostname_included(controller, monkeypatch, tmp_path):
    port, _, seen, pem = controller()
    _settings(monkeypatch, tmp_path, REDFISH_TRUST="ca", REDFISH_CA_PEM_B64=base64.b64encode(pem.read_bytes()).decode())
    doc = redfish.read("127.0.0.1", port)
    assert doc["authenticated"] is True and doc["trust"]["mode"] == "ca" and seen["auth"] >= 1


def test_an_expired_certificate_fails_observed_before_any_credential(controller, monkeypatch, tmp_path):
    port, _, seen, _ = controller(expired=True)
    _settings(monkeypatch, tmp_path, REDFISH_TRUST="observed")
    doc = redfish.read("127.0.0.1", port)
    assert doc["authenticated"] is False and "expired" in doc["trust"]["refused"] and seen["auth"] == 0


def test_a_pin_the_controller_matches_lets_the_session_through(controller, monkeypatch, tmp_path):
    port, cert, seen, _ = controller()
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    _settings(monkeypatch, tmp_path, REDFISH_TRUST="pin", REDFISH_PIN_SHA256=fp.upper())    # case does not matter
    doc = redfish.read("127.0.0.1", port)
    assert doc["authenticated"] is True and doc["trust"] == {"mode": "pin", "observed_sha256": fp, "pinned_sha256": fp}
    assert seen["auth"] >= 1


def test_a_ca_that_did_not_issue_the_certificate_sends_no_credential(controller, monkeypatch, tmp_path):
    port, _, seen, _ = controller()
    other, _, _ = _cert(tmp_path / "other")                       # a CA bundle holding a different certificate
    _settings(monkeypatch, tmp_path, REDFISH_TRUST="ca", REDFISH_CA_PEM_B64=base64.b64encode(other.read_bytes()).decode())
    doc = redfish.read("127.0.0.1", port)
    assert doc["authenticated"] is False and doc["trust"]["mode"] == "ca" and doc["trust"]["refused"]
    assert seen["auth"] == 0
