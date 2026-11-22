"""The Redfish reader after the 2026-11 review: the controller's credentials go to the scoped
controller only, whatever links it hands back, and nothing the controller should keep to itself is
in the document."""

import http.server
import json
import threading

import pytest

from pqch.scout import redfish
from tests.test_redfish_trust import _cert

MANAGER = "/redfish/v1/Managers/iDRAC.Embedded.1"
ATTRS = MANAGER + "/Oem/Dell/DellAttributes/iDRAC.Embedded.1"
# Attribute names as the lab's iDRAC 9 lists them (the values here are made up).
ATTRIBUTES = {
    "SSHCrypto.1.KexAlgorithms": "curve25519-sha256", "WebServer.1.TLSProtocol": "TLS 1.2 and Higher",
    "SNMP.1.AgentEnable": "Enabled", "SNMP.1.SNMPProtocol": "All", "SNMP.1.TrapFormat": "SNMPv1",
    "Security.1.FIPSMode": "Disabled", "SecurityCertificate.1.CertificateType": "Server", "SCV.1.CertificateVersion": "1",
    "SNMP.1.AgentCommunity": "s3cret-community", "IPMILan.1.CommunityName": "s3cret-community",
    "IPMILan.1.EncryptionKey": "0" * 40, "Users.2.IPMIKey": "A" * 64, "Users.2.SNMPv3AuthenticationPassphrase": "pass-one",
    "Users.2.SNMPv3PrivacyPassphrase": "pass-two", "Users.2.Password": "hunter2", "Users.2.UserName": "root",
    "NTPConfigGroup.1.NTP1SecurityKey": "ntp-key", "IPMILan.1.Enable": "Enabled", "Security.1.CsrKeySize": "2048",
    "WebServer.1.SessionToken": "tok",
}
SECRETS = ("s3cret-community", "0" * 40, "A" * 64, "pass-one", "pass-two", "hunter2", "ntp-key", "tok")


def _serve(tmp_path, routes, seen):
    c, k, _ = _cert(tmp_path)

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, bool(self.headers.get("Authorization"))))
            body = routes.get(self.path, {"Name": "x"})
            raw = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    import ssl
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(c, k)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def servers(tmp_path, monkeypatch):
    made = []

    def start(name, routes):
        seen = []
        srv = _serve(tmp_path / name, routes, seen)
        made.append(srv)
        return srv.server_address[1], seen
    f = tmp_path / "controller.env"
    f.write_text("REDFISH_USER=u\nREDFISH_PASSWORD=p\nREDFISH_TRUST=observed\n")
    monkeypatch.setattr(redfish, "CRED", f)
    yield start
    for s in made:
        s.shutdown()


def test_a_link_to_another_host_is_refused_and_no_credential_leaves_the_controller(servers):
    other_port, other_seen = servers("other", {})
    elsewhere = f"https://127.0.0.1:{other_port}/redfish/v1/steal"
    routes = {"/redfish/v1/UpdateService/FirmwareInventory": {"Members": [
        {"@odata.id": elsewhere}, {"@odata.id": f"//127.0.0.1:{other_port}/redfish/v1/x"},
        {"@odata.id": "/somewhere/else"}, {"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/Installed-1__BIOS"}]},
        "/redfish/v1/Systems/System.Embedded.1/SecureBoot/SecureBootDatabases": {"Members": [
            {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/SecureBoot/SecureBootDatabases/db"}]},
        "/redfish/v1/Systems/System.Embedded.1/SecureBoot/SecureBootDatabases/db": {
            "Certificates": {"@odata.id": elsewhere}, "Signatures": {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/SecureBoot/SecureBootDatabases/db/Signatures"}}}
    port, seen = servers("bmc", routes)
    doc = redfish.read("127.0.0.1", port)
    assert doc["authenticated"] is True
    assert other_seen == []                                       # nothing was sent to the other host, with or without credentials
    assert doc["links_refused"] == [elsewhere, f"//127.0.0.1:{other_port}/redfish/v1/x", "/somewhere/else", elsewhere]
    assert "/redfish/v1/UpdateService/FirmwareInventory/Installed-1__BIOS" in doc["resources"]
    assert "/redfish/v1/Systems/System.Embedded.1/SecureBoot/SecureBootDatabases/db/Signatures" in doc["resources"]
    assert elsewhere not in doc["resources"]
    assert all(path.startswith("/redfish/v1") for path, _ in seen)


@pytest.mark.parametrize("link,ok", [
    ("/redfish/v1/Managers/x", True), ("https://bmc.example/redfish/v1/x", False), ("//elsewhere/redfish/v1/x", False),
    ("/redfish/v1/../../etc", False), ("/redfish/v2/x", False), ("redfish/v1/x", False), (None, False), ({"a": 1}, False),
    ("/redfish/v1/a b", False), ("/redfish/v1/x\\@elsewhere", False)])
def test_only_the_controllers_own_redfish_paths_are_followed(link, ok):
    assert (redfish.own_path(link) is not None) is ok


def test_a_collection_longer_than_the_cap_is_cut_and_the_cut_is_recorded(servers, monkeypatch):
    monkeypatch.setattr(redfish, "MAX_MEMBERS", 3)
    inv = "/redfish/v1/UpdateService/FirmwareInventory"
    port, seen = servers("bmc", {inv: {"Members": [{"@odata.id": f"{inv}/Installed-{i}"} for i in range(10)]}})
    doc = redfish.read("127.0.0.1", port)
    assert doc["members_not_followed"] == {inv: 7}
    assert sum(1 for path, _ in seen if path.startswith(inv + "/")) == 3


def test_key_material_and_community_strings_never_reach_the_document(servers):
    routes = {ATTRS: {"Attributes": ATTRIBUTES},
              MANAGER + "/NetworkProtocol": {"SNMP": {"ProtocolEnabled": True, "CommunityStrings": [{"CommunityString": "s3cret-community"}],
                                                      "AuthenticationProtocol": "HMAC_SHA96"},
                                             "HTTPS": {"ProtocolEnabled": True, "Port": 443}},
              "/redfish/v1/Systems/System.Embedded.1/Bios": {"Attributes": {"Tpm2Algorithm": "SHA256", "SysPassword": "hunter2",
                                                                              "MemoryEncryption": "Disabled", "BootMode": "Uefi"}}}
    port, _ = servers("bmc", routes)
    doc = redfish.read("127.0.0.1", port)
    text = json.dumps(doc)
    assert not [s for s in SECRETS if s in text]
    kept = doc["resources"][ATTRS]["Attributes"]
    assert sorted(kept) == ["SCV.1.CertificateVersion", "SNMP.1.AgentEnable", "SNMP.1.SNMPProtocol", "SNMP.1.TrapFormat",
                            "SSHCrypto.1.KexAlgorithms", "Security.1.FIPSMode", "SecurityCertificate.1.CertificateType",
                            "WebServer.1.TLSProtocol"]
    assert doc["resources"]["/redfish/v1/Systems/System.Embedded.1/Bios"]["Attributes"] == {"MemoryEncryption": "Disabled", "Tpm2Algorithm": "SHA256"}
    snmp = doc["resources"][MANAGER + "/NetworkProtocol"]["SNMP"]
    assert snmp == {"ProtocolEnabled": True, "AuthenticationProtocol": "HMAC_SHA96"}
    assert doc["filtered"]["attributes_dropped"] == len(ATTRIBUTES) - 8 + 2 and "CommunityStrings" in doc["filtered"]["secret_field_names"]


def test_a_recording_made_before_the_filter_is_cleaned_by_the_same_function():
    """What `systems.recorded_job` and `export_recording` must pass a recording through."""
    old = {"schema": redfish.SCHEMA, "resources": {ATTRS: {"Attributes": dict(ATTRIBUTES)},
                                                   MANAGER: {"Model": "x", "Oem": {"Dell": {"RootPassword": "hunter2"}}}}}
    clean = redfish.sanitize(old)
    assert not [s for s in SECRETS if s in json.dumps(clean)]
    assert clean["resources"][MANAGER] == {"Model": "x", "Oem": {"Dell": {}}}
    assert redfish.sanitize(clean) == clean and ATTRIBUTES["Users.2.Password"] in json.dumps(old)   # the input is not changed


def test_a_body_that_is_not_json_is_recorded_and_the_read_goes_on(servers):
    port, _ = servers("bmc", {MANAGER + "/NetworkProtocol": b"<html>busy</html>"})
    doc = redfish.read("127.0.0.1", port)
    assert doc["resources"][MANAGER + "/NetworkProtocol"] == {"status": 200, "unreadable": "the body is not JSON"}
    assert "/redfish/v1/Systems/System.Embedded.1/Bios" in doc["resources"]
