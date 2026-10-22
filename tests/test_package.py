from pqch.migrator.package import entries, unblock

SNAP = {"services": {
    "sftp": {"software": "OpenSSH 6.6 (Ubuntu 14.04)", "pq": {"kex": [], "sig": []}},
    "bastion": {"software": "OpenSSH 10.0 (Alpine)", "pq": {"kex": ["mlkem768x25519-sha256"], "sig": []}},
    "queue": {"software": "RabbitMQ 4 on Erlang/OTP", "pq": {"kex": [], "sig": []}},
}}


def test_an_upgrade_path_is_the_same_product_listing_it_elsewhere_in_the_estate():
    assert unblock("sftp", "key-establishment", SNAP) == [
        {"service": "bastion", "software": "OpenSSH 10.0 (Alpine)", "lists": ["mlkem768x25519-sha256"]}]
    assert unblock("sftp", "signature", SNAP) == []          # no OpenSSH here lists a PQ signature
    assert unblock("queue", "key-establishment", SNAP) == []  # no other RabbitMQ at all


def _finding(eid, host, port, role, name, fp, layer="wire", path=None):
    subject = {"kind": "file", "image": "img", "path": path} if path else {"kind": "endpoint", "host": host, "port": port, "protocol": "ssh"}
    return {"id": eid, "type": "finding.observed", "payload": {"layer": layer, "fingerprint": fp, "subject": subject,
                                                               "asset": {"role": role, "name": name, "type": "algorithm"}}}


def test_a_package_covers_its_services_entries_for_the_function_and_their_files():
    ev = [
        {"id": "L1", "type": "link.asserted", "payload": {"kind": "served-by", "from": {"kind": "endpoint", "host": "10.0.0.2", "port": 22},
                                                          "to": {"kind": "service", "name": "sftp"}}},
        _finding("F1", "10.0.0.2", 22, "signature", "RSA", "a"),
        _finding("F2", "10.0.0.2", 22, "key-establishment", "DH-1024", "b"),
        _finding("F3", "10.0.0.9", 22, "signature", "RSA", "c"),                 # another service's listener
        _finding("F4", None, None, "other", "RSA", "d", layer="host", path="/etc/ssh/ssh_host_rsa_key"),
        {"id": "L2", "type": "link.asserted", "payload": {"kind": "served-from", "from": "F1", "to": "F4"}},
    ]
    sig = entries(ev, "sftp", "signature")
    assert [(e["fingerprint"], e["listener"]) for e in sig] == [("a", "10.0.0.2:22")]
    assert sig[0]["files"] == [{"fingerprint": "d", "path": "/etc/ssh/ssh_host_rsa_key", "image": "img"}]
    assert [e["name"] for e in entries(ev, "sftp", "key-establishment")] == ["DH-1024"]


def test_the_matrix_names_what_a_change_does_to_each_kind_of_client():
    from pqch.verifier.matrix import clients_for, effect

    assert effect("accepted", "refused") == "shut out" and effect("refused", "accepted") == "let in"
    assert effect("accepted", "accepted") == "unchanged, served" and effect("error", "accepted") == "cannot tell"
    pg = clients_for({"kind": "wire-kex", "target": {"protocol": "postgres"}})
    assert all(c["job"][0].endswith("-postgres") for c in pg)
    assert clients_for({"kind": "ssh-kex"})[0]["job"] == ("ssh-kex-probe", {"kex": "mlkem768x25519-sha256"})
