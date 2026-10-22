from pqch.planning import _topo, _traps


def test_steps_follow_their_dependencies_then_deadline_then_priority():
    steps = {
        "reissue:a": {"id": "reissue:a", "depends_on": ["ca:x"], "due": "2031-12-31", "service": "a"},
        "ca:x": {"id": "ca:x", "depends_on": ["replace:b"], "due": "2031-12-31", "service": None},
        "replace:b": {"id": "replace:b", "depends_on": [], "due": "2030-12-31", "service": "b"},
        "require:c": {"id": "require:c", "depends_on": [], "due": "2030-12-31", "service": "c"},
    }
    order = _topo(steps, {"c": 0, "b": 1, "a": 2})
    assert order.index("replace:b") < order.index("ca:x") < order.index("reissue:a")
    assert order[0] == "require:c"       # same deadline as replace:b, higher priority


def test_the_ca_trap_names_the_services_that_hold_the_root_back():
    deps = [{"kind": "certificate-authority", "id": "ca:x", "name": "CN=Internal CA", "services": ["a", "b", "c"], "what": "", "consequence": ""}]
    steps = {"ca:x": {"id": "ca:x", "kind": "ca", "depends_on": ["replace:b"], "state": "waiting"}}
    t = _traps(deps, steps, [], set())
    assert "b cannot verify ML-DSA" in t[0]["cbom"] and "3 services chain to one internal CA" in t[0]["cbom"]


def test_the_lab_plan_names_the_server_or_the_clients_as_the_blocker():
    from pqch.planning import lab_build

    capture = {"run": "R", "inside_servers": [
        {"host": "10.0.0.5", "port": 443, "handshakes": 100, "hybrid_offered": 80},   # refuses what clients offer
        {"host": "10.0.0.6", "port": 443, "handshakes": 50, "hybrid_offered": 0}],    # accepts, never offered
        "ssh": [], "vlans": [{"vlan": 28, "clients": 3, "hybrid": 1, "classical13": 1, "legacy": 1}]}
    comp = lambda host, vl: {"properties": [{"name": "pqch:subject", "value": '{"kind": "endpoint", "host": "%s", "port": 443}' % host},
                                            {"name": "pqch:parameters", "value": '{"client_vlans": {"%d": 10}}' % vl}]}
    house = {"entries": 4, "doc": {"components": [comp("10.0.0.5", 28), comp("10.0.0.6", 28)]}, "listeners": [
        {"address": "10.0.0.5:443", "protocol": "tls", "layers": ["capture", "scan"], "hybrid_accepted": [], "hybrid_chosen": 0, "certs": []},
        {"address": "10.0.0.6:443", "protocol": "tls", "layers": ["capture", "scan"], "hybrid_accepted": ["X25519MLKEM768"], "hybrid_chosen": 0, "certs": []}]}
    p = lab_build(capture, house)
    steps = {s["id"]: s for w in p["waves"] for s in w["steps"]}
    assert "the server is the blocker" in steps["enable:10.0.0.5:443"]["why"]
    assert steps["require:10.0.0.5:443"]["depends_on"] == ["enable:10.0.0.5:443", "clients:28"]
    assert "refuse 20 of 100 handshakes (20%)" in steps["require:10.0.0.5:443"]["why"]
    assert "enabled, never used" in steps["require:10.0.0.6:443"]["why"]


def test_a_what_if_frees_what_waited_on_the_assumed_step():
    from pqch.planning import _settle

    steps = {"replace:b": {"id": "replace:b", "depends_on": [], "state": "ready"},
             "ca:x": {"id": "ca:x", "depends_on": ["replace:b"], "state": "ready"},
             "reissue:a": {"id": "reissue:a", "depends_on": ["ca:x"], "state": "ready"}}
    assert _settle(steps, frozenset({"replace:b"})) == ["ca:x"]
    assert steps["replace:b"]["assumed"] and steps["reissue:a"]["state"] == "waiting"
