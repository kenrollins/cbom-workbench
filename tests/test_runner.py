import json

import pytest

from pqch import scope as scope_mod
from pqch.runner import Refused, Runner

SCOPE = {
    "schema": "pqch.scope/1",
    "id": "01M40W6W873YWJMWPKGMK3YBMM",
    "estate": "colocated",
    "owned": True,
    "authorized_by": None,
    "endpoints": [
        {"host": "172.16.106.10", "port": 443, "transport": "tcp", "protocol": "tls", "sni": "portal.agency.test"},
        {"host": "172.16.106.20", "port": 22, "transport": "tcp", "protocol": "ssh"},
        {"host": "172.16.106.30", "port": 5432, "transport": "tcp", "protocol": "postgres"},
    ],
    "images": ["pqch-agency/portal@sha256:" + "b" * 64],
    "sources": [],
    "reach": {"kind": "local"},
}


class ExplodingDocker:
    """Any use of Docker fails the test: a refused job must touch nothing."""

    def __getattr__(self, name):
        raise AssertionError(f"docker.{name} used for a refused job")


@pytest.fixture
def runner(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(SCOPE))
    return Runner(p, tmp_path / "raw", target_network="net", docker_client=ExplodingDocker())


H = scope_mod.scope_hash(SCOPE)


@pytest.mark.parametrize("profile,target,code", [
    ("tls-targeted", {"host": "172.16.106.99", "port": 443}, 403),     # address not in scope
    ("tls-targeted", {"host": "172.16.106.10", "port": 8443}, 403),    # port not in scope
    ("tls-targeted", {"host": "10.20.33.201", "port": 4000}, 403),      # a gateway outside the scope
    ("ssh-targeted", {"host": "172.16.106.10", "port": 443}, 403),     # wrong protocol for profile
    ("image-theia", {"image": "nginx:latest"}, 403),                   # image not in scope
    ("shell", {"host": "172.16.106.10", "port": 443}, 400),            # not a profile
    ("tls-targeted", {"host": "172.16.106.10", "port": "443"}, 400),   # port is not an integer
    ("tls-targeted", {"host": ["172.16.106.10"], "port": 443}, 400),   # host is not a string
    ("tls-targeted", {}, 400),
])
def test_refuses_out_of_scope(runner, profile, target, code):
    with pytest.raises(Refused) as e:
        runner.run(profile, target, H)
    assert e.value.code == code


def test_refuses_a_different_scope(runner):
    with pytest.raises(Refused) as e:
        runner.run("tls-targeted", {"host": "172.16.106.10", "port": 443}, "0" * 64)
    assert e.value.code == 409


def test_accepts_in_scope_and_templates_args(runner):
    prof, _, ep = runner.check("tls-targeted", {"host": "172.16.106.10", "port": 443}, H)
    args = Runner._args(prof, ep)
    assert args[-1] == "https://portal.agency.test:443"
    assert "172.16.106.10" in args
    prof, _, ep = runner.check("ssh-targeted", {"host": "172.16.106.20", "port": 22}, H)
    assert Runner._args(prof, ep) == ["-j", "-p", "22", "172.16.106.20"]
    _, _, img = runner.check("image-theia", {"image": "pqch-agency/portal"}, H)
    assert img["image"] == SCOPE["images"][0]


def test_every_profile_image_is_pinned_by_digest_or_is_the_runners_own(runner):
    for name, prof in runner.profiles.items():
        assert prof["image"] == "self" or "@sha256:" in prof["image"], name


@pytest.mark.parametrize("params", [
    {"groups": "X25519; rm -rf /"}, {"groups": "X25519 -connect 10.20.33.201:4000"},
    {"tls13": "-tls1_2"}, {"extra": "x"}, {"groups": ["X25519"]},
])
def test_probe_parameters_are_refused_unless_they_match(runner, params):
    with pytest.raises(Refused) as e:
        runner.run("tls-group-probe", {"host": "172.16.106.10", "port": 443}, H, params)
    assert e.value.code == 400


def test_probe_arguments(runner):
    prof, _, ep = runner.check("tls-group-probe", {"host": "172.16.106.10", "port": 443}, H)
    values = runner.check_params(prof, {"groups": "X25519MLKEM768", "tls13": "-tls1_3"})
    cmd = Runner._args(prof, ep, values)[-1]
    assert "-connect 172.16.106.10:443 -servername portal.agency.test -groups X25519MLKEM768 -tls1_3" in cmd


def test_runner_holds_the_scope_it_started_with(runner):
    _, before = runner.scope()
    widened = {**SCOPE, "endpoints": [*SCOPE["endpoints"],
                                      {"host": "172.16.106.99", "port": 22, "transport": "tcp", "protocol": "ssh"}]}
    runner.scope_path.write_text(json.dumps(widened))
    assert runner.scope()[1] == before
    with pytest.raises(Refused) as e:
        runner.run("ssh-targeted", {"host": "172.16.106.99", "port": 22}, scope_mod.scope_hash(widened))
    assert e.value.code == 409


@pytest.mark.parametrize("field,value", [("host", "--file=/etc/passwd"), ("host", "a b"),
                                         ("sni", "x --connect-timeout 1"), ("sni", "-h"), ("protocol", "TLS x")])
def test_scope_rejects_values_that_would_read_as_scanner_options(field, value):
    from jsonschema import ValidationError

    from pqch import schemas
    bad = json.loads(json.dumps(SCOPE))
    bad["endpoints"][0][field] = value
    with pytest.raises(ValidationError):
        schemas.validate(bad)


def test_a_bundle_registry_changes_where_an_image_comes_from_not_which_image(runner, monkeypatch):
    d = "sha256:" + "a" * 64
    assert runner.resolve(f"ghcr.io/testssl/testssl.sh@{d}") == f"ghcr.io/testssl/testssl.sh@{d}"
    runner.registry = "127.0.0.1:5000"
    assert runner.resolve(f"ghcr.io/testssl/testssl.sh@{d}") == f"127.0.0.1:5000/testssl/testssl.sh@{d}"
    assert runner.resolve(f"positronsecurity/ssh-audit@{d}") == f"127.0.0.1:5000/positronsecurity/ssh-audit@{d}"


def test_scanners_pull_skips_the_runners_own_image(monkeypatch):
    """`pqch scanners pull` crashed on the probe profile's image "self"."""
    import docker

    from pqch.cli import main
    pulled = []

    class Images:
        def pull(self, repo, tag):
            pulled.append(f"{repo}@{tag}")

    class Client:
        images = Images()
    monkeypatch.setattr(docker, "from_env", lambda: Client())
    assert main(["scanners", "pull"]) == 0
    assert pulled and all("@sha256:" in p for p in pulled)


def test_a_postgres_listener_is_scanned_through_its_upgrade_and_by_no_plain_tls_profile(runner):
    """M0B review F-62: TLS after PostgreSQL's SSLRequest is a different conversation; a plain TLS
    scan of the port sees nothing, and the profile that speaks the upgrade must not be pointed at a
    plain TLS listener either."""
    with pytest.raises(Refused) as e:
        runner.check("tls-targeted", {"host": "172.16.106.30", "port": 5432}, H)
    assert e.value.code == 403
    with pytest.raises(Refused) as e:
        runner.check("tls-starttls-postgres", {"host": "172.16.106.10", "port": 443}, H)
    assert e.value.code == 403
    prof, _, ep = runner.check("tls-starttls-postgres", {"host": "172.16.106.30", "port": 5432}, H)
    args = Runner._args(prof, ep)
    assert args[args.index("--starttls") + 1] == "postgres"
    assert args[-1] == "https://172.16.106.30:5432" and "-E" in args



# ---- the scope's authorization: system, person, role and a window the runner enforces (M8, FR-13)

AUTH = {"system_id": "AGY-0042", "person": "Pat Example", "role": "system owner",
        "valid_from": "2026-11-01", "valid_until": "2026-11-30"}


def _authorized(tmp_path, auth, now):
    s = {**SCOPE, "authorized_by": "Pat Example", "authorization": auth}
    p = tmp_path / "scope-auth.json"
    p.write_text(json.dumps(s))
    r = Runner(p, tmp_path / "raw", target_network="net", docker_client=ExplodingDocker())
    r._now = lambda: now
    return r, scope_mod.scope_hash(s)


def test_a_job_inside_the_authorization_window_runs_and_outside_it_is_refused(tmp_path):
    from datetime import UTC, datetime
    target = {"host": "172.16.106.10", "port": 443}
    r, h = _authorized(tmp_path, AUTH, datetime(2026, 11, 30, 23, 59, tzinfo=UTC))   # the last day counts whole
    r.check("tls-targeted", target, h)
    for now, why in ((datetime(2026, 12, 1, 0, 0, 1, tzinfo=UTC), "expired 2026-11-30"),
                     (datetime(2026, 10, 31, 23, 0, tzinfo=UTC), "not yet valid")):
        r, h = _authorized(tmp_path, AUTH, now)
        with pytest.raises(Refused) as e:
            r.run("tls-targeted", target, h)
        assert e.value.code == 403 and why in e.value.reason and "AGY-0042" in e.value.reason


def test_a_scope_without_authorization_runs_as_before_unless_the_runner_requires_one(runner, monkeypatch):
    target = {"host": "172.16.106.10", "port": 443}
    runner.check("tls-targeted", target, H)
    monkeypatch.setenv("PQCH_REQUIRE_AUTHORIZATION", "1")
    with pytest.raises(Refused) as e:
        runner.check("tls-targeted", target, H)
    assert e.value.code == 403 and "requires one" in e.value.reason


def test_the_schema_holds_the_authorization_to_its_fields():
    import jsonschema

    from pqch import schemas
    ok = {**SCOPE, "authorized_by": "Pat Example", "authorization": {**AUTH, "valid_until": "2026-11-30T12:00:00Z",
                                                                    "rules_of_engagement_sha256": "a" * 64}}
    schemas.validate(ok)
    for bad in ({**ok, "authorization": {k: v for k, v in AUTH.items() if k != "role"}},
                {**ok, "authorization": {**AUTH, "valid_from": "next week"}},
                {**ok, "authorized_by": None}):          # an authorization names a person in authorized_by too
        with pytest.raises(jsonschema.ValidationError):
            schemas.validate(bad)


def test_an_impossible_date_is_a_refusal_with_a_reason():
    from datetime import UTC, datetime
    why = scope_mod.authorization_refusal({"authorization": {**AUTH, "valid_from": "2026-02-30"}},
                                          now=datetime(2026, 11, 5, tzinfo=UTC))
    assert "does not exist" in why


def test_an_authorization_that_ends_before_it_begins_is_refused():
    from datetime import UTC, datetime
    why = scope_mod.authorization_refusal({"authorization": {**AUTH, "valid_until": "2026-10-01"}},
                                          now=datetime(2026, 11, 5, tzinfo=UTC))
    assert "before it begins" in why


# ---- containers confined (M8, FR-04 part)

def test_every_job_gets_no_new_privileges_and_a_wire_probe_no_capability():
    from pqch.runner import load_profiles
    profiles = load_profiles()
    for name, prof in profiles.items():
        c = Runner.confinement(prof)
        assert c["security_opt"] == ["no-new-privileges:true"], name
        if prof["layer"] == "wire":
            assert c["cap_drop"] == ["ALL"] and "cap_add" not in c, name
        else:
            assert "cap_drop" not in c, name      # archive readers keep Docker's defaults until measured without
    assert Runner.confinement({"layer": "host", "caps": "none", "cap_add": ["DAC_READ_SEARCH"]}) == {
        "security_opt": ["no-new-privileges:true"], "cap_drop": ["ALL"], "cap_add": ["DAC_READ_SEARCH"]}


def test_the_harness_services_are_confined_in_compose():
    import yaml
    doc = yaml.safe_load(open("compose.yaml"))
    for name in ("runner", "signer", "app"):
        svc = doc["services"][name]
        assert svc["cap_drop"] == ["ALL"] and "no-new-privileges:true" in svc["security_opt"], name
    assert doc["services"]["signer"]["read_only"] is True and "/tmp" in doc["services"]["signer"]["tmpfs"]
    kit = yaml.safe_load(open("kit/compose.system.yaml"))["services"]
    assert kit["signer-system"]["read_only"] is True and "no-new-privileges:true" in kit["system-runner"]["security_opt"]
