"""The runner's apply acts only on the estate's own container for the service (resolution): one it would
recreate itself, from the same Compose files, running the image the scope pins. Anything else that
holds the address is refused, whatever its labels say."""

import json

import pytest

from pqch.runner import Refused, Runner
from pqch.runner.apply import Applier

from .conftest import SCOPE, _img

T = {"service": "portal", "address": "172.16.106.10", "port": 443}
DIGEST = _img("portal").split("@", 1)[1]


class Container:
    def __init__(self, labels, image=DIGEST, name="c1", config_image="pqch-agency/portal:m0"):
        self.id, self.name = "cid", name
        self.attrs = {"Image": image, "Config": {"Labels": labels, "Image": config_image}}


class Docker:
    def __init__(self, c):
        self.containers = self
        self.c = c

    def get(self, _cid):
        return self.c


@pytest.fixture
def applier(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps(SCOPE))
    agency = tmp_path / "agency"
    agency.mkdir()
    runner = Runner(scope, tmp_path / "raw", target_network="n", docker_client=None)
    runner.binding = lambda client, address, network=None: {"container_id": "cid", "address": address}
    a = Applier(runner, runs_dir=tmp_path / "runs", agency_dir=agency, log_dir=tmp_path / "log", signer=None)
    return a


def own(a, **extra):
    return {"com.docker.compose.project": "pqch-agency", "com.docker.compose.service": "portal",
            "com.docker.compose.project.config_files": ",".join(a.compose_files), "com.docker.compose.oneoff": "False", **extra}


def test_the_estates_own_container_is_accepted(applier):
    assert applier._container_at(Docker(Container(own(applier))), T)["container_id"] == "cid"


@pytest.mark.parametrize("why, container", [
    ("another project", lambda a: Container({**own(a), "com.docker.compose.project": "other"})),
    ("another service", lambda a: Container({**own(a), "com.docker.compose.service": "api"})),
    ("labels copied, started from other files", lambda a: Container({**own(a), "com.docker.compose.project.config_files": "/tmp/evil/compose.yaml"})),
    ("not started by Compose at all", lambda a: Container({"com.docker.compose.project": "pqch-agency", "com.docker.compose.service": "portal"})),
    ("a one-off compose run", lambda a: Container({**own(a), "com.docker.compose.oneoff": "True"})),
    ("a rehearsal copy", lambda a: Container({**own(a), "pqch.twin": "portal"})),
    ("the right labels on another image", lambda a: Container(own(a), image="sha256:" + "0" * 64)),
])
def test_anything_else_holding_the_address_is_refused(applier, why, container):
    with pytest.raises(Refused) as e:
        applier._container_at(Docker(container(applier)), T)
    assert e.value.code == 403, why
