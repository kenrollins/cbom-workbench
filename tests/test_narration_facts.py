"""What a plan row tells the narrator: facts a model cannot misread, and a check that lets a line repeat them."""

from pqch.planning import _kex_state
from pqch.ui.demo import narration_check, narration_facts, narration_row


def test_key_establishment_is_read_on_its_own_not_from_the_posture():
    # `mixed` posture is a post-quantum key exchange with a classical certificate: nothing classical is negotiated.
    assert _kex_state({"posture": "mixed", "kex_pq": ["X25519MLKEM768"], "kex_classical": []}) == "pq-only"
    assert _kex_state({"kex_pq": ["X25519MLKEM768"], "kex_classical": ["X25519"]}) == "both"
    assert _kex_state({"kex_pq": [], "kex_classical": ["X25519"]}) == "classical-only"
    assert _kex_state({"kex_pq": [], "kex_pq_not_standardised": ["sntrup761x25519"]}) == "classical-only"
    assert _kex_state({}) is None


def test_a_finished_step_is_told_as_finished_and_a_row_may_name_the_service_its_step_names():
    done = narration_row({"service": "records-db", "kex_state": ["pq-only"], "blocked": [], "criteria": ["high-impact"],
                          "step": {"title": "Require the hybrid group on records-db", "state": "done"}}, 0)
    facts = narration_facts(done)
    assert facts["key_exchange_today"].startswith("a post-quantum hybrid group only")
    assert facts["next_step"].startswith("none for key exchange") and "is done" in facts["next_step"]
    row = narration_row({"service": "sftp-legacy", "kex_state": ["classical-only"], "blocked": ["key-establishment"], "criteria": [],
                         "step": {"title": "Upgrade sftp-legacy to the OpenSSH the estate already runs on bastion", "state": "ready"}}, 1)
    services = ["records-db", "sftp-legacy", "bastion", "portal"]
    assert narration_check("The sftp-legacy service is rank 2; next it is upgraded to the bastion OpenSSH.", row, services=services)["ok"]
    assert not narration_check("The sftp-legacy service is rank 2, like the portal.", row, services=services)["ok"]
