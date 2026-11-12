"""Detection tuning: validation, effect on the pipeline, and the admin API."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from app import tuning as tuning_mod
from app.classifier import rule_catalog
from app.pipeline import detect
from app.tuning import DEFAULT, RuleOverride, Tuning

SHADOW_DELETE = "vssadmin delete shadows /all /quiet"
SECRET = "test-admin-secret"
ADMIN = {"X-Admin-Secret": SECRET}


@pytest.fixture(autouse=True)
def _reset_active():
    tuning_mod.set_active(None)
    yield
    tuning_mod.set_active(None)


def _rule_id(signal_fragment: str) -> str:
    matches = [r["id"] for r in rule_catalog() if signal_fragment in r["signal"]]
    assert len(matches) == 1, matches
    return matches[0]


# ── model ────────────────────────────────────────────────────────────────────

def test_defaults_round_trip() -> None:
    assert tuning_mod.loads(tuning_mod.dumps(DEFAULT)).model_dump() == DEFAULT.model_dump()
    assert tuning_mod.is_default(DEFAULT)


@pytest.mark.parametrize("bad", [
    {"threshold_notable": 9, "threshold_suspicious": 7},
    {"threshold_malicious": 5},
    {"points_low": 12},
    {"class_weights": {"not_a_class": 1.0}},
    {"class_weights": {"impact": 9}},
    {"depth_step": -1},
    {"rules": {"x": {"precision": 2}}},
    {"surprise": 1},
])
def test_invalid_tuning_rejected(bad: dict) -> None:
    with pytest.raises(ValidationError):
        Tuning.model_validate(bad)


def test_unreadable_stored_tuning_falls_back_to_defaults() -> None:
    assert tuning_mod.loads("{not json") is DEFAULT
    assert tuning_mod.loads('{"threshold_malicious": 1}') is DEFAULT
    assert tuning_mod.loads("") is DEFAULT
    assert tuning_mod.loads(None) is DEFAULT


def test_partial_class_weights_keep_other_defaults() -> None:
    t = Tuning.model_validate({"class_weights": {"recon": 2.0}})
    assert t.class_weights["recon"] == 2.0
    assert t.class_weights["impact"] == DEFAULT.class_weights["impact"]


def test_rule_ids_are_unique_and_stable_shape() -> None:
    ids = [r["id"] for r in rule_catalog()]
    assert len(ids) == len(set(ids)) > 200
    assert all(":" in rid for rid in ids)


# ── effect on detection ──────────────────────────────────────────────────────

def test_disabling_a_rule_removes_its_signal() -> None:
    rid = _rule_id("Deletes or resizes VSS shadow copies")
    assert detect(SHADOW_DELETE).verdict["severity"] == "malicious"
    off = Tuning(rules={rid: RuleOverride(enabled=False)})
    det = detect(SHADOW_DELETE, off)
    assert all(rid not in tc.rule_ids for tc in det.threat_classes)
    assert det.verdict["severity"] != "malicious"


def test_precision_override_scales_the_score() -> None:
    rid = _rule_id("Deletes or resizes VSS shadow copies")
    full = detect(SHADOW_DELETE).verdict["score"]
    half = detect(SHADOW_DELETE, Tuning(rules={rid: RuleOverride(precision=0.5)})).verdict["score"]
    assert half == pytest.approx(full / 2, rel=0.01)


def test_thresholds_move_the_verdict_not_the_score() -> None:
    strict = Tuning(threshold_malicious=40, threshold_suspicious=30, threshold_notable=20)
    base, moved = detect(SHADOW_DELETE), detect(SHADOW_DELETE, strict)
    assert moved.verdict["score"] == base.verdict["score"]
    assert base.verdict["severity"] == "malicious"
    assert moved.verdict["severity"] == "low"


def test_class_weight_scales_that_class_only() -> None:
    zero_impact = Tuning.model_validate({"class_weights": {"impact": 0}})
    assert detect(SHADOW_DELETE, zero_impact).verdict["score"] < detect(SHADOW_DELETE).verdict["score"]
    other = "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save"
    assert detect(other, zero_impact).verdict["score"] == detect(other).verdict["score"]


def test_candidate_tuning_does_not_leak_into_active() -> None:
    detect(SHADOW_DELETE, Tuning(threshold_malicious=90, threshold_suspicious=60, threshold_notable=40))
    assert detect(SHADOW_DELETE).verdict["severity"] == "malicious"


# ── admin API ────────────────────────────────────────────────────────────────

@pytest.fixture
def admin_api(client):
    saved: dict[str, str] = {}

    async def _set(key: str, value: str) -> None:
        saved[key] = value

    with (
        patch("app.main._ADMIN_SECRET", SECRET),
        patch("app.main.set_setting", new=AsyncMock(side_effect=_set)),
    ):
        yield client, saved


@pytest.mark.anyio
@pytest.mark.parametrize(("method", "path"), [
    ("get", "/admin/tuning"), ("put", "/admin/tuning"), ("delete", "/admin/tuning"),
    ("post", "/admin/tuning/preview"), ("post", "/admin/tuning/benchmark"),
])
async def test_tuning_endpoints_require_admin(admin_api, method: str, path: str) -> None:
    client, _ = admin_api
    resp = await client.request(method, path, json={})
    assert resp.status_code == 403
    resp = await client.request(method, path, json={}, headers={"X-Admin-Secret": "wrong"})
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_get_tuning_lists_defaults_and_rules(admin_api) -> None:
    client, _ = admin_api
    body = (await client.get("/admin/tuning", headers=ADMIN)).json()
    assert body["is_default"] is True
    assert body["active"] == body["defaults"]
    assert len(body["rules"]) > 200
    assert {"id", "class", "signal", "confidence", "precision"} <= set(body["rules"][0])


@pytest.mark.anyio
async def test_save_activates_and_persists(admin_api) -> None:
    client, saved = admin_api
    candidate = {**DEFAULT.model_dump(), "threshold_malicious": 40, "threshold_suspicious": 30,
                 "threshold_notable": 20}
    resp = await client.put("/admin/tuning", json=candidate, headers=ADMIN)
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_default"] is False
    assert tuning_mod.SETTING_KEY in saved
    assert tuning_mod.loads(saved[tuning_mod.SETTING_KEY]).threshold_malicious == 40
    # New analyses use it…
    analysis = (await client.post("/analyze", json={"command": SHADOW_DELETE})).json()
    assert analysis["verdict"]["severity"] == "low"
    # …and reset restores the defaults.
    resp = await client.delete("/admin/tuning", headers=ADMIN)
    assert resp.json()["is_default"] is True
    assert detect(SHADOW_DELETE).verdict["severity"] == "malicious"


@pytest.mark.anyio
async def test_save_rejects_invalid_and_unknown(admin_api) -> None:
    client, saved = admin_api
    bad = {**DEFAULT.model_dump(), "threshold_malicious": 1}
    resp = await client.put("/admin/tuning", json=bad, headers=ADMIN)
    assert resp.status_code == 422
    assert resp.json()["code"] == "invalid_request"
    ghost = {**DEFAULT.model_dump(), "rules": {"impact:deadbeef": {"enabled": False}}}
    resp = await client.put("/admin/tuning", json=ghost, headers=ADMIN)
    assert resp.status_code == 422
    assert not saved
    assert tuning_mod.is_default(tuning_mod.get_active())


@pytest.mark.anyio
async def test_preview_compares_without_storing_or_activating(admin_api) -> None:
    client, saved = admin_api
    candidate = {**DEFAULT.model_dump(), "threshold_malicious": 40, "threshold_suspicious": 30,
                 "threshold_notable": 20}
    resp = await client.post("/admin/tuning/preview", headers=ADMIN,
                             json={"command": SHADOW_DELETE, "tuning": candidate})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["active"]["severity"] == "malicious"
    assert body["candidate"]["severity"] == "low"
    assert body["candidate"]["classes"][0]["rule_ids"]
    assert not saved
    assert tuning_mod.is_default(tuning_mod.get_active())


@pytest.mark.anyio
async def test_benchmark_reports_regressions_of_a_bad_candidate(admin_api) -> None:
    client, _ = admin_api
    lax = {**DEFAULT.model_dump(), "threshold_malicious": 95, "threshold_suspicious": 70,
           "threshold_notable": 45}
    resp = await client.post("/admin/tuning/benchmark", headers=ADMIN, json={"tuning": lax})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["available"] is True
    first = body["sets"][0]
    assert first["active"]["caught"] == first["attacks"]
    assert first["candidate"]["caught"] < first["attacks"]
    assert body["changes"] and body["failing"]
    assert body["rule_hits"]
