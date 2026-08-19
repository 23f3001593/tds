from main import evaluate


def base_payload(**overrides):
    payload = {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature/x",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {
                    "owner": "docker",
                    "name": "build-push-action",
                    "ref": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                },
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }
    payload.update(overrides)
    return payload


def test_compliant_preview_promotes():
    result = evaluate(base_payload())
    assert result["decision"] == "promote"
    assert result["violations"] == []


def test_compliant_production_promotes():
    payload = base_payload(target="production", event="push", ref="refs/heads/main")
    payload["workflow"]["trigger"] = "push"
    payload["workflow"]["environmentApproval"] = True
    result = evaluate(payload)
    assert result["decision"] == "promote"
    assert result["violations"] == []


def test_excess_permission():
    payload = base_payload()
    payload["workflow"]["permissions"]["actions"] = "write"
    assert "EXCESS_PERMISSION" in evaluate(payload)["violations"]


def test_unsafe_pr_trigger():
    payload = base_payload()
    payload["workflow"]["trigger"] = "pull_request_target"
    assert "UNSAFE_PR_TRIGGER" in evaluate(payload)["violations"]


def test_tests_incomplete_failfast():
    payload = base_payload()
    payload["workflow"]["failFast"] = True
    assert "TESTS_INCOMPLETE" in evaluate(payload)["violations"]


def test_mutable_action():
    payload = base_payload()
    payload["workflow"]["actions"].append({"owner": "docker", "name": "x", "ref": "v3"})
    assert "MUTABLE_ACTION" in evaluate(payload)["violations"]


def test_single_stage_image():
    payload = base_payload()
    payload["image"]["multiStage"] = False
    assert "SINGLE_STAGE_IMAGE" in evaluate(payload)["violations"]


def test_root_runtime():
    payload = base_payload()
    payload["image"]["runsAsRoot"] = True
    assert "ROOT_RUNTIME" in evaluate(payload)["violations"]


def test_secret_in_layer():
    payload = base_payload()
    payload["image"]["secretMode"] = "arg"
    assert "SECRET_IN_LAYER" in evaluate(payload)["violations"]


def test_critical_cve():
    payload = base_payload()
    payload["image"]["criticalVulnerabilities"] = 3
    assert "CRITICAL_CVE" in evaluate(payload)["violations"]


def test_unpinned_image():
    payload = base_payload()
    payload["image"]["digestPinned"] = False
    assert "UNPINNED_IMAGE" in evaluate(payload)["violations"]


def test_invalid_production_ref():
    payload = base_payload(target="production", event="pull_request", ref="refs/heads/x")
    payload["workflow"]["environmentApproval"] = True
    assert "INVALID_PRODUCTION_REF" in evaluate(payload)["violations"]


def test_approval_required():
    payload = base_payload(target="production", event="push", ref="refs/heads/main")
    payload["workflow"]["trigger"] = "push"
    assert "APPROVAL_REQUIRED" in evaluate(payload)["violations"]