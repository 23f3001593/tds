import re
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


class ReleaseGateRequest(BaseModel):
    target: str | None = None
    event: str | None = None
    ref: str | None = None
    workflow: dict[str, Any] = {}
    image: dict[str, Any] = {}


def evaluate(body: dict[str, Any]) -> dict[str, Any]:
    violations: list[str] = []

    target = body.get("target")
    event = body.get("event")
    ref = body.get("ref")
    workflow = body.get("workflow") or {}
    image = body.get("image") or {}
    permissions = workflow.get("permissions") or {}
    actions = workflow.get("actions") or []
    if not isinstance(actions, list):
        actions = []

    # 1. EXCESS_PERMISSION
    perm_keys = set(permissions.keys())
    required_keys = set(REQUIRED_PERMISSIONS.keys())
    has_extra_keys = bool(perm_keys - required_keys)
    has_all_required = all(
        permissions.get(k) == v for k, v in REQUIRED_PERMISSIONS.items()
    )
    if has_extra_keys or not has_all_required or len(perm_keys) != len(required_keys):
        violations.append("EXCESS_PERMISSION")

    # 2. UNSAFE_PR_TRIGGER
    trigger = workflow.get("trigger")
    if trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    elif event == "pull_request" and trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. TESTS_INCOMPLETE
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. MUTABLE_ACTION
    def is_mutable(a: Any) -> bool:
        if not isinstance(a, dict):
            return True
        if a.get("owner") == "actions":
            return False
        ref_val = a.get("ref")
        return not isinstance(ref_val, str) or not SHA_RE.match(ref_val)

    if any(is_mutable(a) for a in actions):
        violations.append("MUTABLE_ACTION")

    # 5. SINGLE_STAGE_IMAGE
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. ROOT_RUNTIME
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. SECRET_IN_LAYER
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # 8. CRITICAL_CVE
    try:
        cves = float(image.get("criticalVulnerabilities"))
    except (TypeError, ValueError):
        cves = None
    if cves != 0:
        violations.append("CRITICAL_CVE")

    # 9. UNPINNED_IMAGE
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10 & 11. Production-only
    if target == "production":
        if not (event == "push" and ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }


@app.post("/release-gate")
def release_gate(req: ReleaseGateRequest):
    return evaluate(req.model_dump())


@app.get("/")
def root():
    return {"status": "release-gate service is up"}