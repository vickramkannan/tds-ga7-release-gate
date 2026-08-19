from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post("/release-gate")
def release_gate():
    data = request.get_json()

    violations = []

    workflow = data["workflow"]
    image = data["image"]

    # Permissions
    if workflow["permissions"] != {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }:
        violations.append("EXCESS_PERMISSION")

    # Pull request security
    if data["event"] == "pull_request":
        if workflow["trigger"] != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

        if not workflow["testsPassed"] or not workflow["matrixComplete"] or workflow["failFast"]:
            violations.append("TESTS_INCOMPLETE")

    # Action pinning
    for action in workflow["actions"]:
        if action["owner"] != "actions":
            ref = action["ref"]
            if not (
                len(ref) == 40
                and all(c in "0123456789abcdef" for c in ref)
            ):
                violations.append("MUTABLE_ACTION")
                break

    # Image security
    if not image["multiStage"]:
        violations.append("SINGLE_STAGE_IMAGE")

    if image["runsAsRoot"]:
        violations.append("ROOT_RUNTIME")

    if image["secretMode"] not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image["criticalVulnerabilities"] != 0:
        violations.append("CRITICAL_CVE")

    if not image["digestPinned"]:
        violations.append("UNPINNED_IMAGE")

    # Production requirements
    if data["target"] == "production":
        if data["event"] != "push" or data["ref"] != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return jsonify({
        "decision": "promote" if not violations else "block",
        "violations": violations
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
