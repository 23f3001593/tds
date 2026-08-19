const express = require('express');
const app = express();
app.use(express.json());

const SHA_RE = /^[0-9a-f]{40}$/;

const REQUIRED_PERMISSIONS = {
  contents: 'read',
  packages: 'write',
  'id-token': 'none',
};

function evaluate(body) {
  const violations = [];

  const target = body && body.target;
  const event = body && body.event;
  const ref = body && body.ref;
  const workflow = (body && body.workflow) || {};
  const image = (body && body.image) || {};
  const permissions = workflow.permissions || {};
  const actions = Array.isArray(workflow.actions) ? workflow.actions : [];

  // 1. EXCESS_PERMISSION - permissions must be EXACTLY the three required
  //    scopes, exact values, and no extra keys.
  const permKeys = Object.keys(permissions);
  const requiredKeys = Object.keys(REQUIRED_PERMISSIONS);
  const hasExtraKeys = permKeys.some((k) => !requiredKeys.includes(k));
  const hasAllRequired = requiredKeys.every(
    (k) => permissions[k] === REQUIRED_PERMISSIONS[k]
  );
  if (hasExtraKeys || !hasAllRequired || permKeys.length !== requiredKeys.length) {
    violations.push('EXCESS_PERMISSION');
  }

  // 2. UNSAFE_PR_TRIGGER - pull_request_target is never allowed; a
  //    pull_request event must be driven by the pull_request trigger.
  if (workflow.trigger === 'pull_request_target') {
    violations.push('UNSAFE_PR_TRIGGER');
  } else if (event === 'pull_request' && workflow.trigger !== 'pull_request') {
    violations.push('UNSAFE_PR_TRIGGER');
  }

  // 3. TESTS_INCOMPLETE - tests must pass, matrix must fully run, and
  //    fail-fast must be disabled so the whole matrix always completes.
  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push('TESTS_INCOMPLETE');
  }

  // 4. MUTABLE_ACTION - actions/* may use a tag; any other owner must be
  //    pinned to a full 40-char lowercase hex commit SHA.
  const hasMutableAction = actions.some((a) => {
    if (!a) return true;
    if (a.owner === 'actions') return false;
    return typeof a.ref !== 'string' || !SHA_RE.test(a.ref);
  });
  if (hasMutableAction) {
    violations.push('MUTABLE_ACTION');
  }

  // 5. SINGLE_STAGE_IMAGE
  if (image.multiStage !== true) {
    violations.push('SINGLE_STAGE_IMAGE');
  }

  // 6. ROOT_RUNTIME
  if (image.runsAsRoot !== false) {
    violations.push('ROOT_RUNTIME');
  }

  // 7. SECRET_IN_LAYER - only "none" or "buildkit" secret mounting is safe.
  if (image.secretMode !== 'none' && image.secretMode !== 'buildkit') {
    violations.push('SECRET_IN_LAYER');
  }

  // 8. CRITICAL_CVE
  if (!(Number(image.criticalVulnerabilities) === 0)) {
    violations.push('CRITICAL_CVE');
  }

  // 9. UNPINNED_IMAGE
  if (image.digestPinned !== true) {
    violations.push('UNPINNED_IMAGE');
  }

  // 10 & 11. Production-only requirements.
  if (target === 'production') {
    if (!(event === 'push' && ref === 'refs/heads/main')) {
      violations.push('INVALID_PRODUCTION_REF');
    }
    if (workflow.environmentApproval !== true) {
      violations.push('APPROVAL_REQUIRED');
    }
  }

  return {
    decision: violations.length === 0 ? 'promote' : 'block',
    violations,
  };
}

app.post('/release-gate', (req, res) => {
  res.json(evaluate(req.body));
});

app.get('/', (_req, res) => res.send('release-gate service is up'));

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`release-gate listening on ${PORT}`));
}

module.exports = { app, evaluate };