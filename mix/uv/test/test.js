const test = require('node:test');
const assert = require('node:assert');
const { evaluate } = require('../server.js');

function basePayload(overrides = {}) {
  return {
    target: 'preview',
    event: 'pull_request',
    ref: 'refs/heads/feature/x',
    workflow: {
      trigger: 'pull_request',
      permissions: { contents: 'read', packages: 'write', 'id-token': 'none' },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [
        { owner: 'actions', name: 'checkout', ref: 'v4' },
        {
          owner: 'docker',
          name: 'build-push-action',
          ref: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
        },
      ],
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: 'none',
      criticalVulnerabilities: 0,
      digestPinned: true,
    },
    ...overrides,
  };
}

test('fully compliant preview payload promotes with no violations', () => {
  const result = evaluate(basePayload());
  assert.strictEqual(result.decision, 'promote');
  assert.deepStrictEqual(result.violations, []);
});

test('fully compliant production payload promotes', () => {
  const payload = basePayload({
    target: 'production',
    event: 'push',
    ref: 'refs/heads/main',
  });
  payload.workflow.trigger = 'push';
  payload.workflow.environmentApproval = true;
  const result = evaluate(payload);
  assert.strictEqual(result.decision, 'promote');
  assert.deepStrictEqual(result.violations, []);
});

test('extra permission scope flags EXCESS_PERMISSION', () => {
  const payload = basePayload();
  payload.workflow.permissions.actions = 'write';
  const result = evaluate(payload);
  assert.ok(result.violations.includes('EXCESS_PERMISSION'));
});

test('wrong permission value flags EXCESS_PERMISSION', () => {
  const payload = basePayload();
  payload.workflow.permissions['id-token'] = 'write';
  const result = evaluate(payload);
  assert.ok(result.violations.includes('EXCESS_PERMISSION'));
});

test('pull_request_target trigger flags UNSAFE_PR_TRIGGER', () => {
  const payload = basePayload();
  payload.workflow.trigger = 'pull_request_target';
  const result = evaluate(payload);
  assert.ok(result.violations.includes('UNSAFE_PR_TRIGGER'));
});

test('failing tests flags TESTS_INCOMPLETE', () => {
  const payload = basePayload();
  payload.workflow.testsPassed = false;
  const result = evaluate(payload);
  assert.ok(result.violations.includes('TESTS_INCOMPLETE'));
});

test('incomplete matrix flags TESTS_INCOMPLETE', () => {
  const payload = basePayload();
  payload.workflow.matrixComplete = false;
  const result = evaluate(payload);
  assert.ok(result.violations.includes('TESTS_INCOMPLETE'));
});

test('failFast true flags TESTS_INCOMPLETE', () => {
  const payload = basePayload();
  payload.workflow.failFast = true;
  const result = evaluate(payload);
  assert.ok(result.violations.includes('TESTS_INCOMPLETE'));
});

test('third-party action with tag ref flags MUTABLE_ACTION', () => {
  const payload = basePayload();
  payload.workflow.actions.push({ owner: 'docker', name: 'setup-buildx-action', ref: 'v3' });
  const result = evaluate(payload);
  assert.ok(result.violations.includes('MUTABLE_ACTION'));
});

test('actions-owned action may keep a version tag', () => {
  const payload = basePayload();
  payload.workflow.actions = [{ owner: 'actions', name: 'setup-node', ref: 'v4' }];
  const result = evaluate(payload);
  assert.ok(!result.violations.includes('MUTABLE_ACTION'));
});

test('single stage image flags SINGLE_STAGE_IMAGE', () => {
  const payload = basePayload();
  payload.image.multiStage = false;
  const result = evaluate(payload);
  assert.ok(result.violations.includes('SINGLE_STAGE_IMAGE'));
});

test('root runtime flags ROOT_RUNTIME', () => {
  const payload = basePayload();
  payload.image.runsAsRoot = true;
  const result = evaluate(payload);
  assert.ok(result.violations.includes('ROOT_RUNTIME'));
});

test('arg secret mode flags SECRET_IN_LAYER', () => {
  const payload = basePayload();
  payload.image.secretMode = 'arg';
  const result = evaluate(payload);
  assert.ok(result.violations.includes('SECRET_IN_LAYER'));
});

test('copy secret mode flags SECRET_IN_LAYER', () => {
  const payload = basePayload();
  payload.image.secretMode = 'copy';
  const result = evaluate(payload);
  assert.ok(result.violations.includes('SECRET_IN_LAYER'));
});

test('buildkit secret mode is allowed', () => {
  const payload = basePayload();
  payload.image.secretMode = 'buildkit';
  const result = evaluate(payload);
  assert.ok(!result.violations.includes('SECRET_IN_LAYER'));
});

test('critical vulnerabilities flags CRITICAL_CVE', () => {
  const payload = basePayload();
  payload.image.criticalVulnerabilities = 2;
  const result = evaluate(payload);
  assert.ok(result.violations.includes('CRITICAL_CVE'));
});

test('unpinned image flags UNPINNED_IMAGE', () => {
  const payload = basePayload();
  payload.image.digestPinned = false;
  const result = evaluate(payload);
  assert.ok(result.violations.includes('UNPINNED_IMAGE'));
});

test('production not on push/main flags INVALID_PRODUCTION_REF', () => {
  const payload = basePayload({
    target: 'production',
    event: 'pull_request',
    ref: 'refs/heads/feature/x',
  });
  payload.workflow.environmentApproval = true;
  const result = evaluate(payload);
  assert.ok(result.violations.includes('INVALID_PRODUCTION_REF'));
});

test('production without environmentApproval flags APPROVAL_REQUIRED', () => {
  const payload = basePayload({
    target: 'production',
    event: 'push',
    ref: 'refs/heads/main',
  });
  payload.workflow.trigger = 'push';
  const result = evaluate(payload);
  assert.ok(result.violations.includes('APPROVAL_REQUIRED'));
});

test('multi-failure payload reports all applicable codes', () => {
  const payload = basePayload({ target: 'production', event: 'push', ref: 'refs/heads/dev' });
  payload.workflow.trigger = 'push';
  payload.workflow.permissions['id-token'] = 'write';
  payload.workflow.testsPassed = false;
  payload.image.runsAsRoot = true;
  payload.image.criticalVulnerabilities = 5;
  const result = evaluate(payload);
  assert.strictEqual(result.decision, 'block');
  for (const code of [
    'EXCESS_PERMISSION',
    'TESTS_INCOMPLETE',
    'ROOT_RUNTIME',
    'CRITICAL_CVE',
    'INVALID_PRODUCTION_REF',
    'APPROVAL_REQUIRED',
  ]) {
    assert.ok(result.violations.includes(code), `expected ${code}`);
  }
});