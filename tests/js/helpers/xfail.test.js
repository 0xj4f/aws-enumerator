'use strict';
// Self-tests for tests/js/helpers/xfail.js.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { xfail, expectFailure, XPassError, XFailWrongReasonError, XFAIL_PREFIX } = require('./xfail');

test('expectFailure resolves when the body throws', async () => {
  const { error } = await expectFailure('sync throw', () => { throw new Error('still broken'); });
  assert.equal(error.message, 'still broken');
});

test('expectFailure resolves when the body rejects', async () => {
  const { error } = await expectFailure('async reject', async () => { throw new RangeError('nope'); });
  assert.ok(error instanceof RangeError);
});

test('expectFailure counts a failed assertion as the expected failure', async () => {
  await expectFailure('assert', () => assert.equal(1, 2), { raises: assert.AssertionError });
});

test('expectFailure rejects with "XPASS: remove xfail" when the body passes', async () => {
  await assert.rejects(expectFailure('fixed already', () => {}), (err) => {
    assert.ok(err instanceof XPassError);
    assert.match(err.message, /^XPASS: remove xfail \(fixed already\)$/);
    return true;
  });
  await assert.rejects(expectFailure('fixed async', async () => 42), XPassError);
});

test('raises: Error class, RegExp and predicate pin the failure reason', async () => {
  await expectFailure('class', () => { throw new TypeError('t'); }, { raises: TypeError });
  await expectFailure('regex', () => { throw new Error('undirected path found'); }, { raises: /undirected/ });
  await expectFailure('predicate', () => { throw Object.assign(new Error('x'), { code: 'E1' }); }, { raises: (e) => e.code === 'E1' });
  await expectFailure('Error itself', () => { throw new Error('plain'); }, { raises: Error });
});

test('raises mismatch fails as XFailWrongReasonError (never passes for the wrong reason)', async () => {
  await assert.rejects(expectFailure('wrong class', () => { throw new Error('generic'); }, { raises: TypeError }), XFailWrongReasonError);
  await assert.rejects(expectFailure('wrong text', () => { throw new Error('generic'); }, { raises: /specific/ }), XFailWrongReasonError);
  await assert.rejects(expectFailure('bad raises', () => { throw new Error('x'); }, { raises: 42 }), TypeError);
});

test('registered xfail names carry the [xfail] prefix', () => {
  assert.equal(XFAIL_PREFIX, '[xfail] ');
});

// A real registration: passes because the body fails as expected.
xfail('helpers self-check: a body that throws keeps the xfail green', () => {
  throw new Error('expected failure');
}, { raises: /expected failure/ });
