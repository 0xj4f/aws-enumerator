'use strict';
// Expected-failure tests for node:test (the JS twin of pytest's xfail(strict=True)).
//
//   const { xfail } = require('../helpers/xfail');
//   xfail('[F-007] Discover All Paths is directed', () => { ...assert the FIXED behaviour... });
//   xfail('[F-040] weight 0 is honoured', fn, { raises: assert.AssertionError });
//
// - The test PASSES while `fn` throws or rejects (the bug is still there).
// - The test FAILS with "XPASS: remove xfail" once `fn` completes: the fix landed,
//   so the stream that fixed it must turn the xfail into a plain test().
// - `raises` (optional) pins the expected failure so the test never passes "for the
//   wrong reason": an Error class, a RegExp matched against the message, or a
//   predicate (err) => boolean. A non-matching error fails the test.
// - Registered names are prefixed with "[xfail] " so finding-coverage tooling can
//   tell an xfail that is still failing from a real passing test.

const test = require('node:test');

const XFAIL_PREFIX = '[xfail] ';

class XPassError extends Error {
  constructor(name) {
    super(`XPASS: remove xfail (${name})`);
    this.name = 'XPassError';
  }
}

class XFailWrongReasonError extends Error {
  constructor(name, err) {
    super(`xfail raised an unexpected error (${name}): ${err && err.stack ? err.stack : err}`);
    this.name = 'XFailWrongReasonError';
    this.cause = err;
  }
}

function matchesRaises(err, raises) {
  if (raises === undefined || raises === null) return true;
  if (raises instanceof RegExp) return raises.test(String(err && err.message !== undefined ? err.message : err));
  if (typeof raises === 'function') {
    if (raises.prototype instanceof Error || raises === Error) return err instanceof raises;
    return !!raises(err);
  }
  throw new TypeError('xfail: `raises` must be an Error class, a RegExp or a predicate');
}

/**
 * Run `fn` and resolve with {error} if it threw/rejected as expected.
 * Rejects with XPassError if it completed, XFailWrongReasonError if `raises` did not match.
 */
async function expectFailure(name, fn, { raises } = {}) {
  let error = null;
  let threw = false;
  try {
    await fn();
  } catch (err) {
    threw = true;
    error = err;
  }
  if (!threw) throw new XPassError(name);
  if (!matchesRaises(error, raises)) throw new XFailWrongReasonError(name, error);
  return { error };
}

/** Register an expected-failure node:test test. `options` may include node:test options plus `raises`. */
function xfail(name, fn, options = {}) {
  const { raises, ...testOptions } = options;
  return test(XFAIL_PREFIX + name, testOptions, async (t) => {
    const { error } = await expectFailure(name, () => fn(t), { raises });
    t.diagnostic(`xfail (expected failure): ${error && error.message !== undefined ? error.message : String(error)}`);
  });
}

module.exports = { xfail, expectFailure, XPassError, XFailWrongReasonError, XFAIL_PREFIX };
