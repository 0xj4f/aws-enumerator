"""Synthetic AWS worlds (python definitions) served by :mod:`tests.support.fakeaws`.

* :mod:`tests.fixtures.worlds.acme` - account 111122223333 answering every API the
  30 baseline collectors call, in eu-west-1 / eu-west-2 (+ us-east-1 for global
  services), with deny / not-found / throttle / BotoCoreError injections and
  secret canaries for redaction tests.
"""
