"""fingerprint: keyed one-way fingerprints for agents-doctor evidence.

Findings carry fingerprints instead of raw secrets. This module replaces
the old public-salt SHA-256 with HMAC-SHA256 keyed by a per-installation
secret: fingerprints stay stable on one machine (the same secret gets the
same fingerprint in every scan) but cannot be computed, compared or
rainbow-tabled anywhere else.

Key location (override with the AGENTS_DOCTOR_KEY_PATH environment
variable; an empty value is ignored - the variable exists for tests and
power users who want the key on another volume):
- Windows: %LOCALAPPDATA%\\agents-doctor\\secret_key, falling back to
  ~\\AppData\\Local when LOCALAPPDATA is unset. The key file inherits the
  NTFS ACLs of the user profile; the stdlib has no ACL API, so no Windows
  permission enforcement is claimed - the guarantee is only that the key
  stays inside the user's local profile directory.
- POSIX: $XDG_CONFIG_HOME/agents-doctor/secret_key, default
  ~/.config/agents-doctor/secret_key. The directory is created 0o700
  and the key file is written 0o600 (umask permitting).

Key material: 32 random bytes (secrets.token_bytes). A key file that
cannot be read or holds fewer than 16 bytes raises FingerprintKeyError;
the error message carries the path and the reason, never the key bytes.

No silent fallback: with create=False and no key, or with a broken key,
callers get FingerprintKeyError and decide themselves. This module never
falls back to a public salt.

Format: 'hmac256:' + 32 hex chars (128 bits). The key reaches one thing
only: the fingerprint values of secrets in a report, which tell that
two findings are the same secret. The identifiers that baselines and
the audit history compare are built from the file, the line and the
kind, so a different key never produces a diff by itself.

CLI self-test: python fingerprint.py --check
"""

import hashlib
import hmac
import os
import secrets
import sys
from pathlib import Path

KEY_BYTES = 32
MIN_KEY_BYTES = 16
ENV_KEY_PATH = 'AGENTS_DOCTOR_KEY_PATH'


class FingerprintKeyError(Exception):
    """The per-installation key is missing, unreadable or malformed."""


def key_path():
    """Location of the key file. AGENTS_DOCTOR_KEY_PATH wins when set."""
    override = os.environ.get(ENV_KEY_PATH)
    if override:
        return Path(override)
    if os.name == 'nt':
        base = os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData' / 'Local'
        return Path(base) / 'agents-doctor' / 'secret_key'
    base = os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config'
    return Path(base) / 'agents-doctor' / 'secret_key'


def get_key(create=True):
    """Load the key, creating it (32 random bytes) when missing.

    create=False with no key file raises FingerprintKeyError. An existing
    file that cannot be read or holds fewer than MIN_KEY_BYTES raises
    FingerprintKeyError; the message never contains key material.
    """
    path = key_path()
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        if not create:
            raise FingerprintKeyError(
                'no fingerprint key at %s and create is disabled' % path) from None
        return _create_key(path)
    except OSError as exc:
        raise FingerprintKeyError(
            'cannot read the fingerprint key file %s: %s' % (path, exc)) from None
    if len(data) < MIN_KEY_BYTES:
        raise FingerprintKeyError(
            'fingerprint key at %s is invalid: %d bytes, at least %d required'
            % (path, len(data), MIN_KEY_BYTES))
    return data


def _create_key(path):
    try:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise FingerprintKeyError(
            'cannot create the fingerprint key file %s: %s' % (path, exc)) from None
    # verified creation: some filesystem filter drivers duplicate the
    # final byte at fsync/close, and the mangling is deterministic in
    # that byte's value (reproduced on Windows: ~11% of random keys
    # corrupt on EVERY write, the rest never). Two consequences:
    # - the check must re-open the path after close: the writing fd
    #   still sees the clean page cache;
    # - each retry draws FRESH random bytes: retrying the same data
    #   would fail every time.
    last_exc = None
    for _attempt in range(4):
        data = secrets.token_bytes(KEY_BYTES)
        try:
            fd = os.open(str(path),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return get_key()  # another process created it first
        except OSError as exc:
            last_exc = exc
            continue
        try:
            written = 0
            while written < len(data):
                written += os.write(fd, data[written:])
            os.fsync(fd)
            data_written = True
        except OSError as exc:
            last_exc = exc
            data_written = False
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        if data_written:
            try:
                landed = path.read_bytes()
            except OSError as exc:
                last_exc = exc
                landed = None
            if landed == data:
                return data
        try:
            path.unlink()
        except OSError:
            pass
    raise FingerprintKeyError(
        'cannot create the fingerprint key file %s: verification failed '
        '(%s)' % (path, last_exc or 'write does not match'))


def fingerprint(value):
    """'hmac256:' + first 32 hex chars of HMAC-SHA256(key, value).

    Stable across calls and runs on one installation; installations with
    different keys disagree on the same value.
    """
    key = get_key()
    return 'hmac256:' + hmac.new(key, value.encode('utf-8'),
                                 hashlib.sha256).hexdigest()[:32]


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    if argv in (['--help'], ['-h'], []):
        print('usage: python fingerprint.py --check\n'
              '  --check  verify the local key and print a sample fingerprint')
        return 0
    if argv != ['--check']:
        print('usage: python fingerprint.py --check', file=sys.stderr)
        return 1
    try:
        sample = fingerprint('agents-doctor self-test')
    except FingerprintKeyError as exc:
        print('key check failed: %s' % exc, file=sys.stderr)
        return 1
    print('key: ok, fingerprint sample: %s' % sample)
    return 0


if __name__ == '__main__':
    sys.exit(main())
