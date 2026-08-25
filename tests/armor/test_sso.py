"""Sprint MT-B: OIDC SSO verifier tests.

RSA keypairs are generated locally with cryptography and test JWTs are
hand-signed (manual base64url construction, no pyjwt dependency).
"""

import base64
import json
import time
from unittest import mock

from archon_core.security import sso
from archon_core.security.sso import OidcConfig, OidcVerifier, require_auth
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISSUER = "https://issuer.test"
CLIENT_ID = "client-1"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URI = f"{ISSUER}/jwks.json"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def int_to_b64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8 or 1
    return b64url(value.to_bytes(length, "big"))


class RsaTestKey:
    """Self-contained RSA test key: builds JWKS and hand-signs JWTs."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwks(self, kid: str = "k1") -> dict:
        numbers = self.key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": kid,
                    "use": "sig",
                    "alg": "RS256",
                    "n": int_to_b64url(numbers.n),
                    "e": int_to_b64url(numbers.e),
                }
            ]
        }

    def sign(self, signing_input: bytes) -> bytes:
        return self.key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def make_token(
    key: RsaTestKey,
    kid: str = "k1",
    header: dict | None = None,
    claims: dict | None = None,
) -> str:
    hdr = header if header is not None else {"alg": "RS256", "typ": "JWT", "kid": kid}
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-1",
        "exp": int(time.time()) + 600,
    }
    payload.update(claims or {})
    signing_input = b64url(json.dumps(hdr).encode()) + "." + b64url(json.dumps(payload).encode())
    sig = key.sign(signing_input.encode())
    return signing_input + "." + b64url(sig)


class FakeHttp:
    """Counts every call; serves discovery doc then JWKS."""

    def __init__(self, *jwks_docs: dict):
        self.jwks_docs = jwks_docs
        self.calls: list[str] = []

    def __call__(self, url: str) -> dict:
        self.calls.append(url)
        if url == DISCOVERY_URL:
            return {"jwks_uri": JWKS_URI}
        return self.jwks_docs[-1]


def make_config(**overrides) -> OidcConfig:
    defaults = {"issuer_url": ISSUER, "client_id": CLIENT_ID}
    defaults.update(overrides)
    return OidcConfig(**defaults)


class TestTokenVerification:
    def test_valid_token_passes_with_claims(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = verifier.verify(make_token(key))
        assert verdict.valid is True
        assert verdict.claims["sub"] == "user-1"
        assert verdict.reason == ""

    def test_wrong_signature_rejected(self):
        signer = RsaTestKey()
        impostor = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(signer.jwks()))
        verdict = verifier.verify(make_token(impostor))  # signed by another key
        assert verdict.valid is False
        assert "signature" in verdict.reason.lower()

    def test_expired_token_rejected(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = verifier.verify(make_token(key, claims={"exp": int(time.time()) - 120}))
        assert verdict.valid is False
        assert "expired" in verdict.reason.lower()

    def test_expired_within_leeway_passes(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = verifier.verify(make_token(key, claims={"exp": int(time.time()) - 30}))
        assert verdict.valid is True

    def test_wrong_issuer_rejected(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = verifier.verify(make_token(key, claims={"iss": "https://evil.test"}))
        assert verdict.valid is False
        assert "issuer" in verdict.reason.lower()

    def test_audience_string_mismatch_rejected(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = verifier.verify(make_token(key, claims={"aud": "other-client"}))
        assert verdict.valid is False
        assert "audience" in verdict.reason.lower()

    def test_audience_list_containing_client_passes(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = verifier.verify(make_token(key, claims={"aud": ["other", CLIENT_ID]}))
        assert verdict.valid is True


class TestKeyResolution:
    def test_unknown_kid_rejected(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = verifier.verify(make_token(key, kid="ghost"))
        assert verdict.valid is False
        assert "kid" in verdict.reason.lower()

    def test_missing_kid_in_header_rejected(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = verifier.verify(make_token(key, header={"alg": "RS256", "typ": "JWT"}))
        assert verdict.valid is False
        assert "kid" in verdict.reason.lower()

    def test_unsupported_algorithm_rejected(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = verifier.verify(
            make_token(key, header={"alg": "HS256", "typ": "JWT", "kid": "k1"})
        )
        assert verdict.valid is False
        assert "algorithm" in verdict.reason.lower()


class TestMalformedTokensNeverRaise:
    def test_no_dots(self):
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(RsaTestKey().jwks()))
        verdict = verifier.verify("not-a-jwt")
        assert verdict.valid is False
        assert verdict.reason != ""
        assert verdict.claims == {}

    def test_bad_base64(self):
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(RsaTestKey().jwks()))
        verdict = verifier.verify("@@@.%%%.***")
        assert verdict.valid is False

    def test_empty_string(self):
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(RsaTestKey().jwks()))
        assert verifier.verify("").valid is False

    def test_four_segments(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        assert verifier.verify(make_token(key) + ".extra").valid is False


class TestJwksCaching:
    def test_jwks_cached_across_verifies(self):
        key = RsaTestKey()
        http = FakeHttp(key.jwks())
        verifier = OidcVerifier(make_config(), http_get=http)
        assert verifier.verify(make_token(key)).valid
        assert verifier.verify(make_token(key)).valid
        # exactly one discovery fetch + one JWKS fetch despite two verifies
        assert http.calls.count(DISCOVERY_URL) == 1
        assert http.calls.count(JWKS_URI) == 1

    def test_ttl_expiry_refetches(self):
        key = RsaTestKey()
        http = FakeHttp(key.jwks())
        verifier = OidcVerifier(make_config(jwks_cache_ttl_seconds=60), http_get=http)
        now = {"t": time.monotonic()}

        def fake_monotonic() -> float:
            return now["t"]

        with mock.patch.object(sso.time, "monotonic", fake_monotonic):
            assert verifier.verify(make_token(key)).valid
            assert http.calls.count(JWKS_URI) == 1
            now["t"] += 61  # advance past TTL
            assert verifier.verify(make_token(key)).valid
            assert http.calls.count(JWKS_URI) == 2


class TestRequireAuth:
    def test_bearer_token_parsed_and_verified(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = require_auth(verifier, f"Bearer {make_token(key)}")
        assert verdict.valid is True
        assert verdict.claims["sub"] == "user-1"

    def test_non_bearer_scheme_rejected(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = require_auth(verifier, f"Basic {make_token(key)}")
        assert verdict.valid is False
        assert verdict.reason == "missing bearer"

    def test_missing_header_reports_missing_bearer(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = require_auth(verifier, None)
        assert verdict.valid is False
        assert verdict.reason == "missing bearer"

    def test_bearer_without_token_rejected(self):
        key = RsaTestKey()
        verifier = OidcVerifier(make_config(), http_get=FakeHttp(key.jwks()))
        verdict = require_auth(verifier, "Bearer ")
        assert verdict.valid is False
