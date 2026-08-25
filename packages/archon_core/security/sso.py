"""OIDC SSO token verification for archon-armor.

Verifies RS256 JWTs against an OIDC provider's published JWKS. The
provider's discovery document (`{issuer}/.well-known/openid-configuration`)
is fetched once to locate the `jwks_uri`; the key set itself is cached with
a TTL so repeated verifications do not re-fetch.

Design rules:
- verify() NEVER raises: every failure path returns an invalid TokenVerdict
  with a specific, stable reason string.
- The HTTP transport is injectable (`http_get(url) -> dict`) so tests can
  stub the network and assert fetch counts.
- Only stdlib plus `cryptography` (already a dependency) are used; JWTs are
  parsed with plain base64url + json rather than a JWT library.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.request
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

EXP_LEEWAY_SECONDS = 60


@dataclass
class OidcConfig:
    issuer_url: str
    client_id: str
    jwks_cache_ttl_seconds: int = 3600


@dataclass
class TokenVerdict:
    valid: bool
    claims: dict
    reason: str = ""


def _default_http_get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310
        return json.loads(response.read().decode())


def _b64url_decode(segment: str) -> bytes:
    padding_len = (-len(segment)) % 4
    return base64.urlsafe_b64decode(segment + "=" * padding_len)


def _int_from_b64url(segment: str) -> int:
    return int.from_bytes(_b64url_decode(segment), "big")


class OidcVerifier:
    """Verifies RS256 OIDC ID/access tokens against the issuer's JWKS."""

    def __init__(self, config: OidcConfig, http_get=None):
        self._config = config
        self._http_get = http_get if http_get is not None else _default_http_get
        self._keys: dict[str, rsa.RSAPublicKey] | None = None
        self._keys_fetched_at: float | None = None

    # -- JWKS ---------------------------------------------------------------

    def _jwks_document(self) -> dict:
        now = time.monotonic()
        if self._keys is not None and self._keys_fetched_at is not None:
            elapsed = now - self._keys_fetched_at
            if elapsed < self._config.jwks_cache_ttl_seconds:
                return {}
        discovery_url = self._config.issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        discovery = self._http_get(discovery_url)
        jwks_uri = discovery["jwks_uri"]
        jwks = self._http_get(jwks_uri)
        keys: dict[str, rsa.RSAPublicKey] = {}
        for jwk in jwks.get("keys", []):
            kid = jwk.get("kid")
            if jwk.get("kty") == "RSA" and kid and "n" in jwk and "e" in jwk:
                numbers = rsa.RSAPublicNumbers(
                    e=_int_from_b64url(jwk["e"]), n=_int_from_b64url(jwk["n"])
                )
                keys[kid] = numbers.public_key()
        self._keys = keys
        self._keys_fetched_at = now
        return {}

    def _public_key(self, kid: str) -> rsa.RSAPublicKey | None:
        self._jwks_document()
        return (self._keys or {}).get(kid)

    # -- verification -------------------------------------------------------

    def verify(self, token: str) -> TokenVerdict:
        try:
            return self._verify(token)
        except Exception as exc:  # noqa: BLE001 - never leak exceptions to callers
            return TokenVerdict(valid=False, claims={}, reason=f"malformed token: {exc}")

    def _verify(self, token: str) -> TokenVerdict:
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            return TokenVerdict(valid=False, claims={}, reason="malformed token")
        encoded_header, encoded_payload, encoded_signature = parts

        try:
            header = json.loads(_b64url_decode(encoded_header))
            payload = json.loads(_b64url_decode(encoded_payload))
            signature = _b64url_decode(encoded_signature)
        except (ValueError, json.JSONDecodeError) as exc:
            return TokenVerdict(valid=False, claims={}, reason=f"malformed token: {exc}")
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return TokenVerdict(valid=False, claims={}, reason="malformed token")

        algorithm = header.get("alg")
        if algorithm != "RS256":
            return TokenVerdict(
                valid=False, claims={}, reason=f"unsupported algorithm: {algorithm!r}"
            )
        kid = header.get("kid")
        if not kid:
            return TokenVerdict(valid=False, claims={}, reason="missing kid")

        public_key = self._public_key(kid)
        if public_key is None:
            return TokenVerdict(valid=False, claims={}, reason=f"unknown kid: {kid}")

        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        try:
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            return TokenVerdict(valid=False, claims={}, reason="invalid signature")

        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            if time.time() > exp + EXP_LEEWAY_SECONDS:
                return TokenVerdict(valid=False, claims={}, reason="token expired")

        if payload.get("iss") != self._config.issuer_url:
            return TokenVerdict(valid=False, claims={}, reason="issuer mismatch")

        audience = payload.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if self._config.client_id not in audiences:
            return TokenVerdict(valid=False, claims={}, reason="audience mismatch")

        return TokenVerdict(valid=True, claims=payload, reason="")


def require_auth(verifier: OidcVerifier, authorization_header: str | None) -> TokenVerdict:
    """Convenience wrapper: parse 'Bearer <token>' and delegate to verifier."""
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return TokenVerdict(valid=False, claims={}, reason="missing bearer")
    token = authorization_header[len("Bearer ") :].strip()
    if not token:
        return TokenVerdict(valid=False, claims={}, reason="missing bearer")
    return verifier.verify(token)
