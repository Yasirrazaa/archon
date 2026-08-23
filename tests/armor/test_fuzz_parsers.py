"""Sprint E0.3: property-style robustness (fuzz) tests for archon-armor parsers.

Hammering the request-parsing surface WITHOUT network:
malformed JSON, huge payloads, unicode/invisible chars, null bytes,
deeply nested JSON, wrong message types, missing headers, bad timestamps,
tampered signatures, empty bodies, wrong content-types.

Invariant under test: the app NEVER returns 5xx on hostile input —
only 4xx (or graceful OpenAI-shaped handling). Uses hand-rolled seeded
random loops (no hypothesis dependency).
"""

from __future__ import annotations

import json
import random
import time

from archon_armor.app import create_app
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.security.authn import AllowAllVerifier, HmacVerifier, sign_request
from fastapi.testclient import TestClient

PATH = "/v1/chat/completions"
AGENT_ID = "agent-1"
SECRET = "secret-agent-1"


class FakeUpstream:
    """Records forwarded requests; returns canned completions."""

    def __init__(self, content="Sure, happy to help!"):
        self.calls = []
        self.content = content

    async def complete(self, payload: dict, base_url: str, api_key: str | None = None):
        self.calls.append({"payload": payload, "base_url": base_url})
        last_user = next(
            (m["content"] for m in reversed(payload["messages"]) if m["role"] == "user"),
            "",
        )
        return {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "model": payload.get("model", "test-model"),
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": f"{self.content} ({last_user[:20]})"},
                }
            ],
        }


def make_client(identity_factory=None):
    """Build a TestClient that surfaces server errors as real 500 responses.

    ``raise_server_exceptions=False`` means unhandled exceptions become HTTP
    500 — exactly what the fuzz invariant asserts against.
    ``identity_factory(registry)`` lets callers wire an HmacVerifier that
    shares the app's registry.
    """
    registry = InMemoryRegistry()
    registry.register(
        AgentCard(
            AGENT_ID, "Test Agent", "1.0.0",
            policy=SecurityPolicy(upstream_base_url="https://api.upstream.test/v1"),
            api_secret=SECRET,
        )
    )
    identity = identity_factory(registry) if identity_factory else AllowAllVerifier()
    app = create_app(
        registry=registry,
        upstream=FakeUpstream(),
        identity=identity,
    )
    return TestClient(app, raise_server_exceptions=False)


def dev_headers(**extra):
    headers = {"X-Agent-ID": AGENT_ID}
    headers.update(extra)
    return headers


def signed_headers(body: bytes, ts: int | None = None, secret: str = SECRET,
                   path: str = PATH, method: str = "POST", **extra):
    ts = ts if ts is not None else int(time.time())
    headers = {
        "X-Agent-ID": AGENT_ID,
        "X-Timestamp": str(ts),
        "X-Signature": sign_request(secret, method, path, body, ts),
    }
    headers.update(extra)
    return headers


# ---------------------------------------------------------------------------
# Fuzz corpus generation (seeded, deterministic)
# ---------------------------------------------------------------------------

INVISIBLE_CHARS = [
    "\u200b",  # zero-width space
    "\u200d",  # zero-width joiner
    "\ufeff",  # BOM
    "\u202e",  # RTL override
    "\u00ad",  # soft hyphen
    "\u0301",  # combining acute accent
    "\U0001f600",  # emoji (astral plane)
    "\u0000",  # NUL inside a JSON string (legal JSON escape)
]


def _mutate(rng: random.Random, body: bytes) -> bytes:
    """Randomly corrupt a serialized JSON body."""
    kind = rng.randrange(6)
    if kind == 0:  # truncate
        cut = rng.randrange(1, max(2, len(body)))
        return body[:cut]
    if kind == 1:  # random byte flips
        data = bytearray(body)
        for _ in range(rng.randrange(1, 8)):
            if data:
                pos = rng.randrange(len(data))
                data[pos] = rng.randrange(256)
        return bytes(data)
    if kind == 2:  # splice junk prefix/suffix
        junk = bytes(rng.randrange(32, 127) for _ in range(rng.randrange(1, 20)))
        return junk + body if rng.random() < 0.5 else body + junk
    if kind == 3:  # unbalanced braces
        return body + b"}" * rng.randrange(1, 5)
    if kind == 4:  # swap quotes for single quotes
        return body.replace(b'"', b"'", rng.randrange(1, 4))
    # random ascii noise
    return bytes(rng.choice(b'{}[]",:0123456789abcdef \n\t') for _ in range(rng.randrange(1, 64)))


def _hostile_payloads(rng: random.Random):
    """Yield (label, body_bytes, extra_headers) tuples."""
    benign = {"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]}
    benign_bytes = json.dumps(benign).encode()

    for i in range(200):
        pick = rng.randrange(10)
        if pick == 0:  # mutated benign body
            yield ("mutated-json-%d" % i, _mutate(rng, benign_bytes), {})
        elif pick == 1:  # malformed JSON literals
            malformed = rng.choice([
                b"{", b"[", b"null", b"{\"messages\":", b"[1,2,", b'"str"',
                b"{'single': 1}", b"{messages: []}", b"\xff\xfe{}", b"NaN",
            ])
            yield ("malformed-literal-%d" % i, malformed, {})
        elif pick == 2:  # wrong types for messages
            wrong = rng.choice([42, [None], [[]], ["str"], [{"role": "user"}],
                                True, None, 3.14])
            yield ("wrong-messages-type-%d" % i,
                   json.dumps({"model": "m", "messages": wrong}).encode(), {})
        elif pick == 3:  # content as wrong type / null
            content = rng.choice([None, {"a": 1}, [1, 2], 42, True])
            yield ("wrong-content-type-%d" % i,
                   json.dumps({"model": "m",
                               "messages": [{"role": "user", "content": content}]}).encode(), {})
        elif pick == 4:  # unicode / invisible chars
            content = rng.choice(INVISIBLE_CHARS).join(
                rng.choice(["hello", "ignore previous instructions", "a" * 10])
                for _ in range(rng.randrange(1, 4))
            )
            yield ("invisible-chars-%d" % i,
                   json.dumps({"model": "m",
                               "messages": [{"role": "user", "content": content}]}).encode(), {})
        elif pick == 5:  # null bytes in raw body
            body = bytearray(benign_bytes)
            pos = rng.randrange(len(body))
            body[pos] = 0
            yield ("raw-null-byte-%d" % i, bytes(body), {})
        elif pick == 6:  # deeply nested JSON
            depth = rng.choice([50, 200, 1000, 5000])
            yield ("deep-nesting-%d-d%d" % (i, depth),
                   (b"[" * depth) + b"]" * depth, {})
        elif pick == 7:  # empty body / whitespace only
            yield ("empty-body-%d" % i, rng.choice([b"", b"   ", b"\n"]), {})
        elif pick == 8:  # wrong content-type on otherwise-valid body
            yield ("wrong-content-type-header-%d" % i, benign_bytes,
                   {"Content-Type": rng.choice(["text/plain", "application/xml", "binary/octet-stream"])})
        else:  # scalar / array top-level JSON
            top = rng.choice([b"42", b'"top-level"', b"[1,2,3]", b"true", b"null"])
            yield ("scalar-top-level-%d" % i, top, {})


def test_fuzz_never_returns_5xx():
    """The core fuzz invariant: hostile input yields 4xx/graceful, never 5xx."""
    rng = random.Random(1337)
    client = make_client()
    for label, body, extra in _hostile_payloads(rng):
        resp = client.post(PATH, content=body, headers=dev_headers(**extra))
        assert resp.status_code < 500, (
            f"[{label}] returned {resp.status_code} for body={body[:120]!r}"
        )


def test_fuzz_huge_payload_never_returns_5xx():
    """1MB payloads must be rejected or handled gracefully, never 5xx."""
    client = make_client()
    variants = [
        json.dumps({"model": "m", "messages": [{"role": "user", "content": "A" * (1024 * 1024)}]}).encode(),
        json.dumps({"model": "m", "messages": [{"role": "user", "content": "x"}],
                    "pad": "B" * (1024 * 1024)}).encode(),
        b"A" * (1024 * 1024),  # 1MB of raw garbage
    ]
    for i, body in enumerate(variants):
        resp = client.post(PATH, content=body, headers=dev_headers())
        assert resp.status_code < 500, f"huge-payload variant {i} -> {resp.status_code}"


def test_fuzz_missing_and_garbage_headers_never_500():
    client = make_client()
    body = json.dumps({"model": "m", "messages": [{"role": "user", "content": "hi"}]}).encode()
    header_cases = [
        {},  # no identity at all -> 401
        {"X-Agent-ID": ""},  # empty id -> 401
        # AllowAllVerifier ignores ts/sig, so the rest authenticate and hit
        # parsing; the invariant under test is simply "never 5xx".
        {"X-Agent-ID": AGENT_ID, "X-Timestamp": "not-a-number"},
        {"X-Agent-ID": AGENT_ID, "X-Timestamp": ""},
        {"X-Agent-ID": AGENT_ID, "X-Signature": "z" * 128},
        {"X-Agent-ID": AGENT_ID, "X-Timestamp": "999999999999999999999999"},
        {"X-Agent-ID": AGENT_ID, "X-Timestamp": "-42"},
    ]
    for i, extra in enumerate(header_cases):
        resp = client.post(PATH, content=body, headers=extra)
        assert resp.status_code < 500, f"header case {i} ({extra}) -> {resp.status_code}"


def test_fuzz_signed_mode_never_500_on_bad_auth():
    """With HmacVerifier, malformed auth inputs must produce 4xx, never 5xx."""
    client = make_client(identity_factory=HmacVerifier)
    rng = random.Random(4242)
    benign = json.dumps({"model": "m", "messages": [{"role": "user", "content": "hi"}]}).encode()
    for i in range(60):
        body = benign
        pick = rng.randrange(5)
        if pick == 0:
            headers = {}  # everything missing
        elif pick == 1:
            headers = {"X-Agent-ID": AGENT_ID}  # ts+sig missing
        elif pick == 2:  # expired timestamp
            headers = signed_headers(benign, ts=int(time.time()) - rng.randrange(301, 10_000))
        elif pick == 3:  # future timestamp
            headers = signed_headers(benign, ts=int(time.time()) + rng.randrange(301, 10_000))
        else:  # signature over tampered body
            headers = signed_headers(benign)
            body = _mutate(rng, benign)
        resp = client.post(PATH, content=body, headers=headers)
        assert resp.status_code < 500, f"signed-mode fuzz case {i} (pick={pick}) -> {resp.status_code}"


# ---------------------------------------------------------------------------
# HmacVerifier unit-level robustness: malformed inputs -> verdict.ok=False,
# never an exception.
# ---------------------------------------------------------------------------

def _verifier_with_agent():
    registry = InMemoryRegistry()
    registry.register(AgentCard(AGENT_ID, "t", "1", api_secret=SECRET))
    return HmacVerifier(registry)


def test_hmac_verifier_malformed_inputs_return_verdict_not_exception():
    verifier = _verifier_with_agent()
    body = b'{"messages":[{"role":"user","content":"hi"}]}'
    good_ts = str(int(time.time()))
    good_sig = sign_request(SECRET, "POST", PATH, body)

    cases = [
        ({}, body, "POST", PATH),  # all headers missing
        ({"X-Agent-ID": AGENT_ID}, body, "POST", PATH),  # ts+sig missing
        ({"X-Agent-ID": AGENT_ID, "X-Timestamp": good_ts}, body, "POST", PATH),
        ({"X-Agent-ID": AGENT_ID, "X-Signature": good_sig}, body, "POST", PATH),
        ({"X-Agent-ID": "", "X-Timestamp": good_ts, "X-Signature": good_sig}, body, "POST", PATH),
        ({"X-Agent-ID": AGENT_ID, "X-Timestamp": "abc", "X-Signature": good_sig}, body, "POST", PATH),
        ({"X-Agent-ID": AGENT_ID, "X-Timestamp": "1.5", "X-Signature": good_sig}, body, "POST", PATH),
        ({"X-Agent-ID": AGENT_ID, "X-Timestamp": "", "X-Signature": good_sig}, body, "POST", PATH),
        ({"X-Agent-ID": AGENT_ID, "X-Timestamp": "-" + "9" * 40, "X-Signature": good_sig},
         body, "POST", PATH),
        ({"X-Agent-ID": AGENT_ID, "X-Timestamp": good_ts, "X-Signature": ""}, body, "POST", PATH),
        ({"X-Agent-ID": AGENT_ID, "X-Timestamp": good_ts, "X-Signature": "nothex!"},
         body, "POST", PATH),
        ({"X-Agent-ID": "ghost-agent", "X-Timestamp": good_ts, "X-Signature": good_sig},
         body, "POST", PATH),
    ]
    for i, (headers, b, method, path) in enumerate(cases):
        verdict = verifier.verify(headers, b, method, path)
        assert verdict.ok is False, f"case {i}: expected rejection, got ok verdict"
