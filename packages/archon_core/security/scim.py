"""SCIM v2 user provisioning (RFC 7643/7644 subset).

Sprint MT-C: a self-contained sqlite-backed SCIM user store plus a FastAPI
router implementing the core /Users CRUD surface: list (with a minimal
``userName eq "..."`` filter), get, create, replace, patch and delete.
Responses use the standard SCIM envelope; errors use
urn:ietf:params:scim:api:messages:2.0:Error.

The router is built with ``build_scim_router(store, authenticator=None)``
and carries its own ``/scim/v2`` prefix so it can be mounted on any app.
When ``authenticator`` is None every request is allowed (dev mode);
otherwise it is called with the raw Authorization header value and must
return True to proceed, False yields a 401 error envelope.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from fastapi import APIRouter, Request, Response

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

_ROUTER_PREFIX = "/scim/v2"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScimUser:
    id: str
    user_name: str
    display_name: str
    active: bool = True
    groups: list[str] = field(default_factory=list)
    created_at: str = ""
    modified_at: str = ""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scim_users (
    id TEXT PRIMARY KEY,
    user_name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    groups_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    modified_at TEXT NOT NULL
)
"""


class DuplicateUserNameError(Exception):
    """Raised when creating a user whose userName is already taken."""


def _row_to_user(row: tuple) -> ScimUser:
    (
        uid,
        user_name,
        display_name,
        active,
        groups_json,
        created_at,
        modified_at,
    ) = row
    return ScimUser(
        id=uid,
        user_name=user_name,
        display_name=display_name,
        active=bool(active),
        groups=json.loads(groups_json),
        created_at=created_at,
        modified_at=modified_at,
    )


class ScimUserStore:
    """sqlite-backed store for SCIM User resources."""

    def __init__(self, path_or_conn: str | sqlite3.Connection | None = None):
        if isinstance(path_or_conn, sqlite3.Connection):
            self._conn = path_or_conn
            owned = False
        else:
            # path=None keeps everything in-memory (tests / ephemeral mode).
            # check_same_thread=False: TestClient may call from another thread.
            self._conn = sqlite3.connect(path_or_conn or ":memory:", check_same_thread=False)
            owned = True
        self._owned = owned
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        if self._owned:
            self._conn.close()

    def create(
        self,
        user_name: str,
        display_name: str,
        active: bool = True,
        groups: list[str] | None = None,
    ) -> ScimUser:
        now = _utc_now_iso()
        user = ScimUser(
            id=uuid.uuid4().hex,
            user_name=user_name,
            display_name=display_name,
            active=active,
            groups=list(groups or []),
            created_at=now,
            modified_at=now,
        )
        try:
            self._conn.execute(
                "INSERT INTO scim_users"
                " (id, user_name, display_name, active, groups_json,"
                "  created_at, modified_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    user.id,
                    user.user_name,
                    user.display_name,
                    int(user.active),
                    json.dumps(user.groups),
                    user.created_at,
                    user.modified_at,
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            raise DuplicateUserNameError(user_name) from exc
        return user

    def get_by_id(self, user_id: str) -> ScimUser | None:
        row = self._conn.execute(
            "SELECT id, user_name, display_name, active, groups_json,"
            " created_at, modified_at FROM scim_users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return _row_to_user(row) if row else None

    def get_by_user_name(self, user_name: str) -> ScimUser | None:
        row = self._conn.execute(
            "SELECT id, user_name, display_name, active, groups_json,"
            " created_at, modified_at FROM scim_users WHERE user_name = ?",
            (user_name,),
        ).fetchone()
        return _row_to_user(row) if row else None

    def list(self, filter_param: str | None = None) -> list[ScimUser]:
        rows = self._conn.execute(
            "SELECT id, user_name, display_name, active, groups_json,"
            " created_at, modified_at FROM scim_users ORDER BY created_at"
        ).fetchall()
        users = [_row_to_user(row) for row in rows]
        target = _parse_filter(filter_param)
        if target is not None:
            users = [u for u in users if u.user_name == target]
        return users

    def update(self, user: ScimUser) -> ScimUser:
        user.modified_at = _utc_now_iso()
        self._conn.execute(
            "UPDATE scim_users SET display_name = ?, active = ?,"
            " groups_json = ?, modified_at = ? WHERE id = ?",
            (
                user.display_name,
                int(user.active),
                json.dumps(user.groups),
                user.modified_at,
                user.id,
            ),
        )
        self._conn.commit()
        return user

    def delete(self, user_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM scim_users WHERE id = ?", (user_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def deactivate(self, user_id: str) -> ScimUser | None:
        user = self.get_by_id(user_id)
        if user is None:
            return None
        user.active = False
        return self.update(user)


def _parse_filter(filter_param: str | None) -> str | None:
    """Minimal SCIM filter parse: only ``userName eq "value"``."""
    if not filter_param:
        return None
    parts = filter_param.strip().split(" ", 2)
    if len(parts) == 3 and parts[0].lower() == "username" and parts[1].lower() == "eq":
        return parts[2].strip().strip('"')
    return None


def _error(status: int, detail: str) -> dict:
    return {
        "schemas": [SCIM_ERROR_SCHEMA],
        "detail": detail,
        "status": str(status),
    }


def _to_envelope(user: ScimUser) -> dict:
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.id,
        "userName": user.user_name,
        "name": {"formatted": user.display_name},
        "active": user.active,
        "groups": [{"value": g, "display": g} for g in user.groups],
        "meta": {
            "resourceType": "User",
            "created": user.created_at,
            "lastModified": user.modified_at,
        },
    }


def _json(payload: dict, status: int) -> Response:
    return Response(
        content=json.dumps(payload),
        status_code=status,
        media_type="application/scim+json",
    )


def build_scim_router(
    store: ScimUserStore,
    authenticator: Callable[[str | None], bool] | None = None,
) -> APIRouter:
    """Build a self-contained SCIM v2 router mounted at /scim/v2."""
    router = APIRouter(prefix=_ROUTER_PREFIX)

    async def _denial(request: Request) -> Response | None:
        if authenticator is None:
            return None
        if not authenticator(request.headers.get("Authorization")):
            return _json(_error(401, "invalid or missing credentials"), 401)
        return None

    def _not_found(user_id: str) -> Response:
        return _json(_error(404, f"User {user_id} not found"), 404)

    @router.get("/Users")
    async def list_users(request: Request):
        denial = await _denial(request)
        if denial:
            return denial
        users = store.list(filter_param=request.query_params.get("filter"))
        body = {
            "schemas": [SCIM_LIST_SCHEMA],
            "totalResults": len(users),
            "Resources": [_to_envelope(u) for u in users],
        }
        return _json(body, 200)

    @router.post("/Users")
    async def create_user(request: Request):
        denial = await _denial(request)
        if denial:
            return denial
        payload = await request.json()
        user_name = payload.get("userName")
        if not user_name:
            return _json(_error(400, "userName is required"), 400)
        name_obj = payload.get("name") or {}
        display_name = payload.get("displayName") or name_obj.get("formatted", "")
        try:
            user = store.create(user_name=user_name, display_name=display_name)
        except DuplicateUserNameError:
            return _json(_error(409, f"userName already taken: {user_name}"), 409)
        return _json(_to_envelope(user), 201)

    @router.get("/Users/{user_id}")
    async def get_user(user_id: str, request: Request):
        denial = await _denial(request)
        if denial:
            return denial
        user = store.get_by_id(user_id)
        if user is None:
            return _not_found(user_id)
        return _json(_to_envelope(user), 200)

    @router.put("/Users/{user_id}")
    async def replace_user(user_id: str, request: Request):
        denial = await _denial(request)
        if denial:
            return denial
        user = store.get_by_id(user_id)
        if user is None:
            return _not_found(user_id)
        payload = await request.json()
        name_obj = payload.get("name") or {}
        user.user_name = payload.get("userName", user.user_name)
        user.display_name = payload.get("displayName") or name_obj.get(
            "formatted", user.display_name
        )
        user.active = bool(payload.get("active", user.active))
        return _json(_to_envelope(store.update(user)), 200)

    @router.patch("/Users/{user_id}")
    async def patch_user(user_id: str, request: Request):
        denial = await _denial(request)
        if denial:
            return denial
        user = store.get_by_id(user_id)
        if user is None:
            return _not_found(user_id)
        payload = await request.json()
        for op in payload.get("Operations", []):
            if op.get("op", "").lower() != "replace":
                continue
            path = op.get("path")
            value = op.get("value")
            if path == "active":
                user.active = bool(value)
            elif path == "displayName":
                user.display_name = str(value)
        return _json(_to_envelope(store.update(user)), 200)

    @router.delete("/Users/{user_id}")
    async def delete_user(user_id: str, request: Request):
        denial = await _denial(request)
        if denial:
            return denial
        if not store.delete(user_id):
            return _not_found(user_id)
        return Response(status_code=204)

    return router
