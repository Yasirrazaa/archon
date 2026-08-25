"""Sprint MT-C: SCIM v2 provisioning — store + router."""

from __future__ import annotations

import sqlite3

import pytest
from archon_core.security.scim import ScimUser, ScimUserStore, build_scim_router
from fastapi import FastAPI
from fastapi.testclient import TestClient

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


@pytest.fixture()
def store(tmp_path):
    return ScimUserStore(str(tmp_path / "scim.db"))


@pytest.fixture()
def client(store):
    app = FastAPI()
    app.include_router(build_scim_router(store))
    return TestClient(app)


def _post(client, user_name="ada@example.com", display_name="Ada Lovelace", headers=None):
    return client.post(
        "/scim/v2/Users",
        json={"schemas": [USER_SCHEMA], "userName": user_name, "displayName": display_name},
        headers=headers,
    )


# ---------------------------------------------------------------- store


class TestScimUserStore:
    def test_create_assigns_uuid_hex_and_utc_timestamps(self, store):
        user = store.create("ada@example.com", "Ada Lovelace")
        assert len(user.id) == 32
        int(user.id, 16)  # uuid4 hex
        assert user.user_name == "ada@example.com"
        assert user.display_name == "Ada Lovelace"
        assert user.active is True
        assert user.groups == []
        assert user.created_at.endswith("+00:00")
        assert user.modified_at.endswith("+00:00")

    def test_get_by_id_roundtrip(self, store):
        created = store.create("a@x.com", "A")
        fetched = store.get_by_id(created.id)
        assert fetched == created

    def test_get_by_id_missing_returns_none(self, store):
        assert store.get_by_id("nope") is None

    def test_get_by_user_name(self, store):
        created = store.create("a@x.com", "A")
        assert store.get_by_user_name("a@x.com").id == created.id
        assert store.get_by_user_name("missing@x.com") is None

    def test_list_returns_all_users(self, store):
        store.create("a@x.com", "A")
        store.create("b@x.com", "B")
        names = [u.user_name for u in store.list()]
        assert sorted(names) == ["a@x.com", "b@x.com"]

    def test_list_filter_param_matches_user_name(self, store):
        store.create("a@x.com", "A")
        store.create("b@x.com", "B")
        found = store.list(filter_param='userName eq "b@x.com"')
        assert len(found) == 1
        assert found[0].user_name == "b@x.com"

    def test_update_persists_changes_and_bumps_modified_at(self, store):
        created = store.create("a@x.com", "A")
        created.display_name = "Renamed"
        created.active = False
        updated = store.update(created)
        assert updated.display_name == "Renamed"
        assert updated.active is False
        assert updated.modified_at >= updated.created_at
        assert store.get_by_id(created.id).display_name == "Renamed"

    def test_delete_removes_row_hard(self, store):
        created = store.create("a@x.com", "A")
        assert store.delete(created.id) is True
        assert store.get_by_id(created.id) is None
        assert store.delete(created.id) is False

    def test_deactivate_soft_disables_without_delete(self, store):
        created = store.create("a@x.com", "A")
        result = store.deactivate(created.id)
        assert result.active is False
        assert store.get_by_id(created.id) is not None

    def test_persistence_across_instances(self, tmp_path):
        db_path = str(tmp_path / "persist.db")
        s1 = ScimUserStore(db_path)
        created = s1.create("p@x.com", "Persisted")
        s1._conn.close()
        s2 = ScimUserStore(db_path)
        fetched = s2.get_by_user_name("p@x.com")
        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.display_name == "Persisted"
        s2._conn.close()

    def test_accepts_existing_connection(self):
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        store = ScimUserStore(conn)
        created = store.create("c@x.com", "C")
        assert store.get_by_id(created.id) is not None


# ---------------------------------------------------------------- router


class TestScimRouterCrud:
    def test_post_creates_user_201_with_scim_envelope(self, client):
        resp = _post(client)
        assert resp.status_code == 201
        body = resp.json()
        assert body["schemas"] == [USER_SCHEMA]
        assert body["userName"] == "ada@example.com"
        assert body["name"] == {"formatted": "Ada Lovelace"}
        assert body["active"] is True
        meta = body["meta"]
        assert meta["resourceType"] == "User"
        assert meta["created"]
        assert meta["lastModified"]

    def test_post_duplicate_user_name_conflicts_409(self, client):
        _post(client, user_name="dup@x.com")
        resp = _post(client, user_name="dup@x.com")
        assert resp.status_code == 409
        assert ERROR_SCHEMA in resp.json()["schemas"]

    def test_get_user_by_id(self, client, store):
        created = store.create("g@x.com", "Getter")
        resp = client.get(f"/scim/v2/Users/{created.id}")
        assert resp.status_code == 200
        assert resp.json()["userName"] == "g@x.com"

    def test_get_missing_user_404_error_envelope(self, client):
        resp = client.get("/scim/v2/Users/doesnotexist")
        assert resp.status_code == 404
        body = resp.json()
        assert body["schemas"] == [ERROR_SCHEMA]
        assert body["status"] == "404"
        assert body["detail"]

    def test_list_users_uses_list_response_envelope(self, client, store):
        store.create("l1@x.com", "L1")
        store.create("l2@x.com", "L2")
        resp = client.get("/scim/v2/Users")
        assert resp.status_code == 200
        body = resp.json()
        assert body["totalResults"] == 2
        assert len(body["Resources"]) == 2

    def test_list_users_with_filter_query(self, client, store):
        store.create("f1@x.com", "F1")
        store.create("f2@x.com", "F2")
        resp = client.get("/scim/v2/Users", params={"filter": 'userName eq "f2@x.com"'})
        body = resp.json()
        assert body["totalResults"] == 1
        assert body["Resources"][0]["userName"] == "f2@x.com"

    def test_put_replaces_user_fields(self, client):
        created = _post(client, user_name="put@x.com").json()
        resp = client.put(
            f"/scim/v2/Users/{created['id']}",
            json={
                "schemas": [USER_SCHEMA],
                "userName": "put@x.com",
                "displayName": "Replaced Name",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == {"formatted": "Replaced Name"}

    def test_patch_replace_display_name_and_active(self, client):
        created = _post(client, user_name="patch@x.com").json()
        resp = client.patch(
            f"/scim/v2/Users/{created['id']}",
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "replace", "path": "displayName", "value": "Patched"},
                    {"op": "replace", "path": "active", "value": False},
                ],
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == {"formatted": "Patched"}
        assert body["active"] is False

    def test_delete_returns_204_then_get_is_404(self, client):
        created = _post(client, user_name="del@x.com").json()
        resp = client.delete(f"/scim/v2/Users/{created['id']}")
        assert resp.status_code == 204
        assert client.get(f"/scim/v2/Users/{created['id']}").status_code == 404


class TestScimAuthenticator:
    def _client(self, authenticator):
        app = FastAPI()
        app.include_router(
            build_scim_router(ScimUserStore(":memory:"), authenticator=authenticator)
        )
        return TestClient(app)

    def test_authenticator_allows_valid_token(self):
        seen = {}

        def auth(header):
            seen["header"] = header
            return header == "Bearer good"

        client = self._client(auth)
        resp = _post(client, headers={"Authorization": "Bearer good"})
        assert resp.status_code == 201
        assert seen["header"] == "Bearer good"

    def test_authenticator_denies_missing_header_401(self):
        client = self._client(lambda header: header == "Bearer good")
        resp = client.post(
            "/scim/v2/Users",
            json={"schemas": [USER_SCHEMA], "userName": "n@x.com", "displayName": "N"},
        )
        assert resp.status_code == 401
        assert ERROR_SCHEMA in resp.json()["schemas"]

    def test_no_authenticator_is_allow_all_dev_mode(self):
        app = FastAPI()
        app.include_router(build_scim_router(ScimUserStore(":memory:")))
        client = TestClient(app)
        resp = _post(client)
        assert resp.status_code == 201


class TestScimUserDefaults:
    def test_dataclass_defaults(self):
        user = ScimUser(id="abc", user_name="d@x.com", display_name="D")
        assert user.active is True
        assert user.groups == []
