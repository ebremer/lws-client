# SPDX-License-Identifier: MIT
"""An in-memory LWS server (storage + authorization server) for httpx.MockTransport tests."""

from __future__ import annotations

import copy
import json
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

import httpx

from lws_client import did_key_to_jwk, verify_jwt
from lws_client.crypto import decode_jwt_unverified

LWS = "https://www.w3.org/ns/lws#"
CONTAINER = LWS + "Container"
DATA = LWS + "DataResource"


@dataclass
class Res:
    url: str
    kind: str  # "container" | "data"
    parent: str | None
    content: bytes = b""
    content_type: str = "application/octet-stream"
    etag: str = '"0"'
    types: list[str] = field(default_factory=list)
    links: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    linkset_etag: str = '"ls-0"'
    children: list[str] = field(default_factory=list)


class PatchError(Exception):
    pass


def apply_patch(doc: Any, ops: list[dict[str, Any]]) -> Any:
    doc = copy.deepcopy(doc)
    for op in ops:
        segs = [s.replace("~1", "/").replace("~0", "~") for s in op["path"].split("/")[1:]]
        parent = doc
        for s in segs[:-1]:
            parent = parent[int(s)] if isinstance(parent, list) else parent[s]
        last = segs[-1] if segs else None
        kind = op["op"]
        if kind == "test":
            cur = parent[int(last)] if isinstance(parent, list) else parent.get(last)
            if cur != op["value"]:
                raise PatchError("test failed")
        elif kind in ("add", "replace"):
            if isinstance(parent, list):
                if last == "-":
                    parent.append(op["value"])
                elif kind == "add":
                    parent.insert(int(last), op["value"])
                else:
                    parent[int(last)] = op["value"]
            else:
                if kind == "replace" and last not in parent:
                    raise PatchError("replace of missing member")
                parent[last] = op["value"]
        elif kind == "remove":
            if isinstance(parent, list):
                del parent[int(last)]
            else:
                del parent[last]
        else:
            raise PatchError(f"unsupported op {kind}")
    return doc


class FakeLws:
    def __init__(
        self,
        base: str = "https://storage.example",
        *,
        auth: bool = False,
        page_size: int = 2,
        as_base: str = "https://as.example",
    ) -> None:
        self.base = base
        self.storage_id = base + "/"
        self.root = base + "/root/"
        self.as_base = as_base
        self.auth = auth
        self.page_size = page_size
        self.resources: dict[str, Res] = {}
        self.requests: list[httpx.Request] = []
        self.tokens: set[str] = set()
        self.token_requests: list[dict[str, list[str]]] = []
        self.metadata_requests = 0
        self.search_cursors: dict[str, list[dict[str, Any]]] = {}
        self._n = 0
        self.notifications = base + "/notifications/"
        self.access_requests = base + "/access/requests/"
        self.access_grants = base + "/access/grants/"
        self.type_index = base + "/types/index"
        self.type_search = base + "/types/search"
        for url in (self.root, self.notifications, self.access_requests, self.access_grants):
            self.resources[url] = Res(url, "container", None, etag=self._etag())

    # -- helpers ----------------------------------------------------------------------

    def _etag(self) -> str:
        self._n += 1
        return f'"{self._n}"'

    def description(self) -> dict[str, Any]:
        return {
            "@context": ["https://www.w3.org/ns/cid/v1", "https://www.w3.org/ns/lws/v1"],
            "id": self.storage_id,
            "type": "Storage",
            "service": [
                {"type": "StorageRoot", "serviceEndpoint": "/root/"},
                {
                    "type": "NotificationService",
                    "serviceEndpoint": self.notifications,
                    "subscriptionType": ["WebhookSubscription"],
                },
                {"type": "AccessRequestService", "serviceEndpoint": self.access_requests},
                {"type": "AccessGrantService", "serviceEndpoint": self.access_grants},
                {"type": "TypeIndexService", "serviceEndpoint": self.type_index},
                {"type": "TypeSearchService", "serviceEndpoint": self.type_search},
            ],
        }

    def _json(self, status: int, body: Any, headers: list[tuple[str, str]] | None = None,
              content_type: str = "application/lws+json") -> httpx.Response:
        return httpx.Response(
            status, headers=[("Content-Type", content_type), *(headers or [])],
            content=json.dumps(body).encode(),
        )

    def _problem(self, status: int, detail: str) -> httpx.Response:
        return self._json(
            status, {"type": "about:blank", "title": detail, "status": status, "detail": detail},
            content_type="application/problem+json",
        )

    def _links(self, res: Res) -> list[tuple[str, str]]:
        links = [
            ("Link", f'<{urlsplit(res.url).path}.meta>; rel="linkset"; type="application/linkset+json"'
             if res.kind == "data" else f'<{res.url}.meta>; rel="linkset"; type="application/linkset+json"'),
            ("Link", f'<{self.storage_id}>; rel="{LWS}storage"'),
            ("Link", f'<{CONTAINER if res.kind == "container" else DATA}>; rel="type"'),
        ]
        links.extend(("Link", f'<{t}>; rel="type"') for t in res.types)
        if res.parent:
            links.append(("Link", f'<{urlsplit(res.parent).path}>; rel="up"'))
        return links

    def _authorized(self, request: httpx.Request) -> bool:
        header = request.headers.get("authorization", "")
        return header.startswith("Bearer ") and header[7:] in self.tokens

    def _challenge(self) -> httpx.Response:
        return httpx.Response(
            401,
            headers=[
                ("WWW-Authenticate", f'Bearer as_uri="{self.as_base}", realm="{self.storage_id}", '
                                     'error="invalid_token"'),
                ("Link", f'<{self.storage_id}>; rel="{LWS}storage"'),
            ],
        )

    # -- dispatch ---------------------------------------------------------------------

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        parts = urlsplit(url)
        path_url = url.split("?", 1)[0]
        query = parse_qs(parts.query)
        method = request.method
        if url.startswith(self.as_base):
            return self._authorization_server(request, parts.path)
        if path_url == self.storage_id and method in ("GET", "HEAD"):
            return self._json(200, self.description(), [("ETag", '"sd"')], "application/lws+cid")
        if self.auth and not self._authorized(request):
            return self._challenge()
        if path_url == self.type_index:
            return self._type_index(int(query.get("page", ["1"])[0]))
        if path_url == self.type_search:
            return self._type_search(request, query)
        if path_url.endswith(".meta"):
            return self._linkset(request, path_url[: -len(".meta")])
        res = self.resources.get(path_url)
        if res is None:
            return self._problem(404, "not found")
        if method in ("GET", "HEAD"):
            return self._get(request, res, int(query.get("page", ["1"])[0]))
        if method == "POST":
            if res.kind != "container":
                return self._problem(405, "not a container")
            return self._post(request, res)
        if method == "PUT":
            return self._put(request, res)
        if method == "PATCH":
            return self._patch(request, res)
        if method == "DELETE":
            return self._delete(request, res)
        return self._problem(405, "method not allowed")

    # -- authorization server -----------------------------------------------------------

    def _authorization_server(self, request: httpx.Request, path: str) -> httpx.Response:
        if path == "/.well-known/lws-configuration":
            self.metadata_requests += 1
            return self._json(200, {
                "issuer": self.as_base,
                "token_endpoint": self.as_base + "/token",
                "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"],
                "subject_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:jwt",
                    "urn:ietf:params:oauth:token-type:id_token",
                    "urn:ietf:params:oauth:token-type:saml2",
                ],
            }, content_type="application/json")
        if path == "/token" and request.method == "POST":
            form = parse_qs(request.content.decode())
            self.token_requests.append(form)
            def error(code: str) -> httpx.Response:
                return self._json(400, {"error": code}, content_type="application/json")
            if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:token-exchange"]:
                return error("unsupported_grant_type")
            if form.get("resource") != [self.storage_id]:
                return error("invalid_target")
            token_type = form.get("subject_token_type", [""])[0]
            subject = form.get("subject_token", [""])[0]
            if token_type == "urn:ietf:params:oauth:token-type:jwt":
                try:
                    header, claims = decode_jwt_unverified(subject)
                    if not (claims["sub"] == claims["iss"] == claims["client_id"]):
                        return error("invalid_request")
                    if self.as_base not in claims["aud"]:
                        return error("invalid_request")
                    if claims["sub"].startswith("did:key:"):
                        verify_jwt(subject, did_key_to_jwk(claims["sub"]))
                        if header.get("kid", "").split("#")[0] != claims["sub"]:
                            return error("invalid_request")
                except Exception:
                    return error("invalid_grant")
            elif not subject:
                return error("invalid_request")
            token = f"tok-{uuid.uuid4().hex[:8]}"
            self.tokens.add(token)
            return self._json(200, {"access_token": token, "token_type": "Bearer",
                                    "expires_in": 300}, content_type="application/json")
        return self._problem(404, "not found")

    # -- resources ----------------------------------------------------------------------

    def _container_body(self, res: Res, page: int) -> tuple[dict[str, Any], list[tuple[str, str]]]:
        items = [self.resources[c] for c in res.children]
        size = self.page_size
        pages = max(1, (len(items) + size - 1) // size)
        chunk = items[(page - 1) * size: page * size]
        body = {
            "@context": "https://www.w3.org/ns/lws/v1",
            "id": urlsplit(res.url).path,
            "type": "Container",
            "totalItems": len(items),
            "items": [
                {
                    "id": urlsplit(i.url).path,
                    "type": ["Container" if i.kind == "container" else "DataResource", *i.types],
                    **({"format": i.content_type, "size": len(i.content),
                        "modified": "2026-10-05T12:00:00Z"} if i.kind == "data" else {}),
                }
                for i in chunk
            ],
        }
        links: list[tuple[str, str]] = []
        if len(items) > size:
            path = urlsplit(res.url).path
            links.append(("Link", f"<{path}?page=1>; rel=\"first\""))
            links.append(("Link", f"<{path}?page={pages}>; rel=\"last\""))
            if page < pages:
                links.append(("Link", f"<{path}?page={page + 1}>; rel=\"next\""))
            if page > 1:
                links.append(("Link", f"<{path}?page={page - 1}>; rel=\"prev\""))
        return body, links

    def _get(self, request: httpx.Request, res: Res, page: int) -> httpx.Response:
        headers = [("ETag", res.etag), *self._links(res), ("Last-Modified", "Mon, 05 Oct 2026 12:00:00 GMT")]
        if request.headers.get("if-none-match") == res.etag:
            return httpx.Response(304, headers=headers)
        if res.kind == "container":
            body, links = self._container_body(res, page)
            accept = request.headers.get("accept", "application/lws+json")
            ctype = next((t for t in ("application/lws+json", "application/ld+json", "application/json")
                          if t in accept), "application/lws+json")
            content = json.dumps(body).encode()
            return httpx.Response(200, headers=[("Content-Type", ctype), ("Vary", "Accept"),
                                               *headers, *links],
                                  content=b"" if request.method == "HEAD" else content)
        content = res.content
        status = 200
        rng = request.headers.get("range")
        if rng and rng.startswith("bytes="):
            start_s, _, end_s = rng[6:].partition("-")
            start = int(start_s)
            end = int(end_s) if end_s else len(content) - 1
            headers.append(("Content-Range", f"bytes {start}-{end}/{len(content)}"))
            content = content[start: end + 1]
            status = 206
        headers.append(("Content-Type", res.content_type))
        if res.content_type.startswith("application/json"):
            headers.append(("Accept-Patch", "application/json-patch+json"))
        return httpx.Response(status, headers=headers,
                              content=b"" if request.method == "HEAD" else content)

    def _post(self, request: httpx.Request, parent: Res) -> httpx.Response:
        from lws_client import parse_link_header

        links = parse_link_header(request.headers.get_list("link"), parent.url)
        is_container = any(lk.rel == "type" and lk.href == CONTAINER for lk in links)
        slug = unquote(request.headers.get("slug", "")) or uuid.uuid4().hex[:8]
        name = quote(slug.strip("/").replace("/", "-"))
        url = parent.url + name + ("/" if is_container else "")
        n = 1
        while url in self.resources:
            url = parent.url + f"{name}-{n}" + ("/" if is_container else "")
            n += 1
        res = Res(url, "container" if is_container else "data", parent.url, etag=self._etag())
        if not is_container:
            res.content = request.content
            res.content_type = request.headers.get("content-type", "application/octet-stream")
        for lk in links:
            if lk.rel == "type":
                if lk.href not in (CONTAINER, DATA):
                    res.types.append(lk.href)
            elif lk.rel not in ("up", "linkset"):
                res.links.setdefault(lk.rel, []).append({"href": lk.href})
        self.resources[url] = res
        parent.children.append(url)
        parent.etag = self._etag()
        headers = [("Location", urlsplit(url).path), *self._links(res)]
        if parent.url == self.notifications:
            doc = json.loads(request.content)
            if doc.get("type") != "WebhookSubscription" or not doc.get("inbox"):
                return self._problem(400, "bad subscription")
            stored = {"@context": ["https://www.w3.org/ns/lws/v1"], "type": "WebhookSubscription",
                      "subscription": url, "topic": doc["topic"], "inbox": doc["inbox"]}
            if "expires" in doc:
                stored["expires"] = doc["expires"]
            res.content = json.dumps(stored).encode()
            res.content_type = "application/lws+json"
            return self._json(200, {k: v for k, v in stored.items() if k not in ("topic", "inbox")},
                              [("Location", url)])
        return httpx.Response(201, headers=headers)

    def _check_if_match(self, request: httpx.Request, etag: str) -> httpx.Response | None:
        if_match = request.headers.get("if-match")
        if if_match and if_match != etag:
            return self._problem(412, "precondition failed")
        return None

    def _put(self, request: httpx.Request, res: Res) -> httpx.Response:
        if res.kind == "container":
            return httpx.Response(405, headers=[("Allow", "GET, HEAD, POST, DELETE")])
        failed = self._check_if_match(request, res.etag)
        if failed:
            return failed
        res.content = request.content
        res.content_type = request.headers.get("content-type", res.content_type)
        res.etag = self._etag()
        return httpx.Response(204, headers=[("ETag", res.etag)])

    def _patch(self, request: httpx.Request, res: Res) -> httpx.Response:
        if request.headers.get("content-type") != "application/json-patch+json":
            return httpx.Response(415, headers=[("Accept-Patch", "application/json-patch+json")])
        failed = self._check_if_match(request, res.etag)
        if failed:
            return failed
        try:
            doc = apply_patch(json.loads(res.content), json.loads(request.content))
        except PatchError as exc:
            return self._problem(409, str(exc))
        res.content = json.dumps(doc).encode()
        res.etag = self._etag()
        return httpx.Response(204, headers=[("ETag", res.etag)])

    def _delete(self, request: httpx.Request, res: Res) -> httpx.Response:
        failed = self._check_if_match(request, res.etag)
        if failed:
            return failed
        if res.parent is None:
            return self._problem(405, "cannot delete a root")
        if res.children and request.headers.get("depth") != "infinity":
            return self._problem(409, f"Cannot delete container {res.url} - container is not empty.")
        stack = [res.url]
        while stack:
            u = stack.pop()
            stack.extend(self.resources[u].children)
            del self.resources[u]
        self.resources[res.parent].children.remove(res.url)
        return httpx.Response(204)

    # -- linksets -----------------------------------------------------------------------

    def _linkset(self, request: httpx.Request, url: str) -> httpx.Response:
        res = self.resources.get(url)
        if res is None:
            return self._problem(404, "not found")
        headers = [("ETag", res.linkset_etag), ("Allow", "GET, HEAD, PUT, PATCH"),
                   ("Accept-Patch", "application/json-patch+json")]
        doc = {"linkset": [{"anchor": res.url, **copy.deepcopy(res.links)}]}
        if request.method in ("GET", "HEAD"):
            return self._json(200, doc, headers, "application/linkset+json")
        failed = self._check_if_match(request, res.linkset_etag)
        if failed:
            return failed
        if request.method == "PUT":
            new = json.loads(request.content)
        elif request.method == "PATCH":
            try:
                new = apply_patch(doc, json.loads(request.content))
            except (PatchError, KeyError, IndexError) as exc:
                return self._problem(409, str(exc))
        else:
            return self._problem(405, "method not allowed")
        ctx = new["linkset"][0]
        res.links = {k: v for k, v in ctx.items() if k != "anchor"}
        self._n += 1
        res.linkset_etag = f'"ls-{self._n}"'
        return httpx.Response(204, headers=[("ETag", res.linkset_etag)])

    # -- type index / search ------------------------------------------------------------

    def _all_typed(self) -> list[Res]:
        return [r for r in self.resources.values() if r.parent is not None]

    def _type_index(self, page: int) -> httpx.Response:
        seen: list[str] = []
        for r in self._all_typed():
            for t in [CONTAINER if r.kind == "container" else DATA, *r.types]:
                if t not in seen:
                    seen.append(t)
        size = self.page_size
        pages = max(1, (len(seen) + size - 1) // size)
        links = [("Cache-Control", "private"), ("Link", f'<{self.type_index}?page=1>; rel="first"')]
        if page < pages:
            links.append(("Link", f'<{self.type_index}?page={page + 1}>; rel="next"'))
        body = {"@context": "https://www.w3.org/ns/lws/v1", "type": "TypeIndex",
                "totalItems": len(seen),
                "items": [{"id": t} for t in seen[(page - 1) * size: page * size]]}
        return self._json(200, body, links)

    def _type_search(self, request: httpx.Request, query: dict[str, list[str]]) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(204, headers=[("Allow", "OPTIONS, QUERY"),
                                                ("Accept-Query", "application/lws-query+json")])
        if request.method == "GET" and "cursor" in query:
            cursor = query["cursor"][0]
            if cursor not in self.search_cursors:
                return self._problem(404, "expired")
            return self._search_page(cursor, int(query.get("page", ["1"])[0]))
        if request.method != "QUERY":
            return self._problem(405, "method not allowed")
        if request.headers.get("content-type") != "application/lws-query+json":
            return httpx.Response(415, headers=[("Accept-Query", "application/lws-query+json")])
        flt = json.loads(request.content)
        matches = []
        for r in self._all_typed():
            types = [CONTAINER if r.kind == "container" else DATA, *r.types]
            ok = True
            for key, groups in flt.items():
                values = types if key == "type" else [t["href"] for t in r.links.get(key, [])]
                for g in groups:
                    group = [g] if isinstance(g, str) else g
                    if not any(v in values for v in group):
                        ok = False
            if ok:
                kind = "Container" if r.kind == "container" else "DataResource"
                matches.append({"id": r.url, "type": [kind, *r.types]})
        cursor = uuid.uuid4().hex[:6]
        self.search_cursors[cursor] = matches
        return self._search_page(cursor, 1)

    def _search_page(self, cursor: str, page: int) -> httpx.Response:
        matches = self.search_cursors[cursor]
        size = self.page_size
        pages = max(1, (len(matches) + size - 1) // size)
        links = [("Cache-Control", "private"),
                 ("Link", f'<{self.type_search}?cursor={cursor}&page=1>; rel="first"')]
        if page < pages:
            links.append(("Link", f'<{self.type_search}?cursor={cursor}&page={page + 1}>; rel="next"'))
        body = {"@context": "https://www.w3.org/ns/lws/v1", "type": "ContainerPage",
                "totalItems": len(matches), "items": matches[(page - 1) * size: page * size]}
        return self._json(200, body, links)
