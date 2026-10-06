// SPDX-License-Identifier: MIT

package lws

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// memServer is a small in-memory LWS server used by the tests. It implements
// storage discovery, containers with pagination, CRUD with conditional
// requests, linksets, JSON Patch, the token exchange authorization server,
// notifications subscriptions, access requests/grants and the type
// index/search services.
type memServer struct {
	t           *testing.T
	srv         *httptest.Server
	mu          sync.Mutex
	res         map[string]*memResource
	pageSize    int
	requireAuth bool
	seq         int

	tokens        map[string]string // access token -> subject
	tokenRequests int
	challenges    int
	lastTokenForm url.Values
	requests      []string // "METHOD path"
	headers       []http.Header

	subs      map[string]json.RawMessage
	subOrder  []string
	access    map[string]map[string]json.RawMessage // endpoint -> path -> doc
	accessOrd map[string][]string
	searches  map[string][]string // cursor -> matched paths
}

type memResource struct {
	container bool
	body      []byte
	ctype     string
	etag      string
	modified  time.Time
	children  []string
	types     []string
	linkset   json.RawMessage // user-managed linkset context relations, as {"rel":[{...}]}
}

func newMemServer(t *testing.T) *memServer {
	s := &memServer{
		t:         t,
		res:       map[string]*memResource{},
		pageSize:  5,
		tokens:    map[string]string{},
		subs:      map[string]json.RawMessage{},
		access:    map[string]map[string]json.RawMessage{"/access/requests/": {}, "/access/grants/": {}},
		accessOrd: map[string][]string{},
		searches:  map[string][]string{},
	}
	s.res["/root/"] = &memResource{container: true, etag: s.nextETag(), modified: time.Now()}
	s.srv = httptest.NewServer(s)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *memServer) URL(path string) string { return s.srv.URL + path }

func (s *memServer) nextETag() string {
	s.seq++
	return fmt.Sprintf(`"e%d"`, s.seq)
}

func (s *memServer) count(method, path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if r == method+" "+path {
			n++
		}
	}
	return n
}

func (s *memServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	s.headers = append(s.headers, r.Header.Clone())
	p := r.URL.Path
	switch {
	case p == "/.well-known/lws-configuration":
		s.metadata(w)
		return
	case p == "/token":
		s.token(w, r)
		return
	case p == "/" && r.Method == http.MethodGet:
		s.description(w)
		return
	}
	if s.requireAuth {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if _, ok := s.tokens[auth]; !ok {
			s.challenges++
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer as_uri="%s", realm="%s/", error="invalid_token"`, s.srv.URL, s.srv.URL))
			w.Header().Add("Link", fmt.Sprintf(`<%s/>; rel="%s"`, s.srv.URL, RelStorage))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	switch {
	case strings.HasPrefix(p, "/types/"):
		s.types(w, r)
	case strings.HasPrefix(p, "/notifications/"):
		s.notifications(w, r)
	case strings.HasPrefix(p, "/access/"):
		s.accessEndpoint(w, r)
	case strings.HasSuffix(p, ".meta"):
		s.linksetResource(w, r, strings.TrimSuffix(p, ".meta"))
	default:
		s.resource(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, ctype string, v any) {
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, title string) {
	writeJSON(w, status, MediaProblemJSON, map[string]any{"type": "about:blank", "title": title, "status": status})
}

func (s *memServer) metadata(w http.ResponseWriter) {
	writeJSON(w, 200, MediaJSON, map[string]any{
		"issuer":                        s.srv.URL,
		"token_endpoint":                s.srv.URL + "/token",
		"grant_types_supported":         []string{GrantTypeTokenExchange},
		"subject_token_types_supported": []string{TokenTypeJWT, TokenTypeIDToken, TokenTypeSAML2},
	})
}

func (s *memServer) token(w http.ResponseWriter, r *http.Request) {
	s.tokenRequests++
	_ = r.ParseForm()
	s.lastTokenForm = r.PostForm
	f := r.PostForm
	bad := func(msg string) {
		writeJSON(w, 400, MediaJSON, map[string]string{"error": "invalid_request", "error_description": msg})
	}
	if f.Get("grant_type") != GrantTypeTokenExchange {
		bad("grant_type")
		return
	}
	if f.Get("resource") != s.srv.URL+"/" {
		bad("unknown resource " + f.Get("resource"))
		return
	}
	subject := "anonymous"
	switch f.Get("subject_token_type") {
	case TokenTypeJWT:
		token := f.Get("subject_token")
		_, claims, err := DecodeJWT(token)
		if err != nil {
			bad(err.Error())
			return
		}
		sub, _ := claims["sub"].(string)
		pub, err := PublicKeyFromDIDKey(sub)
		if err != nil {
			bad("subject must be did:key in tests")
			return
		}
		if _, _, err := VerifyJWT(token, pub); err != nil {
			bad(err.Error())
			return
		}
		aud, _ := claims["aud"].([]any)
		if claims["iss"] != sub || claims["client_id"] != sub || len(aud) != 1 || aud[0] != s.srv.URL {
			bad("bad claims")
			return
		}
		subject = sub
	case TokenTypeIDToken, TokenTypeSAML2:
		subject = f.Get("subject_token")
	default:
		bad("subject_token_type")
		return
	}
	tok := fmt.Sprintf("at-%d", s.tokenRequests)
	s.tokens[tok] = subject
	writeJSON(w, 200, MediaJSON, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 300})
}

func (s *memServer) description(w http.ResponseWriter) {
	writeJSON(w, 200, MediaLWSCID, map[string]any{
		"@context": []string{CIDContext, LWSContext},
		"id":       s.srv.URL + "/",
		"type":     "Storage",
		"service": []map[string]any{
			{"type": ServiceStorageRoot, "serviceEndpoint": s.srv.URL + "/root/"},
			{"type": ServiceNotification, "serviceEndpoint": s.srv.URL + "/notifications/", "subscriptionType": []string{SubscriptionWebhook}},
			{"type": ServiceAccessRequest, "serviceEndpoint": "/access/requests/"},
			{"type": ServiceAccessGrant, "serviceEndpoint": s.srv.URL + "/access/grants/"},
			{"type": ServiceTypeIndex, "serviceEndpoint": s.srv.URL + "/types/index"},
			{"type": ServiceTypeSearch, "serviceEndpoint": s.srv.URL + "/types/search"},
		},
	})
}

func parentOf(p string) string {
	trimmed := strings.TrimSuffix(p, "/")
	return trimmed[:strings.LastIndexByte(trimmed, '/')+1]
}

// esc percent-encodes a decoded path for use in headers and documents.
func esc(p string) string { return (&url.URL{Path: p}).EscapedPath() }

func (s *memServer) links(w http.ResponseWriter, p string, res *memResource) {
	h := w.Header()
	h.Add("Link", fmt.Sprintf(`<%s.meta>; rel="linkset"; type="application/linkset+json"`, esc(p)))
	if p != "/root/" {
		h.Add("Link", fmt.Sprintf(`<%s>; rel="up"`, esc(parentOf(p))))
	}
	t := TypeDataResource
	if res.container {
		t = TypeContainer
	}
	h.Add("Link", fmt.Sprintf(`<%s>; rel="type"`, t))
	for _, ut := range res.types {
		h.Add("Link", fmt.Sprintf(`<%s>; rel="type"`, ut))
	}
	h.Add("Link", fmt.Sprintf(`</>; rel="%s"`, RelStorage))
	h.Set("ETag", res.etag)
	h.Set("Last-Modified", res.modified.UTC().Format(http.TimeFormat))
}

func (s *memServer) resource(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	res, ok := s.res[p]
	if !ok {
		problem(w, 404, "Not Found")
		return
	}
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		s.links(w, p, res)
		if inm := r.Header.Get("If-None-Match"); inm != "" && inm == res.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if res.container {
			s.listing(w, r, p, res)
			return
		}
		w.Header().Set("Content-Type", res.ctype)
		w.Header().Set("Accept-Patch", MediaJSONPatch)
		body := res.body
		if rg := r.Header.Get("Range"); rg != "" {
			var a, b int
			if _, err := fmt.Sscanf(rg, "bytes=%d-%d", &a, &b); err == nil && a <= b && b < len(body) {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", a, b, len(body)))
				w.WriteHeader(http.StatusPartialContent)
				if r.Method == http.MethodGet {
					_, _ = w.Write(body[a : b+1])
				}
				return
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	case http.MethodPost:
		if !res.container {
			problem(w, 405, "Method Not Allowed")
			return
		}
		s.create(w, r, p, res)
	case http.MethodPut:
		if res.container {
			w.Header().Set("Allow", "GET, HEAD, POST, DELETE")
			problem(w, 405, "Method Not Allowed")
			return
		}
		if im := r.Header.Get("If-Match"); im != "" && im != res.etag {
			problem(w, 412, "Precondition Failed")
			return
		}
		body, _ := io.ReadAll(r.Body)
		res.body, res.ctype = body, r.Header.Get("Content-Type")
		res.etag, res.modified = s.nextETag(), time.Now()
		if strings.Contains(r.Header.Get("Prefer"), PreferSetLinkset) {
			res.linkset = userLinks(r)
		}
		w.Header().Set("ETag", res.etag)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPatch:
		if r.Header.Get("Content-Type") != MediaJSONPatch {
			w.Header().Set("Accept-Patch", MediaJSONPatch)
			problem(w, 415, "Unsupported Media Type")
			return
		}
		if im := r.Header.Get("If-Match"); im != "" && im != res.etag {
			problem(w, 412, "Precondition Failed")
			return
		}
		var doc any
		if err := json.Unmarshal(res.body, &doc); err != nil {
			problem(w, 422, "not JSON")
			return
		}
		var patch []map[string]any
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &patch); err != nil {
			problem(w, 400, "bad patch")
			return
		}
		out, err := applyPatch(doc, patch)
		if err != nil {
			problem(w, 409, err.Error())
			return
		}
		res.body, _ = json.Marshal(out)
		res.etag, res.modified = s.nextETag(), time.Now()
		w.Header().Set("ETag", res.etag)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if im := r.Header.Get("If-Match"); im != "" && im != res.etag {
			problem(w, 412, "Precondition Failed")
			return
		}
		if p == "/root/" {
			problem(w, 405, "cannot delete root")
			return
		}
		if res.container && len(res.children) > 0 && r.Header.Get("Depth") != "infinity" {
			problem(w, 409, "Container not empty")
			return
		}
		s.remove(p)
		w.WriteHeader(http.StatusNoContent)
	default:
		problem(w, 405, "Method Not Allowed")
	}
}

func (s *memServer) remove(p string) {
	if res, ok := s.res[p]; ok {
		for _, c := range res.children {
			s.remove(c)
		}
	}
	delete(s.res, p)
	if parent, ok := s.res[parentOf(p)]; ok {
		kids := parent.children[:0]
		for _, c := range parent.children {
			if c != p {
				kids = append(kids, c)
			}
		}
		parent.children = kids
	}
}

// userLinks converts request Link headers (except server-managed ones) to
// linkset relations.
func userLinks(r *http.Request) json.RawMessage {
	rels := map[string][]map[string]any{}
	for _, l := range ParseLinkHeader(r.URL.String(), r.Header.Values("Link")...) {
		switch l.Rel {
		case RelType, RelUp, RelLinkset, RelStorage:
			continue
		}
		rels[l.Rel] = append(rels[l.Rel], map[string]any{"href": l.Href})
	}
	if len(rels) == 0 {
		return nil
	}
	b, _ := json.Marshal(rels)
	return b
}

func (s *memServer) create(w http.ResponseWriter, r *http.Request, p string, parent *memResource) {
	slug, _ := url.PathUnescape(r.Header.Get("Slug"))
	slug = strings.Trim(strings.ReplaceAll(slug, "/", "-"), " ")
	if slug == "" {
		slug = fmt.Sprintf("r%d", s.seq+1)
	}
	isContainer := false
	var types []string
	for _, l := range ParseLinkHeader(r.URL.String(), r.Header.Values("Link")...) {
		if l.Rel != RelType {
			continue
		}
		if l.Href == TypeContainer {
			isContainer = true
		} else if l.Href != TypeDataResource {
			types = append(types, l.Href)
		}
	}
	name := p + slug
	if isContainer {
		name += "/"
	}
	for i := 1; s.res[name] != nil; i++ {
		name = fmt.Sprintf("%s%s-%d", p, slug, i)
		if isContainer {
			name += "/"
		}
	}
	body, _ := io.ReadAll(r.Body)
	res := &memResource{container: isContainer, types: types, etag: s.nextETag(), modified: time.Now(), linkset: userLinks(r)}
	if !isContainer {
		res.body = body
		res.ctype = r.Header.Get("Content-Type")
		if res.ctype == "" {
			res.ctype = "application/octet-stream"
		}
	}
	s.res[name] = res
	parent.children = append(parent.children, name)
	parent.etag = s.nextETag()
	s.links(w, name, res)
	w.Header().Del("ETag")
	w.Header().Set("Location", esc(name)) // relative on purpose
	w.WriteHeader(http.StatusCreated)
}

func (s *memServer) describe(p string) map[string]any {
	res := s.res[p]
	if res.container {
		return map[string]any{"id": esc(p), "type": "Container", "modified": res.modified.UTC().Format(time.RFC3339)}
	}
	t := any("DataResource")
	if len(res.types) > 0 {
		t = append([]string{"DataResource"}, res.types...)
	}
	return map[string]any{"id": esc(p), "type": t, "format": res.ctype, "size": len(res.body), "modified": res.modified.UTC().Format(time.RFC3339)}
}

// page writes a paginated container-shaped listing of ids.
func (s *memServer) page(w http.ResponseWriter, r *http.Request, id, typ string, ids []string, describe func(string) map[string]any, pageURL func(int) string) {
	n := 1
	if v := r.URL.Query().Get("page"); v != "" {
		n, _ = strconv.Atoi(v)
	}
	pages := (len(ids) + s.pageSize - 1) / s.pageSize
	if pages == 0 {
		pages = 1
	}
	if n < 1 || n > pages {
		problem(w, 404, "no such page")
		return
	}
	start, end := (n-1)*s.pageSize, n*s.pageSize
	if end > len(ids) {
		end = len(ids)
	}
	items := []map[string]any{}
	for _, c := range ids[start:end] {
		items = append(items, describe(c))
	}
	if len(ids) > s.pageSize {
		w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="first"`, pageURL(1)))
		w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="last"`, pageURL(pages)))
		if n < pages {
			w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="next"`, pageURL(n+1)))
		}
		if n > 1 {
			w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="prev"`, pageURL(n-1)))
		}
	}
	accept := r.Header.Get("Accept")
	ct := MediaLWSJSON
	if accept == MediaJSON || accept == MediaLDJSON {
		ct = accept
	}
	doc := map[string]any{"@context": LWSContext, "type": typ, "totalItems": len(ids), "items": items}
	if id != "" {
		doc["id"] = id
	}
	w.Header().Set("Vary", "Accept")
	writeJSON(w, 200, ct, doc)
}

func (s *memServer) listing(w http.ResponseWriter, r *http.Request, p string, res *memResource) {
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", MediaLWSJSON)
		return
	}
	s.page(w, r, p, "Container", res.children, s.describe, func(n int) string { return fmt.Sprintf("%s?page=%d", p, n) })
}

func (s *memServer) linksetDoc(p string, res *memResource) map[string]any {
	ctx := map[string]any{"anchor": s.srv.URL + esc(p)}
	if len(res.linkset) > 0 {
		var rels map[string]any
		_ = json.Unmarshal(res.linkset, &rels)
		for k, v := range rels {
			ctx[k] = v
		}
	}
	return map[string]any{"linkset": []any{ctx}}
}

func (s *memServer) linksetResource(w http.ResponseWriter, r *http.Request, p string) {
	res, ok := s.res[p]
	if !ok {
		problem(w, 404, "Not Found")
		return
	}
	lsETag := fmt.Sprintf(`"ls-%s"`, strings.Trim(res.etag, `"`))
	w.Header().Set("Allow", "GET, HEAD, PUT, PATCH")
	w.Header().Set("Accept-Patch", MediaJSONPatch)
	if im := r.Header.Get("If-Match"); im != "" && im != lsETag {
		problem(w, 412, "Precondition Failed")
		return
	}
	var doc any = s.linksetDoc(p, res)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		w.Header().Set("ETag", lsETag)
		writeJSON(w, 200, MediaLinksetJSON, doc)
		return
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &doc); err != nil {
			problem(w, 400, "bad linkset")
			return
		}
	case http.MethodPatch:
		var patch []map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &patch)
		norm, _ := json.Marshal(doc)
		_ = json.Unmarshal(norm, &doc)
		out, err := applyPatch(doc, patch)
		if err != nil {
			problem(w, 409, err.Error())
			return
		}
		doc = out
	default:
		problem(w, 405, "Method Not Allowed")
		return
	}
	ctxs, _ := doc.(map[string]any)["linkset"].([]any)
	rels := map[string]any{}
	if len(ctxs) > 0 {
		for k, v := range ctxs[0].(map[string]any) {
			if k != "anchor" {
				rels[k] = v
			}
		}
	}
	res.linkset, _ = json.Marshal(rels)
	res.etag = s.nextETag()
	w.Header().Set("ETag", fmt.Sprintf(`"ls-%s"`, strings.Trim(res.etag, `"`)))
	w.WriteHeader(http.StatusNoContent)
}

// applyPatch is a minimal RFC 6902 implementation (add, remove, replace,
// test) over decoded JSON.
func applyPatch(doc any, ops []map[string]any) (any, error) {
	for _, op := range ops {
		path, _ := op["path"].(string)
		segs := strings.Split(path, "/")[1:]
		for i := range segs {
			segs[i] = UnescapePointerSegment(segs[i])
		}
		var err error
		doc, err = patchAt(doc, segs, op)
		if err != nil {
			return nil, err
		}
	}
	return doc, nil
}

func patchAt(node any, segs []string, op map[string]any) (any, error) {
	kind, _ := op["op"].(string)
	if len(segs) == 1 {
		key := segs[0]
		switch n := node.(type) {
		case map[string]any:
			switch kind {
			case "add", "replace":
				if _, ok := n[key]; !ok && kind == "replace" {
					return nil, errors.New("replace of missing member")
				}
				n[key] = op["value"]
			case "remove":
				delete(n, key)
			case "test":
				a, _ := json.Marshal(n[key])
				b, _ := json.Marshal(op["value"])
				if string(a) != string(b) {
					return nil, errors.New("test failed")
				}
			}
			return n, nil
		case []any:
			if key == "-" && kind == "add" {
				return append(n, op["value"]), nil
			}
			i, err := strconv.Atoi(key)
			if err != nil || i < 0 || i >= len(n) {
				return nil, errors.New("bad index")
			}
			switch kind {
			case "remove":
				return append(n[:i], n[i+1:]...), nil
			case "replace":
				n[i] = op["value"]
			case "add":
				n = append(n[:i], append([]any{op["value"]}, n[i:]...)...)
			}
			return n, nil
		}
		return nil, errors.New("bad target")
	}
	switch n := node.(type) {
	case map[string]any:
		child, ok := n[segs[0]]
		if !ok {
			return nil, errors.New("missing member " + segs[0])
		}
		v, err := patchAt(child, segs[1:], op)
		if err != nil {
			return nil, err
		}
		n[segs[0]] = v
		return n, nil
	case []any:
		i, err := strconv.Atoi(segs[0])
		if err != nil || i < 0 || i >= len(n) {
			return nil, errors.New("bad index")
		}
		v, err := patchAt(n[i], segs[1:], op)
		if err != nil {
			return nil, err
		}
		n[i] = v
		return n, nil
	}
	return nil, errors.New("bad path")
}

func (s *memServer) notifications(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/notifications/" {
		switch r.Method {
		case http.MethodPost:
			var req map[string]any
			body, _ := io.ReadAll(r.Body)
			if json.Unmarshal(body, &req) != nil || req["type"] != SubscriptionWebhook || req["inbox"] == nil || r.Header.Get("Content-Type") != MediaLWSJSON {
				problem(w, 400, "bad subscription")
				return
			}
			s.seq++
			id := fmt.Sprintf("/notifications/sub-%d", s.seq)
			resp := map[string]any{"@context": []string{LWSContext}, "type": SubscriptionWebhook, "subscription": id}
			if e, ok := req["expires"]; ok {
				resp["expires"] = e
			}
			b, _ := json.Marshal(resp)
			s.subs[id] = b
			s.subOrder = append(s.subOrder, id)
			w.Header().Set("Location", id)
			writeJSON(w, 200, MediaLWSJSON, resp)
		case http.MethodGet:
			s.page(w, r, p, "Container", s.subOrder, func(id string) map[string]any {
				return map[string]any{"id": id, "type": []string{"DataResource", SubscriptionWebhook}, "format": MediaLWSJSON}
			}, func(n int) string { return fmt.Sprintf("%s?page=%d", p, n) })
		default:
			problem(w, 405, "Method Not Allowed")
		}
		return
	}
	doc, ok := s.subs[p]
	if !ok {
		problem(w, 404, "Not Found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", MediaLWSJSON)
		_, _ = w.Write(doc)
	case http.MethodDelete:
		delete(s.subs, p)
		ord := s.subOrder[:0]
		for _, id := range s.subOrder {
			if id != p {
				ord = append(ord, id)
			}
		}
		s.subOrder = ord
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *memServer) accessEndpoint(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	endpoint := "/access/requests/"
	want := TypeAccessRequest
	if strings.HasPrefix(p, "/access/grants/") {
		endpoint, want = "/access/grants/", TypeAccessGrant
	}
	docs := s.access[endpoint]
	if p == endpoint {
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			var doc struct {
				Type    TypeList        `json:"type"`
				Storage string          `json:"storage"`
				Access  json.RawMessage `json:"access"`
			}
			if json.Unmarshal(body, &doc) != nil || !doc.Type.Has(want) || doc.Storage == "" || len(doc.Access) == 0 {
				problem(w, 400, "bad access document")
				return
			}
			s.seq++
			id := fmt.Sprintf("%s%d", endpoint, s.seq)
			docs[id] = body
			s.accessOrd[endpoint] = append(s.accessOrd[endpoint], id)
			w.Header().Set("Location", id)
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			var ids []string
			for _, id := range s.accessOrd[endpoint] {
				if _, ok := docs[id]; ok {
					ids = append(ids, id)
				}
			}
			s.page(w, r, p, "Container", ids, func(id string) map[string]any {
				return map[string]any{"id": id, "type": "DataResource", "format": MediaLWSJSON}
			}, func(n int) string { return fmt.Sprintf("%s?page=%d", p, n) })
		}
		return
	}
	doc, ok := docs[p]
	if !ok {
		problem(w, 404, "Not Found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", MediaLWSJSON)
		_, _ = w.Write(doc)
	case http.MethodDelete:
		delete(docs, p)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *memServer) typesOf(p string) []string {
	res := s.res[p]
	t := TypeDataResource
	if res.container {
		t = TypeContainer
	}
	return append([]string{t}, res.types...)
}

func (s *memServer) types(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/types/index":
		set := map[string]bool{}
		for p := range s.res {
			for _, t := range s.typesOf(p) {
				set[t] = true
			}
		}
		var all []string
		for t := range set {
			all = append(all, t)
		}
		sort.Strings(all)
		w.Header().Set("Cache-Control", "private")
		s.page(w, r, "", "TypeIndex", all, func(t string) map[string]any { return map[string]any{"id": t} },
			func(n int) string { return fmt.Sprintf("/types/index?page=%d", n) })
	case "/types/search":
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "OPTIONS, QUERY")
			w.Header().Set("Accept-Query", MediaLWSQueryJSON)
			w.WriteHeader(http.StatusNoContent)
		case "QUERY":
			if r.Header.Get("Content-Type") != MediaLWSQueryJSON {
				w.Header().Set("Accept-Query", MediaLWSQueryJSON)
				problem(w, 415, "Unsupported Media Type")
				return
			}
			var filter map[string][]any
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &filter); err != nil {
				problem(w, 400, "bad filter")
				return
			}
			var matched []string
			for p := range s.res {
				if matchFilter(s.typesOf(p), filter["type"]) {
					matched = append(matched, p)
				}
			}
			sort.Strings(matched)
			s.seq++
			cursor := fmt.Sprintf("c%d", s.seq)
			s.searches[cursor] = matched
			s.searchPage(w, r, cursor)
		case http.MethodGet:
			s.searchPage(w, r, r.URL.Query().Get("cursor"))
		}
	default:
		problem(w, 404, "Not Found")
	}
}

func (s *memServer) searchPage(w http.ResponseWriter, r *http.Request, cursor string) {
	matched, ok := s.searches[cursor]
	if !ok {
		problem(w, 404, "expired cursor")
		return
	}
	w.Header().Set("Cache-Control", "private")
	s.page(w, r, "", "ContainerPage", matched, func(p string) map[string]any {
		return map[string]any{"id": s.srv.URL + esc(p), "type": s.typesOf(p)}
	}, func(n int) string { return fmt.Sprintf("/types/search?cursor=%s&page=%d", cursor, n) })
}

func matchFilter(types []string, groups []any) bool {
	for _, g := range groups {
		var alts []string
		switch x := g.(type) {
		case string:
			alts = []string{x}
		case []any:
			for _, a := range x {
				alts = append(alts, a.(string))
			}
		}
		ok := false
		for _, a := range alts {
			if contains(types, a) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
