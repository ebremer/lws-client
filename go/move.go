// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// MoveResult describes where a moved resource is.
type MoveResult struct {
	// StatusCode is 200 or 204.
	StatusCode int
	// Location is the absolute URL of the resource after the move.
	Location string
	// Linkset is the absolute URL of the resource's linkset after the move.
	Linkset string
	// IdentifierPreserved reports whether the resource kept its URL.
	IdentifierPreserved bool
	// ETag is the linkset's new entity tag, when the server returned one.
	ETag     string
	Metadata ResourceMetadata
	// Document is the updated linkset of a 200 answer, if it carried one.
	Document *Linkset
}

// Move moves the resource at resourceURL (a container with everything in it)
// into the container at destinationURL (lws10-core "Moving Resources").
// lws10-core defines no method for a move: Move reads the resource's linkset
// and patches its up link to destinationURL (see MovePatch), conditionally on
// the linkset's ETag, and the storage moves the resource atomically. A
// storage that does not keep identifiers gives the resource a new URL, which
// is the result's Location: unless the storage's MoveCapability promises
// PreservesIdentifier, rely on it rather than on resourceURL.
//
// Move does not read the storage description: whether the storage moves
// resources is its MoveCapability, which an application checks first. A
// storage that does not refuses with a 4xx (ErrConflict), as it does a
// destination that is not an existing container, or a container moved into
// itself or below it. Moving needs permission to delete the resource and to
// create in the destination (ErrForbidden).
//
// Honoured options: IfMatch (overrides the linkset's ETag), Header.
func (c *Client) Move(ctx context.Context, resourceURL, destinationURL string, opts ...CallOption) (*MoveResult, error) {
	o := applyCallOptions(opts)
	doc, err := c.ReadLinkset(ctx, resourceURL, func(r *callOptions) { r.header = o.header.Clone() })
	if err != nil {
		return nil, err
	}
	patch, err := MovePatch(doc.Linkset, doc.URL, resourceURL, destinationURL)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	po := &callOptions{header: o.header, ifMatch: o.ifMatch}
	if po.ifMatch == "" {
		po.ifMatch = doc.ETag
	}
	u, err := c.modify(ctx, http.MethodPatch, doc.URL, bytes.NewReader(data), MediaJSONPatch, po)
	if err != nil {
		return nil, err
	}
	return moveResult(resourceURL, doc.URL, u)
}

// MovePatch builds the JSON Patch that moves a resource into the container
// destinationURL (absolute), given the resource's linkset as read from
// linksetURL: it tests that the resource's up link still holds the href as
// read, and replaces it with destinationURL. The resource's link context is
// the first whose anchor resolves (against linksetURL) to resourceURL, or the
// only context when it has no anchor; its up link is its first "up" target.
// Without either it fails with a *ProtocolError.
func MovePatch(ls *Linkset, linksetURL, resourceURL, destinationURL string) (JSONPatch, error) {
	i := resourceContext(ls, linksetURL, resourceURL)
	if i < 0 {
		return nil, protocolErr("linkset %s has no link context for %s", linksetURL, resourceURL)
	}
	for _, r := range ls.Contexts[i].Relations {
		if relEquals(r.Rel, RelUp) && len(r.Targets) > 0 {
			path := JSONPointer("linkset", strconv.Itoa(i), r.Rel, "0", "href")
			return JSONPatch{}.Test(path, r.Targets[0].Href).Replace(path, destinationURL), nil
		}
	}
	return nil, protocolErr("linkset %s has no up link for %s", linksetURL, resourceURL)
}

// resourceContext returns the index of resourceURL's link context in ls, or
// -1 if it has none.
func resourceContext(ls *Linkset, linksetURL, resourceURL string) int {
	if len(ls.Contexts) == 1 && ls.Contexts[0].Anchor == "" {
		return 0
	}
	for i, lc := range ls.Contexts {
		if lc.Anchor != "" && SameResource(resolveURL(linksetURL, lc.Anchor), resourceURL) {
			return i
		}
	}
	return -1
}

// moveResult interprets the answer to a move's patch of the linkset at
// linksetURL. A 200 that carries the updated linkset names the resource's URL
// after the move as the anchor of its first context with an up link (resolved
// against Content-Location, the linkset's new URL, else linksetURL); otherwise
// the resource and its linkset kept their URLs.
func moveResult(resourceURL, linksetURL string, u *UpdateResult) (*MoveResult, error) {
	r := &MoveResult{StatusCode: u.StatusCode, Location: resourceURL, Linkset: linksetURL, ETag: u.ETag, Metadata: u.Metadata}
	if u.StatusCode == http.StatusOK {
		if cl := u.Metadata.Header.Get("Content-Location"); cl != "" {
			r.Linkset = resolveURL(linksetURL, cl)
		}
		if len(bytes.TrimSpace(u.Body)) > 0 {
			ls, err := ParseLinkset(u.Body)
			if err != nil {
				return nil, &ProtocolError{Message: "malformed linkset in the answer to a move", Err: err}
			}
			r.Document = ls
			for _, lc := range ls.Contexts {
				if len(lc.Targets(RelUp)) > 0 {
					if lc.Anchor != "" {
						r.Location = resolveURL(r.Linkset, lc.Anchor)
					}
					break
				}
			}
		}
	}
	r.IdentifierPreserved = r.Location == resourceURL || SameResource(r.Location, resourceURL)
	return r, nil
}
