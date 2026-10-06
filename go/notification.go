// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"time"
)

// Notification is an LWS notification envelope: one or more Activity
// Streams 2.0 activities about resources in a storage.
type Notification struct {
	// Storage is the URI of the storage the notification is about.
	Storage string
	// Activities always holds every activity (the "activity" member may be a
	// single object or an array).
	Activities []Activity
	Raw        json.RawMessage
}

// Activity describes one event.
type Activity struct {
	ID     string
	Types  TypeList
	Object ActivityObject
	// Actor is the agent that performed the action, if disclosed.
	Actor string
	// Target is the container a resource was added to (Create).
	Target string
	// Origin is the container a resource was removed from (Delete).
	Origin string
	// Published is when the activity occurred (zero if unparseable; see
	// PublishedRaw).
	Published    time.Time
	PublishedRaw string
	Raw          json.RawMessage
}

// ActivityObject identifies the resource an activity is about.
type ActivityObject struct {
	ID    string   `json:"id"`
	Types TypeList `json:"type"`
}

// IsCreate reports whether the activity is a Create.
func (a Activity) IsCreate() bool { return a.Types.Has(ActivityCreate) }

// IsUpdate reports whether the activity is an Update.
func (a Activity) IsUpdate() bool { return a.Types.Has(ActivityUpdate) }

// IsDelete reports whether the activity is a Delete.
func (a Activity) IsDelete() bool { return a.Types.Has(ActivityDelete) }

// ParseNotification parses a notification envelope. It fails with a
// *ProtocolError if the type is not "Notification".
func ParseNotification(data []byte) (*Notification, error) {
	var doc struct {
		Type     TypeList        `json:"type"`
		Storage  string          `json:"storage"`
		Activity json.RawMessage `json:"activity"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, &ProtocolError{Message: "malformed notification", Err: err}
	}
	if !doc.Type.Has(TypeNotification) {
		return nil, protocolErr("notification type %v is not Notification", []string(doc.Type))
	}
	n := &Notification{Storage: doc.Storage, Raw: append(json.RawMessage(nil), data...)}
	for _, raw := range objectList(doc.Activity) {
		var a struct {
			ID        string         `json:"id"`
			Type      TypeList       `json:"type"`
			Object    ActivityObject `json:"object"`
			Actor     string         `json:"actor"`
			Target    string         `json:"target"`
			Origin    string         `json:"origin"`
			Published string         `json:"published"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, &ProtocolError{Message: "malformed activity", Err: err}
		}
		n.Activities = append(n.Activities, Activity{
			ID: a.ID, Types: a.Type, Object: a.Object, Actor: a.Actor, Target: a.Target, Origin: a.Origin,
			Published: parseDateTime(a.Published), PublishedRaw: a.Published, Raw: append(json.RawMessage(nil), raw...),
		})
	}
	return n, nil
}

// WebhookSubscriptionRequest describes a webhook subscription.
type WebhookSubscriptionRequest struct {
	// Topics are the resources to watch. A container topic is recursive.
	Topics []string
	// Inbox is the URL notifications are POSTed to.
	Inbox string
	// Expires optionally requests an expiry time.
	Expires time.Time
}

// MarshalJSON encodes the application/lws+json subscription request.
func (r WebhookSubscriptionRequest) MarshalJSON() ([]byte, error) {
	doc := map[string]any{
		"@context": []string{LWSContext},
		"type":     SubscriptionWebhook,
		"topic":    nonNil(r.Topics),
		"inbox":    r.Inbox,
	}
	if !r.Expires.IsZero() {
		doc["expires"] = r.Expires.UTC().Format(time.RFC3339)
	}
	return json.Marshal(doc)
}

// Subscription is a notification subscription.
type Subscription struct {
	Type string
	// URL manages the subscription's lifecycle (GetSubscription, Unsubscribe).
	URL string
	// Expires is the expiry time, if any (see ExpiresRaw).
	Expires    time.Time
	ExpiresRaw string
	Raw        json.RawMessage
}

func parseSubscription(data []byte, base, location string) (*Subscription, error) {
	var doc struct {
		Type         string `json:"type"`
		Subscription string `json:"subscription"`
		Expires      string `json:"expires"`
	}
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, &ProtocolError{Message: "malformed subscription", Err: err}
		}
	}
	s := &Subscription{
		Type:       doc.Type,
		URL:        resolveURL(base, doc.Subscription),
		ExpiresRaw: doc.Expires,
		Expires:    parseDateTime(doc.Expires),
		Raw:        append(json.RawMessage(nil), data...),
	}
	if s.URL == "" && location != "" {
		s.URL = resolveURL(base, location)
	}
	if s.URL == "" {
		return nil, protocolErr("subscription response has neither a subscription URL nor a Location")
	}
	return s, nil
}

// Subscribe creates a webhook subscription at the NotificationService
// endpoint serviceURL.
func (c *Client) Subscribe(ctx context.Context, serviceURL string, req WebhookSubscriptionRequest, opts ...CallOption) (*Subscription, error) {
	o := applyCallOptions(opts)
	if o.accept == "" {
		o.accept = MediaLWSJSON
	}
	resp, body, err := c.executeJSON(ctx, http.MethodPost, serviceURL, req, MediaLWSJSON, o)
	if err != nil {
		return nil, err
	}
	return parseSubscription(body, responseURL(resp), resp.Header.Get("Location"))
}

// SubscribeWebhook finds the storage's NotificationService, checks that it
// supports WebhookSubscription and subscribes.
func (c *Client) SubscribeWebhook(ctx context.Context, storage *StorageDescription, req WebhookSubscriptionRequest, opts ...CallOption) (*Subscription, error) {
	svc, ok := storage.NotificationService()
	if !ok {
		return nil, protocolErr("storage %s has no NotificationService", storage.ID)
	}
	if !TypeList(svc.SubscriptionTypes()).Has(SubscriptionWebhook) {
		return nil, protocolErr("notification service %s does not support %s", svc.ServiceEndpoint, SubscriptionWebhook)
	}
	return c.Subscribe(ctx, svc.ServiceEndpoint, req, opts...)
}

// ListSubscriptions iterates over the subscriber's subscriptions listed by
// the notification service.
func (c *Client) ListSubscriptions(ctx context.Context, serviceURL string, opts ...CallOption) iter.Seq2[ContainedResource, error] {
	return flattenPages(c.pages(ctx, serviceURL, false, opts))
}

// GetSubscription retrieves the current state of a subscription.
func (c *Client) GetSubscription(ctx context.Context, url string, opts ...CallOption) (*Subscription, error) {
	o := applyCallOptions(opts)
	if o.accept == "" {
		o.accept = MediaLWSJSON
	}
	resp, body, err := c.execute(ctx, http.MethodGet, url, nil, "", o)
	if err != nil {
		return nil, err
	}
	s, err := parseSubscription(body, responseURL(resp), "")
	if err != nil {
		// A server may omit the "subscription" member in GET responses.
		s, err = parseSubscription(body, responseURL(resp), responseURL(resp))
	}
	return s, err
}

// Unsubscribe cancels a subscription.
func (c *Client) Unsubscribe(ctx context.Context, url string, opts ...CallOption) error {
	return c.Delete(ctx, url, opts...)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
