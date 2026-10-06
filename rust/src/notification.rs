// SPDX-License-Identifier: MIT
//! Notifications: the LWS notification data model and webhook subscriptions.

use std::time::SystemTime;

use serde_json::{Map, Value, json};
use url::Url;

use crate::constants::{LWS_CONTEXT, activity, service};
use crate::datetime::{format_rfc3339, parse_rfc3339};
use crate::error::{Error, Result};
use crate::types::{has_type, string_list, type_matches};

/// The resource an activity is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityObject {
    /// Resource URI.
    pub id: String,
    /// Resource types (e.g. `DataResource`, `Container`).
    pub types: Vec<String>,
}

/// An Activity Streams 2.0 activity describing a change.
#[derive(Debug, Clone, PartialEq)]
pub struct Activity {
    /// Activity identifier.
    pub id: String,
    /// Activity types (`Create`, `Update`, `Delete`, …).
    pub types: Vec<String>,
    /// The affected resource.
    pub object: ActivityObject,
    /// The agent that performed the action.
    pub actor: Option<String>,
    /// Container the resource was added to (Create).
    pub target: Option<String>,
    /// Container the resource was removed from (Delete).
    pub origin: Option<String>,
    /// When the activity occurred, when parseable.
    pub published: Option<SystemTime>,
    /// Raw `published` value.
    pub published_raw: Option<String>,
    /// The raw JSON object.
    pub raw: Value,
}

impl Activity {
    fn from_json(v: &Value) -> Result<Self> {
        let obj = v
            .get("object")
            .ok_or_else(|| Error::Protocol("activity without object".into()))?;
        let object_id = match obj {
            Value::String(s) => s.clone(),
            _ => obj
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Protocol("activity object without id".into()))?
                .to_owned(),
        };
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let published_raw = s("published");
        Ok(Self {
            id: s("id").unwrap_or_default(),
            types: string_list(v.get("type")),
            object: ActivityObject {
                id: object_id,
                types: string_list(obj.get("type")),
            },
            actor: s("actor"),
            target: s("target"),
            origin: s("origin"),
            published: published_raw.as_deref().and_then(parse_rfc3339),
            published_raw,
            raw: v.clone(),
        })
    }

    /// `true` when the activity has the given type.
    pub fn has_type(&self, t: &str) -> bool {
        self.types.iter().any(|x| {
            x == t || type_matches(x, &format!("https://www.w3.org/ns/activitystreams#{t}"))
        })
    }
    /// `true` for `Create`.
    pub fn is_create(&self) -> bool {
        self.has_type(activity::CREATE)
    }
    /// `true` for `Update`.
    pub fn is_update(&self) -> bool {
        self.has_type(activity::UPDATE)
    }
    /// `true` for `Delete`.
    pub fn is_delete(&self) -> bool {
        self.has_type(activity::DELETE)
    }
}

/// A notification envelope (`type: "Notification"`).
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// The storage the notification is associated with.
    pub storage: String,
    /// The activities (always a list, even when the envelope carried a single object).
    pub activities: Vec<Activity>,
    /// The raw JSON document.
    pub raw: Value,
}

impl Notification {
    /// Parses a notification from JSON bytes.
    pub fn parse(body: &[u8]) -> Result<Self> {
        Self::from_json(serde_json::from_slice(body)?)
    }

    /// Builds a notification from JSON.
    pub fn from_json(raw: Value) -> Result<Self> {
        if !has_type(&string_list(raw.get("type")), "Notification") {
            return Err(Error::Protocol("document type is not Notification".into()));
        }
        let storage = raw
            .get("storage")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Protocol("notification without storage".into()))?
            .to_owned();
        let activities = match raw.get("activity") {
            Some(Value::Array(a)) => a.iter().map(Activity::from_json).collect::<Result<_>>()?,
            Some(v @ Value::Object(_)) => vec![Activity::from_json(v)?],
            _ => return Err(Error::Protocol("notification without activity".into())),
        };
        Ok(Self {
            storage,
            activities,
            raw,
        })
    }
}

/// Parses a notification envelope from JSON bytes.
pub fn parse_notification(body: &[u8]) -> Result<Notification> {
    Notification::parse(body)
}

/// A webhook subscription request (`type: "WebhookSubscription"`).
///
/// ```
/// use lws_client::WebhookSubscriptionRequest;
/// use url::Url;
/// let req = WebhookSubscriptionRequest::new(
///     [Url::parse("https://storage.example/alice/notes/").unwrap()],
///     Url::parse("https://receiver.example/hooks/lws").unwrap(),
/// );
/// assert_eq!(req.to_json()["type"], "WebhookSubscription");
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct WebhookSubscriptionRequest {
    /// Resources to subscribe to (containers are recursive).
    pub topics: Vec<Url>,
    /// Where notifications are delivered.
    pub inbox: Url,
    /// Requested expiry (RFC 3339 date-time).
    pub expires: Option<String>,
    /// Extra members to send.
    pub extra: Map<String, Value>,
}

impl WebhookSubscriptionRequest {
    /// A request for `topics` delivering to `inbox`.
    pub fn new(topics: impl IntoIterator<Item = Url>, inbox: Url) -> Self {
        Self {
            topics: topics.into_iter().collect(),
            inbox,
            expires: None,
            extra: Map::new(),
        }
    }
    /// Sets the expiry time.
    #[must_use]
    pub fn expires(mut self, at: SystemTime) -> Self {
        self.expires = Some(format_rfc3339(at));
        self
    }
    /// Sets the expiry as a raw date-time string.
    #[must_use]
    pub fn expires_raw(mut self, at: impl Into<String>) -> Self {
        self.expires = Some(at.into());
        self
    }
    /// The request body.
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "@context": [LWS_CONTEXT],
            "type": service::SUBSCRIPTION_WEBHOOK,
            "topic": self.topics.iter().map(Url::as_str).collect::<Vec<_>>(),
            "inbox": self.inbox.as_str(),
        });
        let o = v.as_object_mut().expect("object");
        if let Some(e) = &self.expires {
            o.insert("expires".into(), Value::String(e.clone()));
        }
        for (k, val) in &self.extra {
            o.insert(k.clone(), val.clone());
        }
        v
    }
}

/// A subscription as returned by the notification service.
#[derive(Debug, Clone, PartialEq)]
pub struct Subscription {
    /// Subscription type (e.g. `WebhookSubscription`).
    pub subscription_type: String,
    /// URL of the subscription resource (GET / DELETE).
    pub subscription: Url,
    /// Expiry, when parseable.
    pub expires: Option<SystemTime>,
    /// Raw `expires` value.
    pub expires_raw: Option<String>,
    /// The raw JSON document (`Null` when the response had no body).
    pub raw: Value,
}

impl Subscription {
    /// Builds a subscription from a response body and/or `Location`.
    pub fn from_json(
        raw: Value,
        base: &Url,
        location: Option<&Url>,
        default_type: &str,
    ) -> Result<Self> {
        let subscription = match raw.get("subscription").and_then(Value::as_str) {
            Some(s) => base
                .join(s)
                .map_err(|e| Error::Protocol(format!("invalid subscription URL: {e}")))?,
            None => location.cloned().ok_or_else(|| {
                Error::Protocol(
                    "subscription response has neither 'subscription' nor Location".into(),
                )
            })?,
        };
        let expires_raw = raw
            .get("expires")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(Self {
            subscription_type: raw
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or(default_type)
                .to_owned(),
            subscription,
            expires: expires_raw.as_deref().and_then(parse_rfc3339),
            expires_raw,
            raw,
        })
    }
}
