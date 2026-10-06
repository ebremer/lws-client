// SPDX-License-Identifier: MIT
//! Access requests and access grants (ODRL-based LWS access profile).

use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::constants::{LWS_CONTEXT, access as c, types as lws_types};
use crate::datetime::format_rfc3339;
use crate::error::{Error, Result};
use crate::types::{has_type, one_or_many};

fn lws_context() -> Value {
    json!([LWS_CONTEXT])
}

/// An ODRL constraint (`leftOperand` / `operator` / `rightOperand`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Constraint {
    /// The constrained operand (`purpose`, `client`, `format`, `type`, `dateTime`, …).
    #[serde(rename = "leftOperand")]
    pub left_operand: String,
    /// The operator (`eq`, `isAnyOf`, `gteq`, `lteq`, …).
    pub operator: String,
    /// The comparison value (string, array, …).
    #[serde(rename = "rightOperand")]
    pub right_operand: Value,
}

impl Constraint {
    /// A constraint from its parts.
    pub fn new(
        left_operand: impl Into<String>,
        operator: impl Into<String>,
        right_operand: impl Into<Value>,
    ) -> Self {
        Self {
            left_operand: left_operand.into(),
            operator: operator.into(),
            right_operand: right_operand.into(),
        }
    }
    fn any_of<I: IntoIterator<Item = S>, S: Into<String>>(operand: &str, values: I) -> Self {
        let v: Vec<Value> = values
            .into_iter()
            .map(|s| Value::String(s.into()))
            .collect();
        Self::new(operand, c::OPERATOR_IS_ANY_OF, Value::Array(v))
    }
    /// `purpose eq <uri>`.
    pub fn purpose(uri: impl Into<String>) -> Self {
        Self::new(c::OPERAND_PURPOSE, c::OPERATOR_EQ, uri.into())
    }
    /// `purpose isAnyOf [<uri>…]`.
    pub fn purpose_any_of<I: IntoIterator<Item = S>, S: Into<String>>(uris: I) -> Self {
        Self::any_of(c::OPERAND_PURPOSE, uris)
    }
    /// `client eq <client id>`.
    pub fn client(client_id: impl Into<String>) -> Self {
        Self::new(c::OPERAND_CLIENT, c::OPERATOR_EQ, client_id.into())
    }
    /// `format eq <media type>`.
    pub fn format(media_type: impl Into<String>) -> Self {
        Self::new(c::OPERAND_FORMAT, c::OPERATOR_EQ, media_type.into())
    }
    /// `format isAnyOf [<media type>…]`.
    pub fn format_any_of<I: IntoIterator<Item = S>, S: Into<String>>(media_types: I) -> Self {
        Self::any_of(c::OPERAND_FORMAT, media_types)
    }
    /// `type eq <type uri>`.
    pub fn resource_type(type_uri: impl Into<String>) -> Self {
        Self::new(c::OPERAND_TYPE, c::OPERATOR_EQ, type_uri.into())
    }
    /// `type isAnyOf [<type uri>…]`.
    pub fn resource_type_any_of<I: IntoIterator<Item = S>, S: Into<String>>(type_uris: I) -> Self {
        Self::any_of(c::OPERAND_TYPE, type_uris)
    }
    /// `dateTime gteq <xsd:dateTime>` (start of the access window).
    pub fn not_before(date_time: impl Into<String>) -> Self {
        Self::new(c::OPERAND_DATE_TIME, c::OPERATOR_GTEQ, date_time.into())
    }
    /// `dateTime lteq <xsd:dateTime>` (end of the access window).
    pub fn not_after(date_time: impl Into<String>) -> Self {
        Self::new(c::OPERAND_DATE_TIME, c::OPERATOR_LTEQ, date_time.into())
    }
    /// [`not_before`](Self::not_before) from a [`SystemTime`].
    pub fn not_before_time(t: SystemTime) -> Self {
        Self::not_before(format_rfc3339(t))
    }
    /// [`not_after`](Self::not_after) from a [`SystemTime`].
    pub fn not_after_time(t: SystemTime) -> Self {
        Self::not_after(format_rfc3339(t))
    }
}

/// The resources an access policy applies to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessTarget {
    /// Target matcher type (`StorageResource`, `DataResource`, `Container`, or an IRI).
    #[serde(rename = "type")]
    pub target_type: String,
    /// Resource identifiers.
    #[serde(rename = "value", deserialize_with = "one_or_many")]
    pub values: Vec<String>,
}

/// An access policy (one element of `access`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Types (includes `AccessPolicy`).
    #[serde(rename = "type", deserialize_with = "one_or_many", default)]
    pub types: Vec<String>,
    /// Actions (`read`, `modify`, `create`, `delete`).
    #[serde(rename = "action", deserialize_with = "one_or_many", default)]
    pub actions: Vec<String>,
    /// The agent requesting / being granted access.
    pub assignee: String,
    /// Target resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<AccessTarget>,
    /// Constraints (all must be satisfied).
    #[serde(rename = "constraint", default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
    /// Extension members.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl AccessPolicy {
    /// Starts a policy for `assignee`.
    pub fn builder(assignee: impl Into<String>) -> AccessPolicyBuilder {
        AccessPolicyBuilder {
            policy: AccessPolicy {
                types: vec![c::TYPE_ACCESS_POLICY.to_owned()],
                actions: Vec::new(),
                assignee: assignee.into(),
                target: None,
                constraints: Vec::new(),
                extra: Map::new(),
            },
        }
    }
}

/// Builder for [`AccessPolicy`].
#[derive(Debug, Clone)]
pub struct AccessPolicyBuilder {
    policy: AccessPolicy,
}

impl AccessPolicyBuilder {
    /// Adds an action.
    #[must_use]
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.policy.actions.push(action.into());
        self
    }
    /// Adds actions.
    #[must_use]
    pub fn actions<I: IntoIterator<Item = S>, S: Into<String>>(mut self, actions: I) -> Self {
        self.policy
            .actions
            .extend(actions.into_iter().map(Into::into));
        self
    }
    /// Sets the target matcher.
    #[must_use]
    pub fn target<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        target_type: impl Into<String>,
        values: I,
    ) -> Self {
        self.policy.target = Some(AccessTarget {
            target_type: target_type.into(),
            values: values.into_iter().map(Into::into).collect(),
        });
        self
    }
    /// Targets any storage resource with the given identifiers (`StorageResource`).
    #[must_use]
    pub fn target_resources<I: IntoIterator<Item = S>, S: Into<String>>(self, values: I) -> Self {
        self.target("StorageResource", values)
    }
    /// Adds a constraint.
    #[must_use]
    pub fn constraint(mut self, constraint: Constraint) -> Self {
        self.policy.constraints.push(constraint);
        self
    }
    /// Validates and builds the policy (at least one action and a non-empty assignee).
    pub fn build(self) -> Result<AccessPolicy> {
        if self.policy.actions.is_empty() {
            return Err(Error::InvalidInput(
                "access policy needs at least one action".into(),
            ));
        }
        if self.policy.assignee.is_empty() {
            return Err(Error::InvalidInput(
                "access policy needs an assignee".into(),
            ));
        }
        Ok(self.policy)
    }
}

macro_rules! access_document {
    ($(#[$doc:meta])* $name:ident, $builder:ident, $type_term:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $name {
            /// JSON-LD context.
            #[serde(rename = "@context", default = "lws_context")]
            pub context: Value,
            /// Types.
            #[serde(rename = "type", deserialize_with = "one_or_many", default)]
            pub types: Vec<String>,
            /// Notification inbox for this document.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub inbox: Option<String>,
            /// The storage the document is scoped to.
            pub storage: String,
            /// Access policies.
            pub access: Vec<AccessPolicy>,
            /// Extension members.
            #[serde(flatten)]
            pub extra: Map<String, Value>,
        }

        impl $name {
            /// Starts building a document for `storage`.
            pub fn builder(storage: impl Into<String>) -> $builder {
                $builder {
                    doc: $name {
                        context: lws_context(),
                        types: vec![$type_term.to_owned()],
                        inbox: None,
                        storage: storage.into(),
                        access: Vec::new(),
                        extra: Map::new(),
                    },
                }
            }
            /// Parses and validates a document.
            pub fn from_json(value: Value) -> Result<Self> {
                let doc: Self = serde_json::from_value(value)?;
                if !has_type(&doc.types, $type_term) {
                    return Err(Error::Protocol(format!("document type does not include {}", $type_term)));
                }
                Ok(doc)
            }
            /// The JSON form.
            pub fn to_json(&self) -> Value {
                serde_json::to_value(self).unwrap_or(Value::Null)
            }
        }

        #[doc = concat!("Builder for [`", stringify!($name), "`].")]
        #[derive(Debug, Clone)]
        pub struct $builder {
            doc: $name,
        }

        impl $builder {
            /// Sets the notification inbox.
            #[must_use]
            pub fn inbox(mut self, inbox: impl Into<String>) -> Self {
                self.doc.inbox = Some(inbox.into());
                self
            }
            /// Adds an access policy.
            #[must_use]
            pub fn policy(mut self, policy: AccessPolicy) -> Self {
                self.doc.access.push(policy);
                self
            }
            /// Validates and builds the document (storage and at least one policy).
            pub fn build(self) -> Result<$name> {
                if self.doc.storage.is_empty() {
                    return Err(Error::InvalidInput("storage is required".into()));
                }
                if self.doc.access.is_empty() {
                    return Err(Error::InvalidInput("at least one access policy is required".into()));
                }
                Ok(self.doc)
            }
        }
    };
}

access_document!(
    /// A request by an agent for access to resources.
    AccessRequest,
    AccessRequestBuilder,
    c::TYPE_ACCESS_REQUEST
);
access_document!(
    /// An authorization by a storage controller granting access to resources.
    AccessGrant,
    AccessGrantBuilder,
    c::TYPE_ACCESS_GRANT
);

/// Target matcher type for any storage resource (`lws:StorageResource`).
pub const TARGET_STORAGE_RESOURCE: &str = lws_types::STORAGE_RESOURCE;
