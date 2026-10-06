// SPDX-License-Identifier: MIT
//! Storage description resources (`application/lws+cid`).

use serde_json::{Map, Value};
use url::Url;

use crate::constants::{service, types as lws_types};
use crate::error::{Error, Result};
use crate::types::{has_type, string_list, type_matches};

/// A service advertised in a storage description.
#[derive(Debug, Clone, PartialEq)]
pub struct Service {
    /// Optional service identifier.
    pub id: Option<String>,
    /// Raw type values.
    pub types: Vec<String>,
    /// Absolute service endpoint.
    pub service_endpoint: Url,
    /// The raw service object (extra properties such as `subscriptionType` or `conformsTo`).
    pub raw: Map<String, Value>,
}

impl Service {
    /// `true` when the service has the given type.
    pub fn has_type(&self, wanted: &str) -> bool {
        has_type(&self.types, wanted)
    }
    /// An extension property.
    pub fn property(&self, name: &str) -> Option<&Value> {
        self.raw.get(name)
    }
    /// `subscriptionType` values (notification services).
    pub fn subscription_types(&self) -> Vec<String> {
        string_list(self.raw.get("subscriptionType"))
    }
    /// `true` when `subscriptionType` lists the given subscription type.
    pub fn supports_subscription_type(&self, subscription_type: &str) -> bool {
        self.subscription_types()
            .iter()
            .any(|t| type_matches(t, subscription_type))
    }
    /// `conformsTo` values (access request/grant services).
    pub fn conforms_to(&self) -> Vec<String> {
        string_list(self.raw.get("conformsTo"))
    }
}

/// A capability advertised in a storage description.
#[derive(Debug, Clone, PartialEq)]
pub struct Capability {
    /// Optional identifier.
    pub id: Option<String>,
    /// Raw type values.
    pub types: Vec<String>,
    /// The raw capability object.
    pub raw: Map<String, Value>,
}

impl Capability {
    /// `true` when the capability has the given type.
    pub fn has_type(&self, wanted: &str) -> bool {
        has_type(&self.types, wanted)
    }
    /// An extension property.
    pub fn property(&self, name: &str) -> Option<&Value> {
        self.raw.get(name)
    }
}

/// A verification method (public key) from a controlled identifier document.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationMethod {
    /// Identifier (absolute or fragment form such as `#key-1`).
    pub id: String,
    /// Type, e.g. `JsonWebKey`.
    pub method_type: Option<String>,
    /// Controller.
    pub controller: Option<String>,
    /// The public key as a JWK object.
    pub public_key_jwk: Option<Map<String, Value>>,
    /// The raw object.
    pub raw: Value,
}

impl VerificationMethod {
    fn from_json(v: &Value) -> Option<Self> {
        let id = v.get("id")?.as_str()?.to_owned();
        Some(Self {
            id,
            method_type: v.get("type").and_then(Value::as_str).map(str::to_owned),
            controller: v
                .get("controller")
                .and_then(Value::as_str)
                .map(str::to_owned),
            public_key_jwk: v.get("publicKeyJwk").and_then(Value::as_object).cloned(),
            raw: v.clone(),
        })
    }
}

/// An entry of a verification relationship such as `authentication`.
#[derive(Debug, Clone, PartialEq)]
pub enum VerificationRelationship {
    /// A reference to a verification method by id.
    Reference(String),
    /// An embedded verification method.
    Embedded(VerificationMethod),
}

impl VerificationRelationship {
    /// The referenced or embedded method id.
    pub fn id(&self) -> &str {
        match self {
            Self::Reference(s) => s,
            Self::Embedded(m) => &m.id,
        }
    }
}

/// A storage description: a W3C Controlled Identifier document describing a storage, its
/// services and capabilities.
#[derive(Debug, Clone, PartialEq)]
pub struct StorageDescription {
    /// Canonical storage URI.
    pub id: Url,
    /// Raw type values (include `Storage`).
    pub types: Vec<String>,
    /// Services.
    pub services: Vec<Service>,
    /// Capabilities.
    pub capabilities: Vec<Capability>,
    /// Verification methods (keys, e.g. for webhook signatures).
    pub verification_methods: Vec<VerificationMethod>,
    /// The `authentication` verification relationship.
    pub authentication: Vec<VerificationRelationship>,
    /// The raw JSON document.
    pub raw: Value,
}

impl StorageDescription {
    /// Parses a storage description fetched from `url`.
    pub fn parse(url: &Url, body: &[u8]) -> Result<Self> {
        let raw: Value = serde_json::from_slice(body)?;
        Self::from_json(url, raw)
    }

    /// Builds a storage description from JSON; relative URLs resolve against `base`.
    pub fn from_json(base: &Url, raw: Value) -> Result<Self> {
        if !raw.is_object() {
            return Err(Error::Protocol(
                "storage description is not a JSON object".into(),
            ));
        }
        let types = string_list(raw.get("type"));
        if !has_type(&types, lws_types::STORAGE) {
            return Err(Error::Protocol(
                "document type does not include Storage".into(),
            ));
        }
        let id_str = raw
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Protocol("storage description has no id".into()))?;
        let id = base
            .join(id_str)
            .map_err(|e| Error::Protocol(format!("invalid storage id: {e}")))?;
        let objects = |key: &str| -> Vec<Map<String, Value>> {
            match raw.get(key) {
                Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_object().cloned()).collect(),
                Some(Value::Object(o)) => vec![o.clone()],
                _ => Vec::new(),
            }
        };
        let services = objects("service")
            .into_iter()
            .filter_map(|o| {
                let endpoint = o.get("serviceEndpoint")?.as_str()?;
                Some(Service {
                    id: o.get("id").and_then(Value::as_str).map(str::to_owned),
                    types: string_list(o.get("type")),
                    service_endpoint: base.join(endpoint).ok()?,
                    raw: o,
                })
            })
            .collect();
        let capabilities = objects("capability")
            .into_iter()
            .map(|o| Capability {
                id: o.get("id").and_then(Value::as_str).map(str::to_owned),
                types: string_list(o.get("type")),
                raw: o,
            })
            .collect();
        let verification_methods = match raw.get("verificationMethod") {
            Some(Value::Array(a)) => a.iter().filter_map(VerificationMethod::from_json).collect(),
            _ => Vec::new(),
        };
        let authentication = match raw.get("authentication") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(VerificationRelationship::Reference(s.clone())),
                    Value::Object(_) => {
                        VerificationMethod::from_json(v).map(VerificationRelationship::Embedded)
                    }
                    _ => None,
                })
                .collect(),
            Some(Value::String(s)) => vec![VerificationRelationship::Reference(s.clone())],
            _ => Vec::new(),
        };
        Ok(Self {
            id,
            types,
            services,
            capabilities,
            verification_methods,
            authentication,
            raw,
        })
    }

    /// The storage root container (the required `StorageRoot` service).
    pub fn storage_root(&self) -> Result<&Url> {
        self.service(service::STORAGE_ROOT)
            .map(|s| &s.service_endpoint)
            .ok_or_else(|| Error::Protocol("storage description has no StorageRoot service".into()))
    }

    /// The first service of the given type.
    pub fn service(&self, service_type: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.has_type(service_type))
    }

    /// All services of the given type.
    pub fn services_of<'a>(
        &'a self,
        service_type: &'a str,
    ) -> impl Iterator<Item = &'a Service> + 'a {
        self.services
            .iter()
            .filter(move |s| s.has_type(service_type))
    }

    /// The first capability of the given type.
    pub fn capability(&self, capability_type: &str) -> Option<&Capability> {
        self.capabilities
            .iter()
            .find(|c| c.has_type(capability_type))
    }

    /// The `NotificationService`.
    pub fn notification_service(&self) -> Option<&Service> {
        self.service(service::NOTIFICATION)
    }
    /// The `AccessRequestService`.
    pub fn access_request_service(&self) -> Option<&Service> {
        self.service(service::ACCESS_REQUEST)
    }
    /// The `AccessGrantService`.
    pub fn access_grant_service(&self) -> Option<&Service> {
        self.service(service::ACCESS_GRANT)
    }
    /// The `TypeIndexService`.
    pub fn type_index_service(&self) -> Option<&Service> {
        self.service(service::TYPE_INDEX)
    }
    /// The `TypeSearchService`.
    pub fn type_search_service(&self) -> Option<&Service> {
        self.service(service::TYPE_SEARCH)
    }

    /// Resolves a verification-method reference (absolute id, `#fragment` or bare fragment)
    /// against the storage id.
    fn resolve_ref(&self, reference: &str) -> Option<Url> {
        let r = if reference.contains(':') || reference.starts_with('#') {
            reference.to_owned()
        } else {
            format!("#{reference}")
        };
        self.id.join(&r).ok()
    }

    /// Finds a verification method by full id, `#fragment` or bare fragment.
    pub fn verification_method(&self, id_or_fragment: &str) -> Option<&VerificationMethod> {
        let wanted = self.resolve_ref(id_or_fragment)?;
        self.verification_methods
            .iter()
            .chain(self.authentication.iter().filter_map(|r| match r {
                VerificationRelationship::Embedded(m) => Some(m),
                VerificationRelationship::Reference(_) => None,
            }))
            .find(|m| self.resolve_ref(&m.id).as_ref() == Some(&wanted))
    }

    /// `true` when the verification method is referenced from (or embedded in) `authentication`.
    pub fn is_authentication_method(&self, method: &VerificationMethod) -> bool {
        let Some(wanted) = self.resolve_ref(&method.id) else {
            return false;
        };
        self.authentication
            .iter()
            .any(|r| self.resolve_ref(r.id()).as_ref() == Some(&wanted))
    }
}
