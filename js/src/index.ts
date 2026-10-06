// SPDX-License-Identifier: MIT
/**
 * lws-client — a W3C Linked Web Storage (LWS) client for JavaScript and TypeScript.
 *
 * Targets the LWS 1.0 specifications as of 2026-10-05 (core protocol, OpenID
 * Connect / SAML 2.0 / self-signed authentication suites, webhook
 * notifications, type index and type search).
 *
 * @packageDocumentation
 */

export * from "./constants.js";
export * from "./errors.js";
export { LwsClient } from "./client.js";
export type {
  LwsClientOptions,
  RequestOptions,
  ReadOptions,
  RangeSpec,
  CreateOptions,
  UpdateOptions,
  ConditionalOptions,
  DeleteOptions,
  RawPatch,
  CreateResult,
  UpdateResult,
  ServiceRef,
} from "./client.js";

// HTTP primitives
export { Link, parseLinkHeader, formatLink, findLink, normalizeRel, type LinkInit } from "./http/link.js";
export { AuthChallenge, parseWwwAuthenticate } from "./http/www-authenticate.js";
export {
  parseDictionary,
  parseItem,
  serializeBareItem,
  serializeParams,
  serializeMember,
  serializeDictionary,
  StructuredFieldError,
  type BareItem,
  type Parameters,
  type SfItem,
  type SfInnerList,
  type SfMember,
  type SfDictionary,
} from "./http/structured-fields.js";
export { parseProblemDetails, toProblemDetails, type ProblemDetails } from "./http/problem.js";
export { JsonPatch, JsonPointer, type JsonPatchOperation } from "./json-patch.js";

// Models
export { ResourceMetadata, Resource } from "./models/resource.js";
export {
  StorageDescription,
  Service,
  Capability,
  type VerificationMethod,
} from "./models/storage.js";
export { ContainerPage, ContainedResource, type PageLinks, type SearchPage } from "./models/container.js";
export {
  Linkset,
  type LinkContext,
  type LinkTarget,
  type LinksetLink,
  type LinksetDocument,
} from "./models/linkset.js";
export {
  Notification,
  Activity,
  Subscription,
  parseNotification,
  type ActivityObject,
  type WebhookSubscriptionRequest,
} from "./models/notification.js";
export {
  AccessRequest,
  AccessGrant,
  Constraints,
  type AccessPolicy,
  type AccessTarget,
  type Constraint,
  type AccessDocumentInit,
} from "./models/access.js";
export { TypeIndexPage, TypeQuery, RelationFilter } from "./models/type-index.js";

// Authentication & authorization
export {
  BearerTokenAuthenticator,
  type Authenticator,
  type AuthRequest,
  type AuthContext,
  type BearerTokenOptions,
} from "./auth/authenticator.js";
export { TokenExchangeAuthenticator, type TokenExchangeOptions } from "./auth/token-exchange.js";
export {
  OpenIdCredentials,
  SamlCredentials,
  SelfSignedCredentials,
  type CredentialProvider,
  type CredentialContext,
  type SelfSignedOptions,
} from "./auth/credentials.js";
export {
  isWithinRealm,
  metadataUrl,
  fetchAuthorizationServerMetadata,
  exchangeToken,
  tokenExpiry,
  type AuthorizationServerMetadata,
  type TokenResponse,
  type TokenExchangeRequest,
} from "./auth/oauth.js";

// Keys, did:key, JWT
export {
  generateKeyPair,
  importKeyPair,
  importPublicJwk,
  exportPrivateJwk,
  publicJwkOf,
  algorithmOfJwk,
  didKeyFromJwk,
  didKeyFromPublicKey,
  jwkFromDidKey,
  controlledIdentifierDocument,
  base58btcEncode,
  base58btcDecode,
  type SigningAlgorithm,
  type SigningKeyPair,
  type DidKey,
} from "./crypto/keys.js";
export { signJwt, decodeJwt, verifyJwt, type DecodedJwt } from "./crypto/jwt.js";

// Webhooks
export {
  WebhookVerifier,
  verifyContentDigest,
  contentDigest,
  signatureBase,
  type WebhookRequestLike,
  type WebhookVerifierOptions,
  type VerifyOptions,
  type VerifiedNotification,
  type StorageDescriptionResolver,
} from "./notifications/webhook.js";

// Utilities
export { hasType, typeEquals, expandLwsTerm, isAbsoluteIri } from "./util/types.js";
