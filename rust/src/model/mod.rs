// SPDX-License-Identifier: MIT
//! Resource, container, storage-description and linkset models.

mod container;
mod linkset;
mod resource;
mod storage;

pub(crate) use container::parse_items;
pub use container::{ContainedResource, ContainerPage, Pagination};
pub use linkset::{LinkContext, LinkTarget, Linkset, LinksetDocument, LinksetLink, MoveResult};
pub use resource::{CreateResult, Resource, ResourceMetadata, StreamingResource, UpdateResult};
pub use storage::{
    Capability, MoveCapability, Service, StorageDescription, VerificationMethod,
    VerificationRelationship,
};
