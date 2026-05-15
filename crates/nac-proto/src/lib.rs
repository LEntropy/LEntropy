//! nac-proto: protobuf/gRPC generated code wrappers.
//!
//! Re-exports generated modules from tonic/prost build output.

/// Policy service protobuf types.
pub mod policy {
    tonic::include_proto!("nac.policy");
}

/// Enforcement service protobuf types.
pub mod enforcement {
    tonic::include_proto!("nac.enforcement");
}

/// Agent gateway protobuf types.
pub mod agent {
    tonic::include_proto!("nac.agent");
}

/// Internal event bus message types.
pub mod events {
    tonic::include_proto!("nac.events");
}
