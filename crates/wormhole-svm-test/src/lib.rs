//! Testing utilities for Wormhole SVM integrations.
//!
//! Provides guardian signing, VAA construction, and optional LiteSVM helpers.
//!
//! # Example
//!
//! ```rust
//! use wormhole_svm_test::{TestGuardian, TestGuardianSet, TestVaa};
//!
//! // Create guardians
//! let guardians = TestGuardianSet::single(TestGuardian::default());
//!
//! // Build and sign a VAA
//! let vaa = TestVaa::new(
//!     1,                    // emitter chain (Solana)
//!     [0xAB; 32],           // emitter address
//!     42,                   // sequence
//!     vec![1, 2, 3, 4],     // payload
//! );
//! let signed_vaa = vaa.sign(&guardians);
//! ```

mod guardian;
mod vaa;

pub use guardian::*;
pub use vaa::*;

#[cfg(feature = "litesvm")]
mod litesvm;

#[cfg(feature = "litesvm")]
pub use crate::litesvm::*;

#[cfg(feature = "resolver")]
mod resolver;

#[cfg(feature = "resolver")]
pub use resolver::*;
