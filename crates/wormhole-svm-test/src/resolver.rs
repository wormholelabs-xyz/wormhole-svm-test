//! Test utilities for the executor-account-resolver protocol.
//!
//! Provides a generic helper that runs the iterative `resolve_execute_vaa_v1`
//! loop in LiteSVM, simulating the resolver instruction repeatedly until it
//! returns `Resolved`.
//!
//! # Example
//!
//! ```ignore
//! use wormhole_svm_test::resolve_execute_vaa_v1;
//!
//! let result = resolve_execute_vaa_v1(
//!     &svm,
//!     &my_program::ID,
//!     &payer,
//!     &vaa_body,
//!     &guardian_set_pubkey,
//!     10,
//! ).expect("resolution should succeed");
//!
//! assert_eq!(result.iterations, 2);
//! ```

use anchor_lang::AnchorDeserialize;
use executor_account_resolver_svm::{
    InstructionGroups, MissingAccounts, Resolver, RESOLVER_EXECUTE_VAA_V1,
};
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

// Re-export types consumers will need for inspecting resolved instructions.
pub use executor_account_resolver_svm::{
    InstructionGroup, SerializableAccountMeta, SerializableInstruction,
    RESOLVER_PUBKEY_GUARDIAN_SET, RESOLVER_PUBKEY_PAYER, RESOLVER_PUBKEY_SHIM_VAA_SIGS,
};

/// Result of running the resolver, including resolution metadata.
pub struct ResolverResult {
    /// The resolved instruction groups.
    pub instruction_groups: Vec<executor_account_resolver_svm::InstructionGroup>,
    /// How many iterations it took to resolve.
    pub iterations: usize,
}

/// Run the executor-account-resolver `resolve_execute_vaa_v1` loop.
///
/// Iteratively simulates the resolver instruction against `program_id` until
/// the program returns `Resolved(InstructionGroups)`, accumulating missing
/// accounts each round.
///
/// Well-known placeholder pubkeys are automatically substituted:
/// - `RESOLVER_PUBKEY_PAYER` → `payer.pubkey()`
/// - `RESOLVER_PUBKEY_GUARDIAN_SET` → `guardian_set`
/// - `RESOLVER_PUBKEY_SHIM_VAA_SIGS` → left as-is (substituted at execution time)
///
/// # Arguments
/// * `svm` - LiteSVM instance (must have the target program loaded)
/// * `program_id` - The program implementing `resolve_execute_vaa_v1`
/// * `payer` - Keypair for signing simulation transactions
/// * `vaa_body` - The VAA body bytes to resolve
/// * `guardian_set` - The actual guardian set pubkey to substitute for the placeholder
/// * `max_iterations` - Safety limit on resolution rounds
pub fn resolve_execute_vaa_v1(
    svm: &LiteSVM,
    program_id: &Pubkey,
    payer: &Keypair,
    vaa_body: &[u8],
    guardian_set: &Pubkey,
    max_iterations: usize,
) -> Result<ResolverResult, String> {
    let mut remaining_accounts: Vec<AccountMeta> = Vec::new();

    for iteration in 1..=max_iterations {
        // Build the resolver instruction data:
        // 8-byte discriminator + borsh Vec<u8> (4-byte LE length + bytes)
        let mut ix_data = Vec::with_capacity(8 + 4 + vaa_body.len());
        ix_data.extend_from_slice(&RESOLVER_EXECUTE_VAA_V1);
        ix_data.extend_from_slice(&(vaa_body.len() as u32).to_le_bytes());
        ix_data.extend_from_slice(vaa_body);

        let ix = Instruction {
            program_id: *program_id,
            accounts: remaining_accounts.clone(),
            data: ix_data,
        };

        let blockhash = svm.latest_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[payer],
            blockhash,
        );

        let sim_result = svm
            .simulate_transaction(tx)
            .map_err(|e| format!("Resolver simulation failed on iteration {}: {:?}", iteration, e))?;

        // Parse return data
        let return_data = &sim_result.meta.return_data;
        if return_data.data.is_empty() {
            return Err(format!(
                "No return data from resolver on iteration {}",
                iteration
            ));
        }

        let resolver: Resolver<InstructionGroups> =
            AnchorDeserialize::deserialize(&mut return_data.data.as_slice())
                .map_err(|e| format!("Failed to deserialize resolver return data: {}", e))?;

        match resolver {
            Resolver::Resolved(groups) => {
                return Ok(ResolverResult {
                    instruction_groups: groups.0,
                    iterations: iteration,
                });
            }
            Resolver::Missing(MissingAccounts {
                accounts: missing,
                address_lookup_tables: _,
            }) => {
                for pubkey in missing {
                    let actual = substitute_placeholder(pubkey, &payer.pubkey(), guardian_set);
                    remaining_accounts.push(AccountMeta::new_readonly(actual, false));
                }
            }
            Resolver::Account() => {
                return Err(
                    "Resolver returned Account() -- result account not supported in test helper"
                        .to_string(),
                );
            }
        }
    }

    Err(format!(
        "Resolver did not resolve after {} iterations",
        max_iterations
    ))
}

/// Substitute well-known placeholder pubkeys with actual values.
fn substitute_placeholder(pubkey: Pubkey, payer: &Pubkey, guardian_set: &Pubkey) -> Pubkey {
    if pubkey == RESOLVER_PUBKEY_PAYER {
        *payer
    } else if pubkey == RESOLVER_PUBKEY_GUARDIAN_SET {
        *guardian_set
    } else {
        // RESOLVER_PUBKEY_SHIM_VAA_SIGS and others are left as-is;
        // they are substituted at execution time, not resolve time.
        pubkey
    }
}
