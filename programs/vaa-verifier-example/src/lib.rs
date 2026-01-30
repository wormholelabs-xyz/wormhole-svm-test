//! Minimal example program demonstrating VAA verification.
//!
//! This program shows the complete flow of verifying a Wormhole VAA:
//!
//! 1. Parse the VAA from instruction data
//! 2. Compute the VAA body digest
//! 3. CPI to the Wormhole Verify VAA Shim to verify guardian signatures
//! 4. Process the verified payload
//!
//! ## Account Layout
//!
//! The instruction expects:
//! 0. `[signer]` Payer (for logging, not used for payment)
//! 1. `[]` Guardian set account (Wormhole Core Bridge PDA)
//! 2. `[]` Guardian signatures account (from post_signatures)
//! 3. `[]` Wormhole Verify VAA Shim program
//!
//! ## Instruction Data
//!
//! - `guardian_set_bump: u8` (1 byte)
//! - `vaa_bytes: Vec<u8>` (4-byte length prefix + VAA data)

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    keccak, msg,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;
use wormhole_raw_vaas::Vaa;
use wormhole_svm_definitions::solana::mainnet::VERIFY_VAA_SHIM_PROGRAM_ID;

// Declare program ID - this is a placeholder, actual ID is set at deploy time
solana_program::declare_id!("VAAVerifier11111111111111111111111111111111");

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

/// Process the verify_vaa instruction.
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("VAA Verifier: Processing instruction");

    // Parse accounts
    let account_iter = &mut accounts.iter();
    let _payer = next_account_info(account_iter)?;
    let guardian_set = next_account_info(account_iter)?;
    let guardian_signatures = next_account_info(account_iter)?;
    let shim_program = next_account_info(account_iter)?;

    // Verify the shim program ID
    if shim_program.key != &VERIFY_VAA_SHIM_PROGRAM_ID {
        msg!("Error: Invalid shim program ID");
        return Err(ProgramError::IncorrectProgramId);
    }

    // Parse instruction data
    if instruction_data.is_empty() {
        msg!("Error: Empty instruction data");
        return Err(ProgramError::InvalidInstructionData);
    }

    let guardian_set_bump = instruction_data[0];
    let vaa_len = u32::from_le_bytes(
        instruction_data[1..5]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    ) as usize;

    if instruction_data.len() < 5 + vaa_len {
        msg!("Error: Instruction data too short for VAA");
        return Err(ProgramError::InvalidInstructionData);
    }

    let vaa_bytes = &instruction_data[5..5 + vaa_len];

    // Parse the VAA
    let vaa = Vaa::parse(vaa_bytes).map_err(|_| {
        msg!("Error: Failed to parse VAA");
        ProgramError::InvalidInstructionData
    })?;

    // Compute the VAA digest (double keccak256)
    let body = vaa.body();

    msg!(
        "VAA: chain={}, sequence={}",
        body.emitter_chain(),
        body.sequence()
    );
    let body_bytes = body.as_ref();
    let message_hash = keccak::hashv(&[body_bytes]);
    let digest = keccak::hash(&message_hash.to_bytes());

    msg!("VAA digest: {:?}", &digest.to_bytes()[..8]);

    // Build the verify_hash CPI instruction using wormhole_svm_shim types
    use wormhole_svm_shim::verify_vaa::{VerifyHash, VerifyHashAccounts, VerifyHashData};

    let verify_ix = VerifyHash {
        program_id: &VERIFY_VAA_SHIM_PROGRAM_ID,
        accounts: VerifyHashAccounts {
            guardian_set: guardian_set.key,
            guardian_signatures: guardian_signatures.key,
        },
        data: VerifyHashData::new(guardian_set_bump, digest.into()),
    }
    .instruction();

    // Execute CPI to verify the VAA
    invoke(
        &verify_ix,
        &[guardian_set.clone(), guardian_signatures.clone()],
    )?;

    msg!("VAA verified successfully!");

    // Extract and log payload info
    let payload = body.payload();
    let payload_bytes = payload.as_ref();
    msg!("Payload length: {} bytes", payload_bytes.len());

    if payload_bytes.len() >= 4 {
        msg!(
            "Payload prefix: {:02x}{:02x}{:02x}{:02x}",
            payload_bytes[0],
            payload_bytes[1],
            payload_bytes[2],
            payload_bytes[3]
        );
    }

    msg!("VAA Verifier: Success");
    Ok(())
}

/// Build instruction data for the verify_vaa instruction.
pub fn build_instruction_data(guardian_set_bump: u8, vaa_bytes: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(5 + vaa_bytes.len());
    data.push(guardian_set_bump);
    data.extend_from_slice(&(vaa_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(vaa_bytes);
    data
}

/// Build a verify_vaa instruction.
pub fn build_verify_vaa_instruction(
    payer: &Pubkey,
    guardian_set: &Pubkey,
    guardian_signatures: &Pubkey,
    guardian_set_bump: u8,
    vaa_bytes: &[u8],
) -> solana_program::instruction::Instruction {
    let data = build_instruction_data(guardian_set_bump, vaa_bytes);

    solana_program::instruction::Instruction {
        program_id: crate::ID,
        accounts: vec![
            solana_program::instruction::AccountMeta::new_readonly(*payer, true),
            solana_program::instruction::AccountMeta::new_readonly(*guardian_set, false),
            solana_program::instruction::AccountMeta::new_readonly(*guardian_signatures, false),
            solana_program::instruction::AccountMeta::new_readonly(
                VERIFY_VAA_SHIM_PROGRAM_ID,
                false,
            ),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_data_roundtrip() {
        let bump = 255;
        let vaa = vec![1, 2, 3, 4, 5];

        let data = build_instruction_data(bump, &vaa);

        assert_eq!(data[0], bump);
        let len = u32::from_le_bytes(data[1..5].try_into().unwrap());
        assert_eq!(len, 5);
        assert_eq!(&data[5..], &vaa);
    }
}
