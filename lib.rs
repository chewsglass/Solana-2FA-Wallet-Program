use hmac::{Hmac, Mac};
use sha1::Sha1;
use solana_program::{
    ed25519_program,
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::Instruction,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
    sysvar::{clock::Clock, instructions::load_instruction_at_checked, rent::Rent, Sysvar},
};
use std::convert::TryInto;

entrypoint!(process_instruction);
const TIME_STEP: u64 = 30;
const ED25519_IX_INDEX: u8 = 0;
fn validate_ed25519_instruction(ix: &Instruction) -> bool {
    if ix.program_id != ed25519_program::ID {
        msg!("Wrong program ID for Ed25519 instruction");
        return false;
    }
    let message_bytes = &ix.data[ix.data.len() - 8..];
    msg!("Message bytes: {:?}", message_bytes);
    msg!("Raw signature bytes: {:?}", &ix.data[48..112]);
    msg!("Signature hex: {:02x?}", &ix.data[48..112]);
    match std::str::from_utf8(message_bytes) {
        Ok(msg_str) => {
            msg!("Decoded message: {}", msg_str);
            if msg_str == "2FA_AUTH" {
                return true;
            }
            msg!("Message mismatch: expected '2FA_AUTH', got '{}'", msg_str);
        }
        Err(e) => {
            msg!("Failed to decode message as UTF-8: {}", e);
            for (i, &byte) in message_bytes.iter().enumerate() {
                msg!("Byte {}: {} ({})", i, byte, byte as char);
            }
        }
    }
    false
}

fn generate_totp(secret: &[u8; 32], counter: u64) -> u64 {
    msg!("Generating TOTP with counter: {}", counter);
    msg!("Secret key before HMAC: {:?}", secret);
    msg!("Secret key hex before HMAC: {:02x?}", secret);
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
    let counter_bytes = counter.to_be_bytes();
    msg!("Counter bytes: {:?}", counter_bytes);
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();
    msg!("HMAC result: {:?}", result);
    let offset = (result[19] & 0xf) as usize;
    let code = ((result[offset] & 0x7f) as u64) << 24
        | ((result[offset + 1] & 0xff) as u64) << 16
        | ((result[offset + 2] & 0xff) as u64) << 8
        | ((result[offset + 3] & 0xff) as u64);
    let totp = code % 1_000_000;
    msg!("Generated TOTP: {}", totp);
    totp
}

fn decrypt_key(encrypted_key: &[u8; 32], nonce: u64, signature: &[u8; 64]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = encrypted_key[i] ^ signature[i] ^ ((nonce >> (i % 8)) & 0xFF) as u8;
    }
    result
}

fn encrypt_key(key: &[u8; 32], nonce: u64, signature: &[u8; 64]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = key[i] ^ signature[i] ^ ((nonce >> (i % 8)) as u8);
    }
    result
}

fn transfer_service_fee_lamports(
    from_account: &AccountInfo,
    to_account: &AccountInfo,
    amount_of_lamports: u64,
) -> ProgramResult {
    if **from_account.try_borrow_lamports()? < amount_of_lamports {
        return Err(ProgramError::InsufficientFunds);
    }
    **from_account.try_borrow_mut_lamports()? -= amount_of_lamports;
    **to_account.try_borrow_mut_lamports()? += amount_of_lamports;
    Ok(())
}


#[derive(Debug)]
enum TwoFactorInstruction {
    Initialize { encrypted_key: [u8; 32] },
    ProcessTransaction { totp: u64, amount: u64 },
}

impl TwoFactorInstruction {
    fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        let (&tag, rest) = input
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        msg!("Instruction tag: {}", tag);
        msg!("Remaining data length: {}", rest.len());
        Ok(match tag {
            0 => {
                if rest.len() != 32 {
                    msg!("Initialize: Expected 32 bytes, got {}", rest.len());
                    return Err(ProgramError::InvalidInstructionData);
                }
                let encrypted_key: [u8; 32] = rest[..32]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?;
                Self::Initialize { encrypted_key }
            }
            1 => {
                if rest.len() != 16 {
                    msg!(
                        "ProcessTransaction: Expected 16 bytes (8 for TOTP + 8 for amount), got {}",
                        rest.len()
                    );
                    return Err(ProgramError::InvalidInstructionData);
                }
                let totp = u64::from_le_bytes(
                    rest[..8]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                let amount = u64::from_le_bytes(
                    rest[8..16]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                msg!("TOTP received: {}", totp);
                msg!("Amount received: {}", amount);
                Self::ProcessTransaction { totp, amount }
            }
            _ => {
                msg!("Invalid instruction tag: {}", tag);
                return Err(ProgramError::InvalidInstructionData);
            }
        })
    }
}

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let instruction = TwoFactorInstruction::unpack(instruction_data)?;
    match instruction {
        TwoFactorInstruction::Initialize { encrypted_key } => {
            let owner = next_account_info(accounts_iter)?;
            let auth_account = next_account_info(accounts_iter)?;
            let wallet_account = next_account_info(accounts_iter)?;
            let system_program = next_account_info(accounts_iter)?;
            if !owner.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let (auth_pda, auth_bump) =
                Pubkey::find_program_address(&[b"auth", owner.key.as_ref()], program_id);
            let (wallet_pda, wallet_bump) =
                Pubkey::find_program_address(&[b"wallet", owner.key.as_ref()], program_id);
            if *auth_account.key != auth_pda || *wallet_account.key != wallet_pda {
                return Err(ProgramError::InvalidSeeds);
            }
            let rent = Rent::get()?;
            let space = 32 + 8 + 32;
            let rent_lamports = rent.minimum_balance(space);
            invoke_signed(
                &system_instruction::create_account(
                    owner.key,
                    &auth_pda,
                    rent_lamports,
                    space as u64,
                    program_id,
                ),
                &[owner.clone(), auth_account.clone(), system_program.clone()],
                &[&[b"auth", owner.key.as_ref(), &[auth_bump]]],
            )?;
            invoke_signed(
                &system_instruction::create_account(
                    owner.key,
                    &wallet_pda,
                    rent.minimum_balance(0),
                    0,
                    program_id,
                ),
                &[
                    owner.clone(),
                    wallet_account.clone(),
                    system_program.clone(),
                ],
                &[&[b"wallet", owner.key.as_ref(), &[wallet_bump]]],
            )?;
            let mut auth_data = auth_account.try_borrow_mut_data()?;
            auth_data[..32].copy_from_slice(&encrypted_key);
            auth_data[32..40].copy_from_slice(&0u64.to_le_bytes());
            auth_data[40..72].copy_from_slice(owner.key.as_ref());
        }
        TwoFactorInstruction::ProcessTransaction { totp, amount } => {
            let owner = next_account_info(accounts_iter)?;
            let auth_account = next_account_info(accounts_iter)?;
            let wallet_account = next_account_info(accounts_iter)?;
            let recipient = next_account_info(accounts_iter)?;
            let instructions_sysvar = next_account_info(accounts_iter)?;
            if !owner.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let auth_data = auth_account.try_borrow_data()?;
            let stored_owner = Pubkey::new(&auth_data[40..72]);
            if stored_owner != *owner.key {
                msg!("Transaction must be initiated by the wallet initializer");
                return Err(ProgramError::InvalidAccountData);
            }
            let (wallet_pda, wallet_bump) =
                Pubkey::find_program_address(&[b"wallet", owner.key.as_ref()], program_id);
            if *wallet_account.key != wallet_pda {
                return Err(ProgramError::InvalidSeeds);
            }
            msg!("two factor process start");
            let ed25519_ix =
                load_instruction_at_checked(ED25519_IX_INDEX.into(), instructions_sysvar)?;
            msg!("Ed25519 instruction loaded: {:?}", ed25519_ix);
            if !validate_ed25519_instruction(&ed25519_ix) {
                msg!("Ed25519 validation failed");
                return Err(ProgramError::InvalidInstructionData);
            }
            msg!("Ed25519 validation passed");
            let signature = &ed25519_ix.data[48..112];
            msg!("Extracted signature length: {}", signature.len());
            msg!("Extracted signature (hex): {:02x?}", signature);
            let signature_array: [u8; 64] = signature
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            let decrypted_key: [u8; 32];
            let current_nonce: u64;
            {
                let auth_data = auth_account.try_borrow_data()?;
                let encrypted_key: [u8; 32] = auth_data[..32].try_into().unwrap();
                current_nonce = u64::from_le_bytes(auth_data[32..40].try_into().unwrap());
                decrypted_key = decrypt_key(&encrypted_key, current_nonce, &signature_array);
            }
            let clock = Clock::get()?;
            let current_time = clock.unix_timestamp as u64;
            let generated_totp = generate_totp(&decrypted_key, current_time / TIME_STEP);
            if generated_totp != totp {
                msg!("TOTP mismatch!");
                return Err(ProgramError::InvalidArgument);
            }
            transfer_service_fee_lamports(wallet_account, recipient, amount)?;
            {
                let mut auth_data = auth_account.try_borrow_mut_data()?;
                let new_nonce = current_nonce + 1;
                let new_encrypted_key = encrypt_key(&decrypted_key, new_nonce, &signature_array);
                auth_data[..32].copy_from_slice(&new_encrypted_key);
                auth_data[32..40].copy_from_slice(&new_nonce.to_le_bytes());
            }
        }
    }
    Ok(())
}
