use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce,
};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash,
        PasswordHasher,
        PasswordVerifier,
        SaltString,
    },
    Argon2,
};
use base64::{
    engine::general_purpose::STANDARD_NO_PAD,
    Engine as _,
};
use rand_core::RngCore;
use std::sync::Mutex;
use tauri::State;
use zeroize::Zeroizing;

/* =========================================================
   VAULT STATE
========================================================= */

struct VaultState {
    key: Mutex<Option<Zeroizing<[u8; 32]>>>,
}

/* =========================================================
   PASSWORD HASHING
========================================================= */

/// Hash the user's master password using Argon2id.
#[tauri::command]
fn hash_password(
    password: String,
) -> Result<String, String> {
    if password.is_empty() {
        return Err(
            "Password cannot be empty.".to_string()
        );
    }

    let salt =
        SaltString::generate(&mut OsRng);

    let password_hash =
        Argon2::default()
            .hash_password(
                password.as_bytes(),
                &salt,
            )
            .map_err(|error| error.to_string())?
            .to_string();

    Ok(password_hash)
}

/// Verify the user's master password.
#[tauri::command]
fn verify_password(
    password: String,
    password_hash: String,
) -> Result<bool, String> {
    if password.is_empty() {
        return Ok(false);
    }

    let parsed_hash =
        PasswordHash::new(&password_hash)
            .map_err(|error| error.to_string())?;

    Ok(
        Argon2::default()
            .verify_password(
                password.as_bytes(),
                &parsed_hash,
            )
            .is_ok(),
    )
}

/* =========================================================
   VAULT SALT
========================================================= */

/// Generate a separate random salt for the
/// journal encryption key.
///
/// This salt is NOT secret. It is stored in SQLite.
/// The password is what makes the derived key secret.
#[tauri::command]
fn generate_vault_salt()
    -> Result<String, String>
{
    let mut salt = [0u8; 16];

    OsRng.fill_bytes(&mut salt);

    Ok(
        STANDARD_NO_PAD.encode(salt)
    )
}

/* =========================================================
   KEY DERIVATION
========================================================= */

fn derive_vault_key(
    password: &str,
    vault_salt: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let salt =
        STANDARD_NO_PAD
            .decode(vault_salt)
            .map_err(|error| {
                format!(
                    "Invalid vault salt: {error}"
                )
            })?;

    if salt.len() < 16 {
        return Err(
            "Vault salt is invalid.".to_string()
        );
    }

    let mut key =
        Zeroizing::new([0u8; 32]);

    /*
     * Argon2id derives 256 bits of key material
     * from the user's password and the separate
     * vault salt.
     */
    Argon2::default()
        .hash_password_into(
            password.as_bytes(),
            &salt,
            key.as_mut(),
        )
        .map_err(|error| error.to_string())?;

    Ok(key)
}

/* =========================================================
   UNLOCK VAULT
========================================================= */

/// Verify the password and, if correct, derive and
/// keep the encryption key in Rust memory.
#[tauri::command]
fn unlock_vault(
    password: String,
    password_hash: String,
    vault_salt: String,
    state: State<VaultState>,
) -> Result<bool, String> {
    if password.is_empty() {
        return Ok(false);
    }

    let parsed_hash =
        PasswordHash::new(&password_hash)
            .map_err(|error| error.to_string())?;

    /*
     * First verify the password.
     *
     * We don't derive/store the vault key until
     * authentication succeeds.
     */
    if Argon2::default()
        .verify_password(
            password.as_bytes(),
            &parsed_hash,
        )
        .is_err()
    {
        return Ok(false);
    }

    let key =
        derive_vault_key(
            &password,
            &vault_salt,
        )?;

    let mut stored_key =
        state
            .key
            .lock()
            .map_err(|_| {
                "Vault state is unavailable."
                    .to_string()
            })?;

    *stored_key = Some(key);

    Ok(true)
}

/* =========================================================
   LOCK VAULT
========================================================= */

/// Remove the encryption key from Rust memory.
#[tauri::command]
fn lock_vault(
    state: State<VaultState>,
) -> Result<(), String> {
    let mut stored_key =
        state
            .key
            .lock()
            .map_err(|_| {
                "Vault state is unavailable."
                    .to_string()
            })?;

    /*
     * Zeroizing automatically clears the previous
     * key from memory when it is dropped.
     */
    *stored_key = None;

    Ok(())
}

/* =========================================================
   INTERNAL KEY ACCESS
========================================================= */

fn get_vault_key(
    state: &State<VaultState>,
) -> Result<
    Zeroizing<[u8; 32]>,
    String,
> {
    let stored_key =
        state
            .key
            .lock()
            .map_err(|_| {
                "Vault state is unavailable."
                    .to_string()
            })?;

    stored_key
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            "Vault is locked.".to_string()
        })
}

/* =========================================================
   ENCRYPT
========================================================= */

/// Encrypt plaintext using AES-256-GCM.
///
/// Returned format:
///
/// base64(
///     12-byte nonce
///     + ciphertext
///     + 16-byte authentication tag
/// )
#[tauri::command]
fn encrypt_text(
    plaintext: String,
    state: State<VaultState>,
) -> Result<String, String> {
    let key =
        get_vault_key(&state)?;

    let cipher =
        Aes256Gcm::new_from_slice(
            key.as_ref(),
        )
        .map_err(|error| {
            error.to_string()
        })?;

    /*
     * AES-GCM uses a 96-bit / 12-byte nonce.
     *
     * A fresh random nonce is generated for
     * every encryption operation.
     */
    let mut nonce_bytes =
        [0u8; 12];

    OsRng.fill_bytes(
        &mut nonce_bytes,
    );

    let nonce =
        Nonce::from_slice(
            &nonce_bytes,
        );

    let ciphertext =
        cipher
            .encrypt(
                nonce,
                plaintext.as_bytes(),
            )
            .map_err(|_| {
                "Encryption failed."
                    .to_string()
            })?;

    /*
     * Store nonce together with ciphertext.
     *
     * The nonce is not secret.
     */
    let mut payload =
        Vec::with_capacity(
            nonce_bytes.len()
                + ciphertext.len(),
        );

    payload.extend_from_slice(
        &nonce_bytes,
    );

    payload.extend_from_slice(
        &ciphertext,
    );

    Ok(
        STANDARD_NO_PAD
            .encode(payload)
    )
}

/* =========================================================
   DECRYPT
========================================================= */

/// Decrypt AES-256-GCM encrypted text.
#[tauri::command]
fn decrypt_text(
    encrypted: String,
    state: State<VaultState>,
) -> Result<String, String> {
    let key =
        get_vault_key(&state)?;

    let payload =
        STANDARD_NO_PAD
            .decode(encrypted)
            .map_err(|_| {
                "Invalid encrypted data."
                    .to_string()
            })?;

    /*
     * 12 bytes nonce
     * 16 bytes authentication tag
     */
    if payload.len() < 12 + 16 {
        return Err(
            "Invalid encrypted data."
                .to_string()
        );
    }

    let (
        nonce_bytes,
        ciphertext,
    ) = payload.split_at(12);

    let cipher =
        Aes256Gcm::new_from_slice(
            key.as_ref(),
        )
        .map_err(|error| {
            error.to_string()
        })?;

    let nonce =
        Nonce::from_slice(
            nonce_bytes,
        );

    let plaintext =
        cipher
            .decrypt(
                nonce,
                ciphertext,
            )
            .map_err(|_| {
                "Decryption failed. Data may be corrupted or the vault key is incorrect."
                    .to_string()
            })?;

    String::from_utf8(
        plaintext,
    )
    .map_err(|_| {
        "Decrypted data is not valid UTF-8."
            .to_string()
    })
}

/* =========================================================
   TAURI ENTRY POINT
========================================================= */

#[cfg_attr(
    mobile,
    tauri::mobile_entry_point
)]
pub fn run() {
    tauri::Builder::default()
        /*
         * The encryption key exists only in this
         * Rust process state while unlocked.
         */
        .manage(VaultState {
            key: Mutex::new(None),
        })
        .plugin(
            tauri_plugin_opener::init()
        )
        .plugin(
            tauri_plugin_sql::Builder::default()
                .build(),
        )
        .invoke_handler(
            tauri::generate_handler![
                hash_password,
                verify_password,
                generate_vault_salt,
                unlock_vault,
                lock_vault,
                encrypt_text,
                decrypt_text
            ],
        )
        .run(
            tauri::generate_context!()
        )
        .expect(
            "error while running tauri application",
        );
}