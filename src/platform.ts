import {
  lockWebVault,
  unlockWebVault,
  verifyWebPassword,
  hashWebPassword,
  generateWebVaultSalt,
} from "./webDatabase";

export const isTauri =
  typeof window !== "undefined" &&
  "__TAURI_INTERNALS__" in window;

async function getTauriInvoke() {
  const { invoke } =
    await import("@tauri-apps/api/core");

  return invoke;
}

export async function hashPassword(
  password: string,
): Promise<string> {
  if (isTauri) {
    const invoke =
      await getTauriInvoke();

    return invoke<string>(
      "hash_password",
      { password },
    );
  }

  return hashWebPassword(password);
}

export async function verifyPassword(
  password: string,
  passwordHash: string,
): Promise<boolean> {
  if (isTauri) {
    const invoke =
      await getTauriInvoke();

    return invoke<boolean>(
      "verify_password",
      {
        password,
        passwordHash,
      },
    );
  }

  return verifyWebPassword(
    password,
    passwordHash,
  );
}

export async function generateVaultSalt(): Promise<string> {
  if (isTauri) {
    const invoke =
      await getTauriInvoke();

    return invoke<string>(
      "generate_vault_salt",
    );
  }

  return generateWebVaultSalt();
}

export async function unlockVault(
  password: string,
  _passwordHash: string,
  _vaultSalt: string,
): Promise<boolean> {
  if (isTauri) {
    const invoke =
      await getTauriInvoke();

    return invoke<boolean>(
      "unlock_vault",
      {
        password,
        passwordHash:
          _passwordHash,
        vaultSalt:
          _vaultSalt,
      },
    );
  }

  return unlockWebVault(password);
}

export async function lockVault(): Promise<void> {
  if (isTauri) {
    const invoke =
      await getTauriInvoke();

    await invoke("lock_vault");
    return;
  }

  lockWebVault();
}