/* =========================================================
   WEB DATABASE
   Browser / Vercel version

   Storage:
   - IndexedDB

   Encryption:
   - Web Crypto API
   - PBKDF2 -> AES-GCM

   This file is used only by the browser version.
========================================================= */

export type JournalEntry = {
  id: string;
  title: string;
  content: string;
  journalDate: string;
  createdAt: string;
  updatedAt: string;
};

export type TodoTask = {
  id: string;
  title: string;
  completed: boolean;
  createdAt: string;
  completedAt: string | null;
};

type StoredJournalEntry = {
  id: string;
  titleEncrypted: string;
  contentEncrypted: string;
  journalDate: string;
  createdAt: string;
  updatedAt: string;
};

type StoredTask = {
  id: string;
  titleEncrypted: string;
  completed: number;
  createdAt: string;
  completedAt: string | null;
};

type StoredSetting = {
  key: string;
  value: string;
};

const DB_NAME = "journal-web";
const DB_VERSION = 1;

const JOURNAL_STORE = "journal_entries";
const TASK_STORE = "tasks";
const SETTINGS_STORE = "app_settings";

const PBKDF2_ITERATIONS = 600_000;
const AES_KEY_LENGTH = 256;

let database: IDBDatabase | null = null;

let encryptionKey: CryptoKey | null = null;

/* =========================================================
   INDEXEDDB
========================================================= */

function getDatabase(): Promise<IDBDatabase> {
  if (database) {
    return Promise.resolve(database);
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(
      DB_NAME,
      DB_VERSION,
    );

    request.onupgradeneeded = () => {
      const db = request.result;

      if (!db.objectStoreNames.contains(JOURNAL_STORE)) {
        db.createObjectStore(
          JOURNAL_STORE,
          {
            keyPath: "id",
          },
        );
      }

      if (!db.objectStoreNames.contains(TASK_STORE)) {
        db.createObjectStore(
          TASK_STORE,
          {
            keyPath: "id",
          },
        );
      }

      if (!db.objectStoreNames.contains(SETTINGS_STORE)) {
        db.createObjectStore(
          SETTINGS_STORE,
          {
            keyPath: "key",
          },
        );
      }
    };

    request.onsuccess = () => {
      database = request.result;

      database.onclose = () => {
        database = null;
      };

      resolve(database);
    };

    request.onerror = () => {
      reject(
        request.error ??
          new Error(
            "Failed to open IndexedDB.",
          ),
      );
    };
  });
}

/* =========================================================
   GENERIC INDEXEDDB HELPERS
========================================================= */

async function getSetting(
  key: string,
): Promise<string | null> {
  const db = await getDatabase();

  return new Promise((resolve, reject) => {
    const transaction =
      db.transaction(
        SETTINGS_STORE,
        "readonly",
      );

    const store =
      transaction.objectStore(
        SETTINGS_STORE,
      );

    const request =
      store.get(key);

    request.onsuccess = () => {
      const setting =
        request.result as
          | StoredSetting
          | undefined;

      resolve(
        setting?.value ?? null,
      );
    };

    request.onerror = () => {
      reject(
        request.error ??
          new Error(
            "Failed to read setting.",
          ),
      );
    };
  });
}

async function setSetting(
  key: string,
  value: string,
): Promise<void> {
  const db = await getDatabase();

  return new Promise((resolve, reject) => {
    const transaction =
      db.transaction(
        SETTINGS_STORE,
        "readwrite",
      );

    const store =
      transaction.objectStore(
        SETTINGS_STORE,
      );

    store.put({
      key,
      value,
    });

    transaction.oncomplete = () => {
      resolve();
    };

    transaction.onerror = () => {
      reject(
        transaction.error ??
          new Error(
            "Failed to save setting.",
          ),
      );
    };
  });
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

export async function initializeDatabase(): Promise<void> {
  await getDatabase();

  const securityVersion =
    await getSetting(
      "security_version",
    );

  if (!securityVersion) {
    await setSetting(
      "security_version",
      "1",
    );
  }
}

/* =========================================================
   PASSWORD HASHING
========================================================= */

/*
 * Browser password verifier.

 * We store:
 *
 *   base64(salt):base64(hash)
 *
 * The password itself is never stored.
 */

function bytesToBase64(
  bytes: Uint8Array,
): string {
  let binary = "";

  const chunkSize = 0x8000;

  for (
    let index = 0;
    index < bytes.length;
    index += chunkSize
  ) {
    binary += String.fromCharCode(
      ...bytes.subarray(
        index,
        Math.min(
          index + chunkSize,
          bytes.length,
        ),
      ),
    );
  }

  return btoa(binary);
}

function base64ToBytes(
  value: string,
): Uint8Array {
  const binary =
    atob(value);

  const bytes =
    new Uint8Array(
      binary.length,
    );

  for (
    let index = 0;
    index < binary.length;
    index++
  ) {
    bytes[index] =
      binary.charCodeAt(index);
  }

  return bytes;
}

function constantTimeEqual(
  a: Uint8Array,
  b: Uint8Array,
): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let difference = 0;

  for (
    let index = 0;
    index < a.length;
    index++
  ) {
    difference |=
      a[index] ^ b[index];
  }

  return difference === 0;
}

async function derivePasswordHash(
  password: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const encoder =
    new TextEncoder();

  const passwordKey =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      {
        name: "PBKDF2",
      },
      false,
      ["deriveBits"],
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations:
          PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      passwordKey,
      256,
    );

  return new Uint8Array(bits);
}

export async function hashWebPassword(
  password: string,
): Promise<string> {
  const salt =
    crypto.getRandomValues(
      new Uint8Array(16),
    );

  const hash =
    await derivePasswordHash(
      password,
      salt,
    );

  return `${bytesToBase64(
    salt,
  )}:${bytesToBase64(hash)}`;
}

export async function verifyWebPassword(
  password: string,
  storedHash: string,
): Promise<boolean> {
  const parts =
    storedHash.split(":");

  if (parts.length !== 2) {
    return false;
  }

  try {
    const salt =
      base64ToBytes(parts[0]);

    const expectedHash =
      base64ToBytes(parts[1]);

    const actualHash =
      await derivePasswordHash(
        password,
        salt,
      );

    return constantTimeEqual(
      actualHash,
      expectedHash,
    );
  } catch {
    return false;
  }
}

/* =========================================================
   VAULT KEY
========================================================= */

async function deriveVaultKey(
  password: string,
  vaultSalt: string,
): Promise<CryptoKey> {
  const encoder =
    new TextEncoder();

  const passwordKey =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      {
        name: "PBKDF2",
      },
      false,
      ["deriveKey"],
    );

  const salt =
    base64ToBytes(vaultSalt);

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations:
        PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    passwordKey,
    {
      name: "AES-GCM",
      length:
        AES_KEY_LENGTH,
    },
    false,
    [
      "encrypt",
      "decrypt",
    ],
  );
}

/* =========================================================
   WEB ENCRYPTION
========================================================= */

async function encryptText(
  plaintext: string,
): Promise<string> {
  if (!encryptionKey) {
    throw new Error(
      "Vault is locked.",
    );
  }

  const encoder =
    new TextEncoder();

  const nonce =
    crypto.getRandomValues(
      new Uint8Array(12),
    );

  const ciphertext =
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
      },
      encryptionKey,
      encoder.encode(
        plaintext,
      ),
    );

  /*
   * Store:
   *
   * nonce + ciphertext
   *
   * as Base64.
   */

  const encrypted =
    new Uint8Array(
      nonce.length +
        ciphertext.byteLength,
    );

  encrypted.set(
    nonce,
    0,
  );

  encrypted.set(
    new Uint8Array(
      ciphertext,
    ),
    nonce.length,
  );

  return bytesToBase64(
    encrypted,
  );
}

async function decryptText(
  encrypted: string,
): Promise<string> {
  if (!encryptionKey) {
    throw new Error(
      "Vault is locked.",
    );
  }

  const combined =
    base64ToBytes(
      encrypted,
    );

  if (combined.length < 13) {
    throw new Error(
      "Invalid encrypted data.",
    );
  }

  const nonce =
    combined.slice(0, 12);

  const ciphertext =
    combined.slice(12);

  const plaintext =
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
      },
      encryptionKey,
      ciphertext,
    );

  return new TextDecoder().decode(
    plaintext,
  );
}

/* =========================================================
   MASTER PASSWORD
========================================================= */

export async function getMasterPasswordHash(): Promise<
  string | null
> {
  return getSetting(
    "master_password_hash",
  );
}

export async function hasMasterPassword(): Promise<boolean> {
  const hash =
    await getMasterPasswordHash();

  return Boolean(
    hash &&
      hash.length > 0,
  );
}

export async function setMasterPasswordHash(
  passwordHash: string,
): Promise<void> {
  if (!passwordHash.trim()) {
    throw new Error(
      "Password hash cannot be empty.",
    );
  }

  await setSetting(
    "master_password_hash",
    passwordHash,
  );
}

/* =========================================================
   VAULT SALT
========================================================= */

export async function getVaultSalt(): Promise<
  string | null
> {
  return getSetting(
    "vault_salt",
  );
}

export async function setVaultSalt(
  vaultSalt: string,
): Promise<void> {
  if (!vaultSalt.trim()) {
    throw new Error(
      "Vault salt cannot be empty.",
    );
  }

  await setSetting(
    "vault_salt",
    vaultSalt,
  );
}

/* =========================================================
   BROWSER PASSWORD SETUP
========================================================= */
export function generateWebVaultSalt(): string {
  const salt =
    crypto.getRandomValues(
      new Uint8Array(16),
    );

  return bytesToBase64(salt);
}

export async function setupWebVault(
  password: string,
): Promise<void> {
  const passwordHash =
    await hashWebPassword(
      password,
    );

  const salt =
    crypto.getRandomValues(
      new Uint8Array(16),
    );

  const vaultSalt =
    bytesToBase64(salt);

  await setMasterPasswordHash(
    passwordHash,
  );

  await setVaultSalt(
    vaultSalt,
  );

  encryptionKey =
    await deriveVaultKey(
      password,
      vaultSalt,
    );
}

/* =========================================================
   BROWSER UNLOCK
========================================================= */

export async function unlockWebVault(
  password: string,
): Promise<boolean> {
  const passwordHash =
    await getMasterPasswordHash();

  const vaultSalt =
    await getVaultSalt();

  if (
    !passwordHash ||
    !vaultSalt
  ) {
    return false;
  }

  const valid =
    await verifyWebPassword(
      password,
      passwordHash,
    );

  if (!valid) {
    encryptionKey = null;
    return false;
  }

  try {
    encryptionKey =
      await deriveVaultKey(
        password,
        vaultSalt,
      );

    /*
     * Verify that the derived key
     * can actually decrypt existing
     * encrypted data, if any exists.
     */
    return true;
  } catch {
    encryptionKey = null;
    return false;
  }
}

export async function lockWebVault(): Promise<void> {
  encryptionKey = null;
}

/* =========================================================
   JOURNAL HELPERS
========================================================= */

async function getAllJournalEntries(): Promise<
  StoredJournalEntry[]
> {
  const db =
    await getDatabase();

  return new Promise(
    (resolve, reject) => {
      const transaction =
        db.transaction(
          JOURNAL_STORE,
          "readonly",
        );

      const store =
        transaction.objectStore(
          JOURNAL_STORE,
        );

      const request =
        store.getAll();

      request.onsuccess = () => {
        resolve(
          request.result as StoredJournalEntry[],
        );
      };

      request.onerror = () => {
        reject(
          request.error ??
            new Error(
              "Failed to read journal entries.",
            ),
        );
      };
    },
  );
}

async function putJournalEntry(
  entry: StoredJournalEntry,
): Promise<void> {
  const db =
    await getDatabase();

  return new Promise(
    (resolve, reject) => {
      const transaction =
        db.transaction(
          JOURNAL_STORE,
          "readwrite",
        );

      const store =
        transaction.objectStore(
          JOURNAL_STORE,
        );

      store.put(entry);

      transaction.oncomplete =
        () => {
          resolve();
        };

      transaction.onerror =
        () => {
          reject(
            transaction.error ??
              new Error(
                "Failed to save journal entry.",
              ),
          );
        };
    },
  );
}

async function deleteJournalEntryFromStore(
  id: string,
): Promise<void> {
  const db =
    await getDatabase();

  return new Promise(
    (resolve, reject) => {
      const transaction =
        db.transaction(
          JOURNAL_STORE,
          "readwrite",
        );

      const store =
        transaction.objectStore(
          JOURNAL_STORE,
        );

      store.delete(id);

      transaction.oncomplete =
        () => {
          resolve();
        };

      transaction.onerror =
        () => {
          reject(
            transaction.error ??
              new Error(
                "Failed to delete journal entry.",
              ),
          );
        };
    },
  );
}

/* =========================================================
   JOURNAL
========================================================= */

export async function getJournalEntries(): Promise<
  JournalEntry[]
> {
  const rows =
    await getAllJournalEntries();

  const entries =
    await Promise.all(
      rows.map(
        async (row) => {
          const [
            title,
            content,
          ] =
            await Promise.all([
              decryptText(
                row.titleEncrypted,
              ),
              decryptText(
                row.contentEncrypted,
              ),
            ]);

          return {
            id: row.id,
            title,
            content,
            journalDate:
              row.journalDate,
            createdAt:
              row.createdAt,
            updatedAt:
              row.updatedAt,
          };
        },
      ),
    );

  return entries.sort(
    (a, b) => {
      if (
        a.journalDate !==
        b.journalDate
      ) {
        return b.journalDate.localeCompare(
          a.journalDate,
        );
      }

      return b.createdAt.localeCompare(
        a.createdAt,
      );
    },
  );
}

export async function createJournalEntry(
  title: string,
  content: string,
  journalDate: string,
): Promise<JournalEntry> {
  const now =
    new Date().toISOString();

  const id =
    crypto.randomUUID();

  const [
    encryptedTitle,
    encryptedContent,
  ] =
    await Promise.all([
      encryptText(title),
      encryptText(content),
    ]);

  const entry: StoredJournalEntry = {
    id,
    titleEncrypted:
      encryptedTitle,
    contentEncrypted:
      encryptedContent,
    journalDate,
    createdAt: now,
    updatedAt: now,
  };

  await putJournalEntry(
    entry,
  );

  return {
    id,
    title,
    content,
    journalDate,
    createdAt: now,
    updatedAt: now,
  };
}

export async function updateJournalEntry(
  id: string,
  title: string,
  content: string,
  journalDate: string,
): Promise<void> {
  const rows =
    await getAllJournalEntries();

  const existing =
    rows.find(
      (row) =>
        row.id === id,
    );

  if (!existing) {
    throw new Error(
      "Journal entry not found.",
    );
  }

  const [
    encryptedTitle,
    encryptedContent,
  ] =
    await Promise.all([
      encryptText(title),
      encryptText(content),
    ]);

  await putJournalEntry({
    id,
    titleEncrypted:
      encryptedTitle,
    contentEncrypted:
      encryptedContent,
    journalDate,
    createdAt:
      existing.createdAt,
    updatedAt:
      new Date().toISOString(),
  });
}

export async function deleteJournalEntry(
  id: string,
): Promise<void> {
  await deleteJournalEntryFromStore(
    id,
  );
}

/* =========================================================
   TASK HELPERS
========================================================= */

async function getAllTasks(): Promise<
  StoredTask[]
> {
  const db =
    await getDatabase();

  return new Promise(
    (resolve, reject) => {
      const transaction =
        db.transaction(
          TASK_STORE,
          "readonly",
        );

      const store =
        transaction.objectStore(
          TASK_STORE,
        );

      const request =
        store.getAll();

      request.onsuccess = () => {
        resolve(
          request.result as StoredTask[],
        );
      };

      request.onerror = () => {
        reject(
          request.error ??
            new Error(
              "Failed to read tasks.",
            ),
        );
      };
    },
  );
}

async function putTask(
  task: StoredTask,
): Promise<void> {
  const db =
    await getDatabase();

  return new Promise(
    (resolve, reject) => {
      const transaction =
        db.transaction(
          TASK_STORE,
          "readwrite",
        );

      const store =
        transaction.objectStore(
          TASK_STORE,
        );

      store.put(task);

      transaction.oncomplete =
        () => {
          resolve();
        };

      transaction.onerror =
        () => {
          reject(
            transaction.error ??
              new Error(
                "Failed to save task.",
              ),
          );
        };
    },
  );
}

async function deleteTaskFromStore(
  id: string,
): Promise<void> {
  const db =
    await getDatabase();

  return new Promise(
    (resolve, reject) => {
      const transaction =
        db.transaction(
          TASK_STORE,
          "readwrite",
        );

      const store =
        transaction.objectStore(
          TASK_STORE,
        );

      store.delete(id);

      transaction.oncomplete =
        () => {
          resolve();
        };

      transaction.onerror =
        () => {
          reject(
            transaction.error ??
              new Error(
                "Failed to delete task.",
              ),
          );
        };
    },
  );
}

/* =========================================================
   TASKS
========================================================= */

export async function getTasks(): Promise<
  TodoTask[]
> {
  const rows =
    await getAllTasks();

  const tasks =
    await Promise.all(
      rows.map(
        async (row) => {
          const title =
            await decryptText(
              row.titleEncrypted,
            );

          return {
            id: row.id,
            title,
            completed:
              row.completed === 1,
            createdAt:
              row.createdAt,
            completedAt:
              row.completedAt,
          };
        },
      ),
    );

  return tasks.sort(
    (a, b) => {
      if (
        a.completed !==
        b.completed
      ) {
        return a.completed
          ? 1
          : -1;
      }

      return b.createdAt.localeCompare(
        a.createdAt,
      );
    },
  );
}

export async function createTask(
  title: string,
): Promise<TodoTask> {
  const now =
    new Date().toISOString();

  const id =
    crypto.randomUUID();

  const encryptedTitle =
    await encryptText(title);

  await putTask({
    id,
    titleEncrypted:
      encryptedTitle,
    completed: 0,
    createdAt: now,
    completedAt: null,
  });

  return {
    id,
    title,
    completed: false,
    createdAt: now,
    completedAt: null,
  };
}

export async function toggleTask(
  id: string,
  completed: boolean,
): Promise<void> {
  const rows =
    await getAllTasks();

  const existing =
    rows.find(
      (row) =>
        row.id === id,
    );

  if (!existing) {
    throw new Error(
      "Task not found.",
    );
  }

  await putTask({
    ...existing,
    completed:
      completed ? 1 : 0,
    completedAt:
      completed
        ? new Date().toISOString()
        : null,
  });
}

export async function deleteTask(
  id: string,
): Promise<void> {
  await deleteTaskFromStore(
    id,
  );
}

/* =========================================================
   MIGRATION FUNCTIONS
========================================================= */

/*
 * Browser storage starts empty, so there is no
 * SQLite plaintext migration to perform.
 *
 * These functions exist because App.tsx calls
 * them for both platforms.
 */

export async function migrateJournalEntriesToEncrypted(): Promise<void> {
  /*
   * Nothing to migrate for a fresh browser database.
   */
}

export async function migrateTasksToEncrypted(): Promise<void> {
  /*
   * Nothing to migrate for a fresh browser database.
   */
}