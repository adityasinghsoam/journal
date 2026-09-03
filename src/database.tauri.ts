import Database from "@tauri-apps/plugin-sql";
import { invoke } from "@tauri-apps/api/core";

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

let db: Database | null = null;

async function getDatabase() {
  if (!db) {
    db = await Database.load("sqlite:journal.db");
  }

  return db;
}

/* =========================================================
   ENCRYPTION HELPERS
========================================================= */

async function encryptText(
  plaintext: string,
): Promise<string> {
  return invoke<string>("encrypt_text", {
    plaintext,
  });
}

async function decryptText(
  encrypted: string,
): Promise<string> {
  return invoke<string>("decrypt_text", {
    encrypted,
  });
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

export async function initializeDatabase() {
  const database = await getDatabase();

  await database.execute(`
    CREATE TABLE IF NOT EXISTS journal_entries (
      id TEXT PRIMARY KEY NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      journal_date TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      title_encrypted TEXT,
      content_encrypted TEXT
    )
  `);

  const journalColumns =
    await database.select<{ name: string }[]>(
      `
        PRAGMA table_info(journal_entries)
      `,
    );

  const hasJournalDate =
    journalColumns.some(
      (column) =>
        column.name === "journal_date",
    );

  if (!hasJournalDate) {
    await database.execute(`
      ALTER TABLE journal_entries
      ADD COLUMN journal_date
      TEXT NOT NULL DEFAULT ''
    `);
  }

  const hasTitleEncrypted =
    journalColumns.some(
      (column) =>
        column.name === "title_encrypted",
    );

  if (!hasTitleEncrypted) {
    await database.execute(`
      ALTER TABLE journal_entries
      ADD COLUMN title_encrypted
      TEXT
    `);
  }

  const hasContentEncrypted =
    journalColumns.some(
      (column) =>
        column.name === "content_encrypted",
    );

  if (!hasContentEncrypted) {
    await database.execute(`
      ALTER TABLE journal_entries
      ADD COLUMN content_encrypted
      TEXT
    `);
  }

  await database.execute(`
    UPDATE journal_entries
    SET journal_date =
      substr(created_at, 1, 10)
    WHERE journal_date = ''
  `);

  /* =======================================================
     TASKS
  ======================================================= */

  await database.execute(`
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY NOT NULL,
      title TEXT NOT NULL,
      completed INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      completed_at TEXT,
      title_encrypted TEXT
    )
  `);

  const taskColumns =
    await database.select<{ name: string }[]>(
      `
        PRAGMA table_info(tasks)
      `,
    );

  const hasTaskTitleEncrypted =
    taskColumns.some(
      (column) =>
        column.name === "title_encrypted",
    );

  if (!hasTaskTitleEncrypted) {
    await database.execute(`
      ALTER TABLE tasks
      ADD COLUMN title_encrypted
      TEXT
    `);
  }

  /* =======================================================
     APP SETTINGS
  ======================================================= */

  await database.execute(`
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY NOT NULL,
      value TEXT NOT NULL
    )
  `);

  await database.execute(`
    INSERT OR IGNORE INTO app_settings
      (key, value)
    VALUES
      ('security_version', '3')
  `);
}

/* =========================================================
   MASTER PASSWORD
========================================================= */

export async function getMasterPasswordHash(): Promise<
  string | null
> {
  const database = await getDatabase();

  const rows =
    await database.select<{ value: string }[]>(
      `
        SELECT value
        FROM app_settings
        WHERE key = ?
        LIMIT 1
      `,
      ["master_password_hash"],
    );

  if (rows.length === 0) {
    return null;
  }

  return rows[0].value;
}

export async function hasMasterPassword(): Promise<boolean> {
  const hash =
    await getMasterPasswordHash();

  return (
    hash !== null &&
    hash.length > 0
  );
}

export async function setMasterPasswordHash(
  passwordHash: string,
): Promise<void> {
  const database = await getDatabase();

  if (!passwordHash.trim()) {
    throw new Error(
      "Password hash cannot be empty.",
    );
  }

  await database.execute(
    `
      INSERT INTO app_settings
        (key, value)
      VALUES
        (?, ?)
      ON CONFLICT(key)
      DO UPDATE SET
        value = excluded.value
    `,
    [
      "master_password_hash",
      passwordHash,
    ],
  );
}

/* =========================================================
   VAULT SALT
========================================================= */

export async function getVaultSalt(): Promise<
  string | null
> {
  const database = await getDatabase();

  const rows =
    await database.select<{ value: string }[]>(
      `
        SELECT value
        FROM app_settings
        WHERE key = ?
        LIMIT 1
      `,
      ["vault_salt"],
    );

  if (rows.length === 0) {
    return null;
  }

  return rows[0].value;
}

export async function setVaultSalt(
  vaultSalt: string,
): Promise<void> {
  const database = await getDatabase();

  if (!vaultSalt.trim()) {
    throw new Error(
      "Vault salt cannot be empty.",
    );
  }

  await database.execute(
    `
      INSERT INTO app_settings
        (key, value)
      VALUES
        (?, ?)
      ON CONFLICT(key)
      DO UPDATE SET
        value = excluded.value
    `,
    [
      "vault_salt",
      vaultSalt,
    ],
  );
}

/* =========================================================
   JOURNAL MIGRATION
========================================================= */

export async function migrateJournalEntriesToEncrypted(): Promise<void> {
  const database = await getDatabase();

  const rows =
    await database.select<
      {
        id: string;
        title: string;
        content: string;
        title_encrypted: string | null;
        content_encrypted: string | null;
      }[]
    >(
      `
        SELECT
          id,
          title,
          content,
          title_encrypted,
          content_encrypted
        FROM journal_entries
      `,
    );

  for (const row of rows) {
    const titleAlreadyEncrypted =
      Boolean(row.title_encrypted);

    const contentAlreadyEncrypted =
      Boolean(row.content_encrypted);

    if (
      titleAlreadyEncrypted &&
      contentAlreadyEncrypted
    ) {
      continue;
    }

    const encryptedTitle =
      titleAlreadyEncrypted
        ? row.title_encrypted!
        : await encryptText(row.title);

    const encryptedContent =
      contentAlreadyEncrypted
        ? row.content_encrypted!
        : await encryptText(row.content);

    await database.execute(
      `
        UPDATE journal_entries
        SET
          title_encrypted = ?,
          content_encrypted = ?,
          title = '',
          content = ''
        WHERE id = ?
      `,
      [
        encryptedTitle,
        encryptedContent,
        row.id,
      ],
    );
  }
}

/* =========================================================
   TASK MIGRATION
========================================================= */

export async function migrateTasksToEncrypted(): Promise<void> {
  const database = await getDatabase();

  const rows =
    await database.select<
      {
        id: string;
        title: string;
        title_encrypted: string | null;
      }[]
    >(
      `
        SELECT
          id,
          title,
          title_encrypted
        FROM tasks
      `,
    );

  for (const row of rows) {
    /*
     * Already encrypted.
     */
    if (row.title_encrypted) {
      continue;
    }

    /*
     * Encrypt the existing plaintext task title.
     */
    const encryptedTitle =
      await encryptText(row.title);

    /*
     * Store the encrypted title and
     * immediately clear the plaintext column.
     */
    await database.execute(
      `
        UPDATE tasks
        SET
          title_encrypted = ?,
          title = ''
        WHERE id = ?
      `,
      [
        encryptedTitle,
        row.id,
      ],
    );
  }
}

/* =========================================================
   JOURNAL
========================================================= */

export async function getJournalEntries(): Promise<
  JournalEntry[]
> {
  const database = await getDatabase();

  const rows =
    await database.select<
      {
        id: string;
        title_encrypted: string | null;
        content_encrypted: string | null;
        journal_date: string;
        created_at: string;
        updated_at: string;
      }[]
    >(
      `
        SELECT
          id,
          title_encrypted,
          content_encrypted,
          journal_date,
          created_at,
          updated_at
        FROM journal_entries
        ORDER BY
          journal_date DESC,
          created_at DESC
      `,
    );

  return Promise.all(
    rows.map(async (row) => {
      if (
        !row.title_encrypted ||
        !row.content_encrypted
      ) {
        throw new Error(
          "Journal entry is not encrypted yet.",
        );
      }

      const [
        title,
        content,
      ] = await Promise.all([
        decryptText(
          row.title_encrypted,
        ),
        decryptText(
          row.content_encrypted,
        ),
      ]);

      return {
        id: row.id,
        title,
        content,
        journalDate:
          row.journal_date,
        createdAt:
          row.created_at,
        updatedAt:
          row.updated_at,
      };
    }),
  );
}

export async function createJournalEntry(
  title: string,
  content: string,
  journalDate: string,
): Promise<JournalEntry> {
  const database = await getDatabase();

  const encryptedTitle =
    await encryptText(title);

  const encryptedContent =
    await encryptText(content);

  const now =
    new Date().toISOString();

  const id =
    crypto.randomUUID();

  await database.execute(
    `
      INSERT INTO journal_entries
        (
          id,
          title,
          content,
          journal_date,
          created_at,
          updated_at,
          title_encrypted,
          content_encrypted
        )
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      id,
      "",
      "",
      journalDate,
      now,
      now,
      encryptedTitle,
      encryptedContent,
    ],
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
  const database = await getDatabase();

  const encryptedTitle =
    await encryptText(title);

  const encryptedContent =
    await encryptText(content);

  const now =
    new Date().toISOString();

  await database.execute(
    `
      UPDATE journal_entries
      SET
        title = '',
        content = '',
        title_encrypted = ?,
        content_encrypted = ?,
        journal_date = ?,
        updated_at = ?
      WHERE id = ?
    `,
    [
      encryptedTitle,
      encryptedContent,
      journalDate,
      now,
      id,
    ],
  );
}

export async function deleteJournalEntry(
  id: string,
): Promise<void> {
  const database = await getDatabase();

  await database.execute(
    `
      DELETE FROM journal_entries
      WHERE id = ?
    `,
    [id],
  );
}

/* =========================================================
   TASKS
========================================================= */

export async function getTasks(): Promise<
  TodoTask[]
> {
  const database = await getDatabase();

  const rows =
    await database.select<
      {
        id: string;
        title_encrypted: string | null;
        completed: number;
        created_at: string;
        completed_at: string | null;
      }[]
    >(
      `
        SELECT
          id,
          title_encrypted,
          completed,
          created_at,
          completed_at
        FROM tasks
        ORDER BY
          completed ASC,
          created_at DESC
      `,
    );

  return Promise.all(
    rows.map(async (row) => {
      if (!row.title_encrypted) {
        throw new Error(
          "Task is not encrypted yet.",
        );
      }

      const title =
        await decryptText(
          row.title_encrypted,
        );

      return {
        id: row.id,
        title,
        completed:
          row.completed === 1,
        createdAt:
          row.created_at,
        completedAt:
          row.completed_at,
      };
    }),
  );
}

export async function createTask(
  title: string,
): Promise<TodoTask> {
  const database = await getDatabase();

  /*
   * Encrypt before SQLite receives the title.
   */
  const encryptedTitle =
    await encryptText(title);

  const now =
    new Date().toISOString();

  const id =
    crypto.randomUUID();

  await database.execute(
    `
      INSERT INTO tasks
        (
          id,
          title,
          completed,
          created_at,
          completed_at,
          title_encrypted
        )
      VALUES
        (?, ?, ?, ?, ?, ?)
    `,
    [
      id,
      "",
      0,
      now,
      null,
      encryptedTitle,
    ],
  );

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
  const database = await getDatabase();

  const completedAt =
    completed
      ? new Date().toISOString()
      : null;

  await database.execute(
    `
      UPDATE tasks
      SET
        completed = ?,
        completed_at = ?
      WHERE id = ?
    `,
    [
      completed ? 1 : 0,
      completedAt,
      id,
    ],
  );
}

export async function deleteTask(
  id: string,
): Promise<void> {
  const database = await getDatabase();

  await database.execute(
    `
      DELETE FROM tasks
      WHERE id = ?
    `,
    [id],
  );
}