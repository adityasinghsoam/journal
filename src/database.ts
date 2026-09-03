import { isTauri } from "./platform";

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

async function getDatabase() {
  if (isTauri) {
    return await import("./database.tauri");
  }

  return await import("./webDatabase");
}

export async function initializeDatabase(): Promise<void> {
  const db = await getDatabase();
  await db.initializeDatabase();
}

export async function hasMasterPassword(): Promise<boolean> {
  const db = await getDatabase();
  return db.hasMasterPassword();
}

export async function getMasterPasswordHash(): Promise<string | null> {
  const db = await getDatabase();
  return db.getMasterPasswordHash();
}

export async function setMasterPasswordHash(
  passwordHash: string,
): Promise<void> {
  const db = await getDatabase();
  await db.setMasterPasswordHash(passwordHash);
}

export async function getVaultSalt(): Promise<string | null> {
  const db = await getDatabase();
  return db.getVaultSalt();
}

export async function setVaultSalt(
  vaultSalt: string,
): Promise<void> {
  const db = await getDatabase();
  await db.setVaultSalt(vaultSalt);
}

export async function migrateJournalEntriesToEncrypted(): Promise<void> {
  const db = await getDatabase();
  await db.migrateJournalEntriesToEncrypted();
}

export async function migrateTasksToEncrypted(): Promise<void> {
  const db = await getDatabase();
  await db.migrateTasksToEncrypted();
}

export async function getJournalEntries(): Promise<JournalEntry[]> {
  const db = await getDatabase();
  return db.getJournalEntries();
}

export async function createJournalEntry(
  title: string,
  content: string,
  journalDate: string,
): Promise<JournalEntry> {
  const db = await getDatabase();

  return db.createJournalEntry(
    title,
    content,
    journalDate,
  );
}

export async function updateJournalEntry(
  id: string,
  title: string,
  content: string,
  journalDate: string,
): Promise<void> {
  const db = await getDatabase();

  await db.updateJournalEntry(
    id,
    title,
    content,
    journalDate,
  );
}

export async function deleteJournalEntry(
  id: string,
): Promise<void> {
  const db = await getDatabase();
  await db.deleteJournalEntry(id);
}

export async function getTasks(): Promise<TodoTask[]> {
  const db = await getDatabase();
  return db.getTasks();
}

export async function createTask(
  title: string,
): Promise<TodoTask> {
  const db = await getDatabase();
  return db.createTask(title);
}

export async function toggleTask(
  id: string,
  completed: boolean,
): Promise<void> {
  const db = await getDatabase();
  await db.toggleTask(id, completed);
}

export async function deleteTask(
  id: string,
): Promise<void> {
  const db = await getDatabase();
  await db.deleteTask(id);
}