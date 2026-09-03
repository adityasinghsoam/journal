import { useEffect, useState } from "react";
import "./App.css";

import {
  hashPassword,
  verifyPassword,
  generateVaultSalt,
  unlockVault,
  lockVault,
} from "./platform";

import {
  createJournalEntry,
  deleteJournalEntry,
  getJournalEntries,
  updateJournalEntry,
  initializeDatabase,
  getMasterPasswordHash,
  setMasterPasswordHash,
  getVaultSalt,
  setVaultSalt,
  migrateJournalEntriesToEncrypted,
  migrateTasksToEncrypted,
  getTasks,
  createTask,
  toggleTask,
  deleteTask,
  type JournalEntry,
  type TodoTask,
} from "./database";

type Page =
  | "dashboard"
  | "journal"
  | "todos"
  | "settings";

type SecurityState =
  | "loading"
  | "setup"
  | "locked"
  | "unlocked"
  | "error";

function App() {
  const [page, setPage] =
    useState<Page>("dashboard");

  const [entries, setEntries] =
    useState<JournalEntry[]>([]);

  const [tasks, setTasks] =
    useState<TodoTask[]>([]);

  const [databaseReady, setDatabaseReady] =
    useState(false);

  const [securityState, setSecurityState] =
    useState<SecurityState>("loading");

  const [securityError, setSecurityError] =
    useState("");

  const [editingEntry, setEditingEntry] =
    useState<JournalEntry | null>(null);

  const [isCreating, setIsCreating] =
    useState(false);

  /*
   * Initialize the database first.
   *
   * IMPORTANT:
   * We intentionally do NOT load journal entries
   * or tasks here.
   *
   * The app checks whether a master password exists,
   * then waits for authentication before loading
   * private data.
   */
  useEffect(() => {
    async function initializeApp() {
      try {
        await initializeDatabase();

        setDatabaseReady(true);

        const passwordHash =
          await getMasterPasswordHash();

        if (passwordHash) {
          setSecurityState("locked");
        } else {
          setSecurityState("setup");
        }
      } catch (error) {
        console.error(
          "Failed to initialize application:",
          error,
        );

        setSecurityError(
          "Failed to initialize the application.",
        );

        setSecurityState("error");
      }
    }

    void initializeApp();
  }, []);

  /*
   * Load private application data only after
   * successful authentication.
   */
  async function loadPrivateData() {
    if (!databaseReady) {
      return;
    }

    try {
      const savedEntries =
        await getJournalEntries();

      const savedTasks =
        await getTasks();

      setEntries(savedEntries);
      setTasks(savedTasks);

      console.log(
        "Private data loaded after unlock.",
      );
    } catch (error) {
      console.error(
        "Failed to load private data:",
        error,
      );

      throw error;
    }
  }

  /*
   * First launch:
   * Create the master password.
   */
  async function handleCreatePassword(
    password: string,
    confirmPassword: string,
  ) {
    setSecurityError("");

    if (!password) {
      setSecurityError(
        "Please enter a master password.",
      );
      return;
    }

    if (password.length < 8) {
      setSecurityError(
        "Master password must be at least 8 characters.",
      );
      return;
    }

    if (password !== confirmPassword) {
      setSecurityError(
        "The passwords do not match.",
      );
      return;
    }

    try {
      /*
       * 1. Create the password verifier.
       */
      const passwordHash =
        await hashPassword(password);

      /*
       * 2. Create a separate random salt
       *    for encryption-key derivation.
       */
      const vaultSalt =
        await generateVaultSalt();

      /*
       * 3. Store both pieces of metadata.
       *
       * Neither the password nor the encryption
       * key is stored here.
       */
      await setMasterPasswordHash(
        passwordHash,
      );

      await setVaultSalt(
        vaultSalt,
      );

      /*
       * 4. Unlock the Rust vault.
       *
       * The derived AES key now lives only
       * inside Rust memory.
       */
      const unlocked =
        await unlockVault(
          password,
          passwordHash,
          vaultSalt,
        );

      if (!unlocked) {
        throw new Error(
          "Vault could not be unlocked.",
        );
      }

      /*
       * 5. Migrate any old journal entries.
       *
       * This is important for an existing
       * database created before encryption.
       */
      await migrateJournalEntriesToEncrypted();
      await migrateTasksToEncrypted();

      /*
       * 6. Only now load private data.
       */
      await loadPrivateData();

      setSecurityState(
        "unlocked",
      );

      setPage("dashboard");
    } catch (error) {
      console.error(
        "Failed to create master password:",
        error,
      );

      setSecurityError(
        "Failed to create the secure vault.",
      );
    }
  }

  /*
   * Existing installation:
   * Verify the master password.
   */
  async function handleUnlock(
    password: string,
  ) {
    setSecurityError("");

    if (!password) {
      setSecurityError(
        "Please enter your master password.",
      );
      return;
    }

    try {
      const passwordHash =
        await getMasterPasswordHash();

      if (!passwordHash) {
        setSecurityState("setup");
        return;
      }

      /*
       * Get the encryption salt.
       *
       * Existing installations may not have
       * one yet, because encryption was added
       * after the original password system.
       */
      let vaultSalt =
        await getVaultSalt();

      /*
       * Legacy installation:
       * verify password first before creating
       * its encryption salt.
       */
      if (!vaultSalt) {
        const isValid =
          await verifyPassword(
            password,
            passwordHash,
          );

        if (!isValid) {
          setSecurityError(
            "Incorrect master password.",
          );
          return;
        }

        vaultSalt =
          await generateVaultSalt();

        await setVaultSalt(
          vaultSalt,
        );
      }

      /*
       * Verify password AND derive the
       * encryption key inside the platform.
       */
      const unlocked =
        await unlockVault(
          password,
          passwordHash,
          vaultSalt,
        );

      if (!unlocked) {
        setSecurityError(
          "Incorrect master password.",
        );
        return;
      }

      /*
       * Convert old plaintext entries
       * to encrypted entries if necessary.
       */
      await migrateJournalEntriesToEncrypted();
      await migrateTasksToEncrypted();

      /*
       * Only after encryption key exists
       * do we load journal data.
       */
      await loadPrivateData();

      setSecurityState(
        "unlocked",
      );

      setPage("dashboard");
    } catch (error) {
      console.error(
        "Failed to unlock application:",
        error,
      );

      setSecurityError(
        "Failed to unlock the application.",
      );
    }
  }

  /*
   * Lock the application.
   *
   * We clear the in-memory journal/task state so
   * the private data isn't kept in the React state
   * while the vault is locked.
   */
  async function lockApp() {
    try {
      /*
       * Remove the encryption key from
       * the platform memory first.
       */
      await lockVault();
    } catch (error) {
      console.error(
        "Failed to lock vault:",
        error,
      );
    } finally {
      /*
       * Clear private data from React memory.
       */
      setEntries([]);
      setTasks([]);

      setEditingEntry(null);
      setIsCreating(false);

      setPage("dashboard");
      setSecurityError("");

      setSecurityState(
        "locked",
      );
    }
  }

  function openNewEntry() {
    setEditingEntry(null);
    setIsCreating(true);
    setPage("journal");
  }

  function openEntry(entry: JournalEntry) {
    setEditingEntry(entry);
    setIsCreating(false);
    setPage("journal");
  }

  async function saveEntry(
    title: string,
    content: string,
    journalDate: string,
  ) {
    try {
      if (!databaseReady) {
        window.alert(
          "Database is not ready yet.",
        );
        return;
      }

      if (
        securityState !== "unlocked"
      ) {
        window.alert(
          "Please unlock the journal first.",
        );
        return;
      }

      if (editingEntry) {
        await updateJournalEntry(
          editingEntry.id,
          title,
          content,
          journalDate,
        );
      } else {
        await createJournalEntry(
          title,
          content,
          journalDate,
        );
      }

      const updatedEntries =
        await getJournalEntries();

      setEntries(updatedEntries);

      setEditingEntry(null);
      setIsCreating(false);
      setPage("journal");
    } catch (error) {
      console.error(
        "Failed to save journal entry:",
        error,
      );

      window.alert(
        "Failed to save the journal entry. Check the console for details.",
      );
    }
  }

  async function deleteEntry(
    id: string,
  ) {
    const confirmed = window.confirm(
      "Delete this journal entry? This cannot be undone.",
    );

    if (!confirmed) {
      return;
    }

    try {
      await deleteJournalEntry(id);

      const updatedEntries =
        await getJournalEntries();

      setEntries(updatedEntries);

      setEditingEntry(null);
      setIsCreating(false);
      setPage("journal");
    } catch (error) {
      console.error(
        "Failed to delete journal entry:",
        error,
      );

      window.alert(
        "Failed to delete the journal entry. Check the console for details.",
      );
    }
  }

  function closeEditor() {
    setEditingEntry(null);
    setIsCreating(false);
  }

  async function handleToggleTask(
    id: string,
    completed: boolean,
  ) {
    try {
      await toggleTask(
        id,
        completed,
      );

      const updatedTasks =
        await getTasks();

      setTasks(updatedTasks);
    } catch (error) {
      console.error(
        "Failed to toggle task:",
        error,
      );

      window.alert(
        "Failed to update the task.",
      );
    }
  }

  function goToDashboard() {
    closeEditor();
    setPage("dashboard");
  }

  function goToJournal() {
    closeEditor();
    setPage("journal");
  }

  function goToTodos() {
    closeEditor();
    setPage("todos");
  }

  function goToSettings() {
    closeEditor();
    setPage("settings");
  }

  /*
   * Application initialization screen.
   */
  if (
    securityState === "loading"
  ) {
    return (
      <div className="security-screen">
        <div className="security-card">
          <div className="security-brand">
            <div className="brand-icon">
              J
            </div>

            <span>Journal</span>
          </div>

          <p className="security-status">
            Initializing your private journal...
          </p>
        </div>
      </div>
    );
  }

  /*
   * Initialization error.
   */
  if (
    securityState === "error"
  ) {
    return (
      <div className="security-screen">
        <div className="security-card">
          <div className="security-brand">
            <div className="brand-icon">
              J
            </div>

            <span>Journal</span>
          </div>

          <h1>Something went wrong</h1>

          <p className="security-description">
            {securityError ||
              "The application could not be initialized."}
          </p>

          <button
            className="primary-button"
            onClick={() =>
              window.location.reload()
            }
          >
            Try again
          </button>
        </div>
      </div>
    );
  }

  /*
   * First-launch password setup.
   */
  if (
    securityState === "setup"
  ) {
    return (
      <PasswordSetup
        error={securityError}
        onSubmit={
          handleCreatePassword
        }
      />
    );
  }

  /*
   * Locked application.
   */
  if (
    securityState === "locked"
  ) {
    return (
      <UnlockScreen
        error={securityError}
        onSubmit={handleUnlock}
      />
    );
  }

  /*
   * Main application.
   */
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            J
          </div>

          <span>Journal</span>
        </div>

        <nav className="navigation">
          <button
            className={`nav-item ${
              page === "dashboard"
                ? "active"
                : ""
            }`}
            onClick={
              goToDashboard
            }
          >
            <span>⌂</span>
            Dashboard
          </button>

          <button
            className={`nav-item ${
              page === "journal"
                ? "active"
                : ""
            }`}
            onClick={
              goToJournal
            }
          >
            <span>✎</span>
            Journal
          </button>

          <button
            className={`nav-item ${
              page === "todos"
                ? "active"
                : ""
            }`}
            onClick={
              goToTodos
            }
          >
            <span>✓</span>
            To-Do
          </button>
        </nav>

        <div className="sidebar-bottom">
          <button
            className={`nav-item ${
              page === "settings"
                ? "active"
                : ""
            }`}
            onClick={
              goToSettings
            }
          >
            <span>⚙</span>
            Settings
          </button>

          <button
            className="nav-item lock-nav-item"
            onClick={lockApp}
          >
            <span>⌑</span>
            Lock
          </button>
        </div>
      </aside>

      <main className="main-content">
        {page === "dashboard" && (
          <Dashboard
            entries={entries}
            tasks={tasks}
            onNewEntry={
              openNewEntry
            }
            onOpenEntry={
              openEntry
            }
            onOpenJournal={
              goToJournal
            }
            onToggleTask={
              handleToggleTask
            }
            onOpenTodos={
              goToTodos
            }
          />
        )}

        {page === "journal" && (
          <Journal
            entries={entries}
            editingEntry={
              editingEntry
            }
            isCreating={
              isCreating
            }
            onNewEntry={
              openNewEntry
            }
            onOpenEntry={
              openEntry
            }
            onSave={saveEntry}
            onDelete={
              deleteEntry
            }
            onCancel={
              goToJournal
            }
          />
        )}

        {page === "todos" && (
          <Todos
            tasks={tasks}
            onTasksChanged={
              setTasks
            }
          />
        )}

        {page === "settings" && (
          <Settings />
        )}
      </main>
    </div>
  );
}

/* =========================
   PASSWORD SETUP
========================= */

function PasswordSetup({
  error,
  onSubmit,
}: {
  error: string;
  onSubmit: (
    password: string,
    confirmPassword: string,
  ) => Promise<void>;
}) {
  const [password, setPassword] =
    useState("");

  const [
    confirmPassword,
    setConfirmPassword,
  ] = useState("");

  const [isSubmitting, setIsSubmitting] =
    useState(false);

  async function handleSubmit(
    event: React.FormEvent,
  ) {
    event.preventDefault();

    setIsSubmitting(true);

    try {
      await onSubmit(
        password,
        confirmPassword,
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="security-screen">
      <div className="security-card">
        <div className="security-brand">
          <div className="brand-icon">
            J
          </div>

          <span>Journal</span>
        </div>

        <p className="eyebrow">
          FIRST-TIME SETUP
        </p>

        <h1>
          Create your master password
        </h1>

        <p className="security-description">
          This password protects access to
          your journal. It is not stored
          directly.
        </p>

        <form
          className="security-form"
          onSubmit={
            handleSubmit
          }
        >
          <label>
            <span>Master password</span>

            <input
              type="password"
              value={password}
              onChange={(event) =>
                setPassword(
                  event.target.value,
                )
              }
              placeholder="Enter a strong password"
              autoFocus
              autoComplete="new-password"
            />
          </label>

          <label>
            <span>
              Confirm password
            </span>

            <input
              type="password"
              value={
                confirmPassword
              }
              onChange={(event) =>
                setConfirmPassword(
                  event.target.value,
                )
              }
              placeholder="Enter the password again"
              autoComplete="new-password"
            />
          </label>

          {error && (
            <p className="security-error">
              {error}
            </p>
          )}

          <button
            className="primary-button security-submit"
            type="submit"
            disabled={
              isSubmitting
            }
          >
            {isSubmitting
              ? "Creating..."
              : "Create password"}
          </button>
        </form>

        <p className="security-note">
          Minimum 8 characters. Choose
          something you will remember —
          there is no password recovery
          mechanism yet.
        </p>
      </div>
    </div>
  );
}

/* =========================
   UNLOCK SCREEN
========================= */

function UnlockScreen({
  error,
  onSubmit,
}: {
  error: string;
  onSubmit: (
    password: string,
  ) => Promise<void>;
}) {
  const [password, setPassword] =
    useState("");

  const [isSubmitting, setIsSubmitting] =
    useState(false);

  async function handleSubmit(
    event: React.FormEvent,
  ) {
    event.preventDefault();

    setIsSubmitting(true);

    try {
      await onSubmit(password);

      setPassword("");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="security-screen">
      <div className="security-card">
        <div className="security-brand">
          <div className="brand-icon">
            J
          </div>

          <span>Journal</span>
        </div>

        <p className="eyebrow">
          PRIVATE JOURNAL
        </p>

        <h1>
          Unlock your journal
        </h1>

        <p className="security-description">
          Enter your master password to
          access your private journal.
        </p>

        <form
          className="security-form"
          onSubmit={
            handleSubmit
          }
        >
          <label>
            <span>
              Master password
            </span>

            <input
              type="password"
              value={password}
              onChange={(event) =>
                setPassword(
                  event.target.value,
                )
              }
              placeholder="Enter your password"
              autoFocus
              autoComplete="current-password"
            />
          </label>

          {error && (
            <p className="security-error">
              {error}
            </p>
          )}

          <button
            className="primary-button security-submit"
            type="submit"
            disabled={
              isSubmitting
            }
          >
            {isSubmitting
              ? "Unlocking..."
              : "Unlock"}
          </button>
        </form>

        <p className="security-note">
          Your journal remains locked until
          the correct password is entered.
        </p>
      </div>
    </div>
  );
}

/* =========================
   DASHBOARD
========================= */

function Dashboard({
  entries,
  tasks,
  onNewEntry,
  onOpenEntry,
  onOpenJournal,
  onToggleTask,
  onOpenTodos,
}: {
  entries: JournalEntry[];
  tasks: TodoTask[];
  onNewEntry: () => void;
  onOpenEntry: (
    entry: JournalEntry,
  ) => void;
  onOpenJournal: () => void;
  onToggleTask: (
    id: string,
    completed: boolean,
  ) => Promise<void>;
  onOpenTodos: () => void;
}) {
  const today = new Date();

  const dateText =
    today.toLocaleDateString(
      "en-US",
      {
        weekday: "long",
        month: "long",
        day: "numeric",
        year: "numeric",
      },
    );

  const latestEntry =
    entries[0];

  const remainingTasks =
    tasks.filter(
      (task) =>
        !task.completed,
    );

  const dashboardTasks =
    tasks.slice(0, 5);

  return (
    <>
      <header className="page-header">
        <div>
          <p className="eyebrow">
            {dateText.toUpperCase()}
          </p>

          <h1>
            Good evening, Adi
          </h1>
        </div>

        <button
          className="primary-button"
          onClick={
            onNewEntry
          }
        >
          + New Entry
        </button>
      </header>

      <div className="dashboard-grid">
        <section className="card tasks-card">
          <div className="card-header">
            <div>
              <p className="card-label">
                TODAY
              </p>

              <h2>Tasks</h2>
            </div>

            <span className="task-count">
              {
                remainingTasks.length
              }{" "}
              remaining
            </span>
          </div>

          {dashboardTasks.length ===
          0 ? (
            <div className="journal-preview">
              <p className="empty-text">
                No tasks yet.
              </p>
            </div>
          ) : (
            <div className="task-list">
              {dashboardTasks.map(
                (task) => (
                  <Task
                    key={
                      task.id
                    }
                    task={
                      task
                    }
                    onToggle={
                      onToggleTask
                    }
                  />
                ),
              )}
            </div>
          )}

          <button
            className="text-button"
            onClick={
              onOpenTodos
            }
          >
            View all tasks →
          </button>
        </section>

        <section className="card journal-card">
          <div className="card-header">
            <div>
              <p className="card-label">
                JOURNAL
              </p>

              <h2>
                Today's Entry
              </h2>
            </div>
          </div>

          {latestEntry ? (
            <>
              <div className="dashboard-entry-preview">
                <h3>
                  {
                    latestEntry.title
                  }
                </h3>

                <p>
                  {latestEntry
                    .content
                    .length >
                  180
                    ? `${latestEntry.content.substring(
                        0,
                        180,
                      )}...`
                    : latestEntry.content}
                </p>
              </div>

              <button
                className="primary-button"
                onClick={() =>
                  onOpenEntry(
                    latestEntry,
                  )
                }
              >
                Open entry
              </button>
            </>
          ) : (
            <>
              <div className="journal-preview">
                <p className="empty-text">
                  You haven't
                  written
                  anything
                  yet.
                </p>
              </div>

              <button
                className="primary-button"
                onClick={
                  onNewEntry
                }
              >
                Write today's
                entry
              </button>
            </>
          )}
        </section>
      </div>

      <section className="recent-section">
        <div className="section-header">
          <div>
            <p className="card-label">
              HISTORY
            </p>

            <h2>
              Recent entries
            </h2>
          </div>

          {entries.length >
            0 && (
            <button
              className="text-button"
              onClick={
                onOpenJournal
              }
            >
              View journal →
            </button>
          )}
        </div>

        {entries.length ===
        0 ? (
          <div className="empty-history">
            <div className="empty-icon">
              ✎
            </div>

            <h3>
              Your thoughts
              will live here.
            </h3>

            <p>
              Start writing your
              first journal entry
              and build your
              private timeline.
            </p>
          </div>
        ) : (
          <div className="recent-entries">
            {entries
              .slice(0, 5)
              .map(
                (entry) => (
                  <button
                    key={
                      entry.id
                    }
                    className="recent-entry"
                    onClick={() =>
                      onOpenEntry(
                        entry,
                      )
                    }
                  >
                    <div>
                      <h3>
                        {
                          entry.title
                        }
                      </h3>

                      <p>
                        {entry
                          .content
                          .length >
                        100
                          ? `${entry.content.substring(
                              0,
                              100,
                            )}...`
                          : entry.content}
                      </p>
                    </div>

                    <span>
                      {formatJournalDate(
                        entry.journalDate,
                      )}
                    </span>
                  </button>
                ),
              )}
          </div>
        )}
      </section>
    </>
  );
}

/* =========================
   JOURNAL
========================= */

function Journal({
  entries,
  editingEntry,
  isCreating,
  onNewEntry,
  onOpenEntry,
  onSave,
  onDelete,
  onCancel,
}: {
  entries: JournalEntry[];
  editingEntry:
    | JournalEntry
    | null;
  isCreating: boolean;
  onNewEntry: () => void;
  onOpenEntry: (
    entry: JournalEntry,
  ) => void;
  onSave: (
    title: string,
    content: string,
    journalDate: string,
  ) => Promise<void>;
  onDelete: (
    id: string,
  ) => Promise<void>;
  onCancel: () => void;
}) {
  const [
    searchTerm,
    setSearchTerm,
  ] = useState("");

  if (
    isCreating ||
    editingEntry
  ) {
    return (
      <JournalEditor
        entry={editingEntry}
        onSave={onSave}
        onDelete={onDelete}
        onCancel={onCancel}
      />
    );
  }

  const normalizedSearchTerm =
    searchTerm
      .trim()
      .toLowerCase();

  const filteredEntries =
    normalizedSearchTerm
      ? entries.filter(
          (entry) => {
            const title =
              entry.title.toLowerCase();

            const content =
              entry.content.toLowerCase();

            return (
              title.includes(
                normalizedSearchTerm,
              ) ||
              content.includes(
                normalizedSearchTerm,
              )
            );
          },
        )
      : entries;

  return (
    <>
      <header className="page-header">
        <div>
          <p className="eyebrow">
            YOUR PRIVATE SPACE
          </p>

          <h1>Journal</h1>
        </div>

        <button
          className="primary-button"
          onClick={
            onNewEntry
          }
        >
          + New Entry
        </button>
      </header>

      {entries.length >
        0 && (
        <div className="journal-search">
          <span className="search-icon">
            ⌕
          </span>

          <input
            type="text"
            placeholder="Search your journal..."
            value={
              searchTerm
            }
            onChange={(
              event,
            ) =>
              setSearchTerm(
                event.target
                  .value,
              )
            }
          />

          {searchTerm && (
            <button
              className="search-clear"
              onClick={() =>
                setSearchTerm(
                  "",
                )
              }
              aria-label="Clear search"
            >
              ×
            </button>
          )}
        </div>
      )}

      {entries.length ===
      0 ? (
        <div className="empty-journal">
          <div className="large-icon">
            ✎
          </div>

          <h2>
            Your journal is
            empty
          </h2>

          <p>
            This is your private
            space. Write down
            whatever is on your
            mind.
          </p>

          <button
            className="primary-button"
            onClick={
              onNewEntry
            }
          >
            Write your first
            entry
          </button>
        </div>
      ) : filteredEntries.length ===
        0 ? (
        <div className="empty-journal search-empty">
          <div className="large-icon">
            ⌕
          </div>

          <h2>
            No entries found
          </h2>

          <p>
            Nothing matches "
            {searchTerm}".
          </p>

          <button
            className="secondary-button"
            onClick={() =>
              setSearchTerm(
                "",
              )
            }
          >
            Clear search
          </button>
        </div>
      ) : (
        <>
          {normalizedSearchTerm && (
            <p className="search-results-count">
              {
                filteredEntries.length
              }{" "}
              {filteredEntries.length ===
              1
                ? "entry"
                : "entries"}{" "}
              found
            </p>
          )}

          <div className="journal-list">
            {filteredEntries.map(
              (entry) => (
                <button
                  key={
                    entry.id
                  }
                  className="journal-list-item"
                  onClick={() =>
                    onOpenEntry(
                      entry,
                    )
                  }
                >
                  <div className="journal-list-date">
                    {formatJournalDate(
                      entry.journalDate,
                    )}
                  </div>

                  <div className="journal-list-content">
                    <h2>
                      {
                        entry.title
                      }
                    </h2>

                    <p>
                      {entry
                        .content
                        .length >
                      180
                        ? `${entry.content.substring(
                            0,
                            180,
                          )}...`
                        : entry.content}
                    </p>
                  </div>

                  <span className="entry-arrow">
                    →
                  </span>
                </button>
              ),
            )}
          </div>
        </>
      )}
    </>
  );
}

/* =========================
   JOURNAL EDITOR
========================= */

function JournalEditor({
  entry,
  onSave,
  onDelete,
  onCancel,
}: {
  entry:
    | JournalEntry
    | null;
  onSave: (
    title: string,
    content: string,
    journalDate: string,
  ) => Promise<void>;
  onDelete: (
    id: string,
  ) => Promise<void>;
  onCancel: () => void;
}) {
  const [title, setTitle] =
    useState(
      entry?.title ?? "",
    );

  const [content, setContent] =
    useState(
      entry?.content ?? "",
    );

  const [
    journalDate,
    setJournalDate,
  ] = useState(
    entry?.journalDate ??
      new Date()
        .toISOString()
        .split("T")[0],
  );

  const isEditing =
    Boolean(entry);

  function handleSave() {
    const cleanTitle =
      title.trim();

    const cleanContent =
      content.trim();

    if (!cleanTitle) {
      window.alert(
        "Please enter a title.",
      );
      return;
    }

    if (!cleanContent) {
      window.alert(
        "Please write something in your journal.",
      );
      return;
    }

    if (!journalDate) {
      window.alert(
        "Please select an entry date.",
      );
      return;
    }

    void onSave(
      cleanTitle,
      cleanContent,
      journalDate,
    );
  }

  return (
    <div className="editor-page">
      <header className="editor-header">
        <button
          className="back-button"
          onClick={
            onCancel
          }
        >
          ← Back to journal
        </button>

        <div className="editor-actions">
          {entry && (
            <button
              className="danger-button"
              onClick={() =>
                void onDelete(
                  entry.id,
                )
              }
            >
              Delete
            </button>
          )}

          <button
            className="secondary-button"
            onClick={
              onCancel
            }
          >
            Cancel
          </button>

          <button
            className="primary-button"
            onClick={
              handleSave
            }
          >
            {isEditing
              ? "Save changes"
              : "Save entry"}
          </button>
        </div>
      </header>

      <div className="editor-container">
        <p className="eyebrow">
          {isEditing
            ? "EDITING ENTRY"
            : "NEW JOURNAL ENTRY"}
        </p>

        <input
          className="title-input"
          type="text"
          placeholder="Give your entry a title..."
          value={title}
          onChange={(
            event,
          ) =>
            setTitle(
              event.target
                .value,
            )
          }
          autoFocus
        />

        <div className="editor-meta">
          <label className="date-field">
            <span>
              Entry date
            </span>

            <input
              type="date"
              value={
                journalDate
              }
              onChange={(
                event,
              ) =>
                setJournalDate(
                  event.target
                    .value,
                )
              }
            />
          </label>

          <span>
            {entry
              ? `Created ${formatDate(
                  entry.createdAt,
                )}`
              : "Write whatever is on your mind."}
          </span>
        </div>

        <textarea
          className="journal-editor"
          placeholder="Start writing..."
          value={
            content
          }
          onChange={(
            event,
          ) =>
            setContent(
              event.target
                .value,
            )
          }
        />

        <div className="editor-footer">
          <span>
            {content.length}{" "}
            characters
          </span>

          <span>
            Your entry is stored
            locally in SQLite.
          </span>
        </div>
      </div>
    </div>
  );
}

/* =========================
   TASK
========================= */

function Task({
  task,
  onToggle,
}: {
  task: TodoTask;
  onToggle: (
    id: string,
    completed: boolean,
  ) => Promise<void>;
}) {
  async function handleToggle() {
    try {
      await onToggle(
        task.id,
        !task.completed,
      );
    } catch (error) {
      console.error(
        "Failed to toggle task:",
        error,
      );

      window.alert(
        "Failed to update the task.",
      );
    }
  }

  return (
    <div
      className={`task ${
        task.completed
          ? "completed"
          : ""
      }`}
    >
      <button
        className="checkbox"
        onClick={() =>
          void handleToggle()
        }
        aria-label={
          task.completed
            ? `Mark ${task.title} as incomplete`
            : `Mark ${task.title} as complete`
        }
      >
        {task.completed
          ? "✓"
          : ""}
      </button>

      <span>
        {task.title}
      </span>
    </div>
  );
}

/* =========================
   TODO PAGE
========================= */

function Todos({
  tasks,
  onTasksChanged,
}: {
  tasks: TodoTask[];
  onTasksChanged: (
    tasks: TodoTask[],
  ) => void;
}) {
  const [
    newTaskTitle,
    setNewTaskTitle,
  ] = useState("");

  const [
    isAdding,
    setIsAdding,
  ] = useState(false);

  const remainingTasks =
    tasks.filter(
      (task) =>
        !task.completed,
    );

  const completedTasks =
    tasks.filter(
      (task) =>
        task.completed,
    );

  async function handleAddTask() {
    const title =
      newTaskTitle.trim();

    if (!title) {
      return;
    }

    try {
      await createTask(
        title,
      );

      const updatedTasks =
        await getTasks();

      onTasksChanged(
        updatedTasks,
      );

      setNewTaskTitle("");
      setIsAdding(false);
    } catch (error) {
      console.error(
        "Failed to create task:",
        error,
      );

      window.alert(
        "Failed to create the task.",
      );
    }
  }

  async function handleToggle(
    id: string,
    completed: boolean,
  ) {
    try {
      await toggleTask(
        id,
        completed,
      );

      const updatedTasks =
        await getTasks();

      onTasksChanged(
        updatedTasks,
      );
    } catch (error) {
      console.error(
        "Failed to update task:",
        error,
      );

      window.alert(
        "Failed to update the task.",
      );
    }
  }

  async function handleDelete(
    id: string,
  ) {
    const confirmed =
      window.confirm(
        "Delete this task? This cannot be undone.",
      );

    if (!confirmed) {
      return;
    }

    try {
      await deleteTask(id);

      const updatedTasks =
        await getTasks();

      onTasksChanged(
        updatedTasks,
      );
    } catch (error) {
      console.error(
        "Failed to delete task:",
        error,
      );

      window.alert(
        "Failed to delete the task.",
      );
    }
  }

  return (
    <>
      <header className="page-header">
        <div>
          <p className="eyebrow">
            STAY ORGANIZED
          </p>

          <h1>To-Do</h1>
        </div>

        <button
          className="primary-button"
          onClick={() =>
            setIsAdding(
              true,
            )
          }
        >
          + Add task
        </button>
      </header>

      {isAdding && (
        <div className="card task-add-card">
          <input
            className="task-input"
            type="text"
            placeholder="What needs to be done?"
            value={
              newTaskTitle
            }
            onChange={(
              event,
            ) =>
              setNewTaskTitle(
                event.target
                  .value,
              )
            }
            onKeyDown={(
              event,
            ) => {
              if (
                event.key ===
                "Enter"
              ) {
                void handleAddTask();
              }

              if (
                event.key ===
                "Escape"
              ) {
                setNewTaskTitle(
                  "",
                );

                setIsAdding(
                  false,
                );
              }
            }}
            autoFocus
          />

          <div className="editor-actions">
            <button
              className="secondary-button"
              onClick={() => {
                setNewTaskTitle(
                  "",
                );

                setIsAdding(
                  false,
                );
              }}
            >
              Cancel
            </button>

            <button
              className="primary-button"
              onClick={() =>
                void handleAddTask()
              }
            >
              Add task
            </button>
          </div>
        </div>
      )}

      <section className="todo-section">
        <div className="section-header">
          <div>
            <p className="card-label">
              OPEN
            </p>

            <h2>
              {
                remainingTasks.length
              }{" "}
              remaining
            </h2>
          </div>
        </div>

        {remainingTasks.length ===
        0 ? (
          <div className="empty-history">
            <div className="empty-icon">
              ✓
            </div>

            <h3>
              Nothing left to
              do.
            </h3>

            <p>
              Add a task when
              something needs your
              attention.
            </p>
          </div>
        ) : (
          <div className="todo-list">
            {remainingTasks.map(
              (task) => (
                <div
                  className="todo-item"
                  key={
                    task.id
                  }
                >
                  <Task
                    task={
                      task
                    }
                    onToggle={
                      handleToggle
                    }
                  />

                  <button
                    className="delete-task-button"
                    onClick={() =>
                      void handleDelete(
                        task.id,
                      )
                    }
                  >
                    Delete
                  </button>
                </div>
              ),
            )}
          </div>
        )}
      </section>

      {completedTasks.length >
        0 && (
        <section className="todo-section">
          <div className="section-header">
            <div>
              <p className="card-label">
                COMPLETED
              </p>

              <h2>
                {
                  completedTasks.length
                }{" "}
                completed
              </h2>
            </div>
          </div>

          <div className="todo-list">
            {completedTasks.map(
              (task) => (
                <div
                  className="todo-item"
                  key={
                    task.id
                  }
                >
                  <Task
                    task={
                      task
                    }
                    onToggle={
                      handleToggle
                    }
                  />

                  <button
                    className="delete-task-button"
                    onClick={() =>
                      void handleDelete(
                        task.id,
                      )
                    }
                  >
                    Delete
                  </button>
                </div>
              ),
            )}
          </div>
        </section>
      )}
    </>
  );
}

/* =========================
   SETTINGS
========================= */

function Settings() {
  return (
    <>
      <header className="page-header">
        <div>
          <p className="eyebrow">
            APP CONFIGURATION
          </p>

          <h1>Settings</h1>
        </div>
      </header>

      <div className="placeholder-page">
        <div className="large-icon">
          ⚙
        </div>

        <h2>Settings</h2>

        <p>
          Privacy, security,
          appearance, and backup
          settings will go here.
        </p>
      </div>
    </>
  );
}

/* =========================
   HELPERS
========================= */

function formatDate(
  dateString: string,
) {
  return new Date(
    dateString,
  ).toLocaleDateString(
    "en-US",
    {
      month: "short",
      day: "numeric",
      year: "numeric",
    },
  );
}

function formatJournalDate(
  dateString: string,
) {
  return new Date(
    `${dateString}T00:00:00`,
  ).toLocaleDateString(
    "en-US",
    {
      month: "short",
      day: "numeric",
      year: "numeric",
    },
  );
}

export default App;