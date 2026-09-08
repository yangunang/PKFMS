# Credentials Page (Flask)

A self-hosted personal vault: an editable Environment / Account / Password
table plus a file locker and a journal, protected by a master password +
TOTP two-factor authentication, with sensitive data encrypted at rest.

## Features

**Credentials** (`/`)
- Columns: account info · Account · Password · Environment
- Rows locked by default — ✎ unlocks a row for inline editing and deletion,
  ✓ locks it again; changes save automatically
- Password masking with show/hide toggle; sort by Account or Environment
- User-defined environments (defaults: home, work, personal, finance) via
  the ⚙ panel; color badges everywhere; removal blocked while in use
- Filtering by environment also shows that environment's files inline
- 📄 per-account **description page** with Markdown (headings, bold/italic,
  `code`, lists, links, code blocks), autosaved and encrypted
- 📁 per-account **files page**: upload and download files that belong to
  that account only — accounts in the same environment keep separate,
  independent file sets
- Export everything to Excel — the downloaded `credentials.xlsx` is
  **password-protected with your master password** (standard OOXML/AES
  encryption): you re-enter it to start the export, and Excel / LibreOffice /
  Numbers prompt for the same password when opening the file

**Files** (`/files`)
- Upload / download / delete arbitrary files; unlock-to-edit like rows
- Tagged by environment + customizable file category (defaults: img, video, docx)
- 📄 per-file description page (Markdown, encrypted) with **tags** drawn
  from Credentials accounts

**Journal** (`/notes`)
- Blog-style entries under customizable categories (defaults: work,
  daily expenses, mood journal), tagged with an environment
- Bodies render as Markdown when locked; ✎ to edit the raw text
- Titles and bodies encrypted at rest

**General**
- UI in English, French, German, Spanish, Japanese, Chinese (🌐 selector)
- Single user, session-based; the lock button logs out immediately

## Build & run with Docker

Build the image (from this directory):

    docker build -t credentials-page .

Run it, persisting all data to a local `./data` directory:

    docker run -d \
      --name credentials-page \
      -p 5000:5000 \
      -v "$(pwd)/data:/data" \
      credentials-page

Open http://localhost:5000.
Windows (PowerShell): use `-v "${PWD}\data:/data"`.

Lifecycle:

    docker stop credentials-page      # stop
    docker start credentials-page     # start again (data intact)
    docker rm -f credentials-page     # remove container (data survives in ./data)

Restarting clears login sessions (just log in again); everything in `./data`
is untouched. To update: rebuild the image, remove the container, run again
with the same `-v` mount.

Without Docker:

    pip install -r requirements.txt
    python app.py          # http://127.0.0.1:5000  (data in ./data)

## Account, 2FA, and recovery

**First run** — there is no default account. The first visit runs setup:

1. Set a **master password** (min 8 characters; stored only as a PBKDF2 hash).
2. **Enable 2FA** — a QR code pops up; scan it with Google Authenticator /
   Authy / 1Password, or enter the printed secret manually. The secret is
   shown only once — save it somewhere safe.
3. **Verify** — enter the current 6-digit code from the app once, to
   confirm the scan worked. Setup only completes after a valid code
   (reloading the page brings the QR step back until then).
4. Log in: master password, then the current 6-digit code.

**Lost your authenticator (2FA)?** One command issues a fresh secret and
prints a scannable QR code in the terminal; password and data are untouched:

    docker exec -it credentials-page flask reset-2fa
    # or locally: flask reset-2fa

The app then asks for one code on the next visit to confirm the new secret.

**Lost the master password?** Also recoverable — the data-encryption key is
not derived from the password (see below):

    docker exec -it credentials-page flask reset-password
    # or locally: flask reset-password

It prompts for a new password (twice); all encrypted data stays readable.

**Start over completely** (deletes the account and ALL data, after a
confirmation prompt):

    docker exec -it credentials-page flask factory-reset

### Security model

- The Fernet data key is derived (PBKDF2-SHA256, 480k iterations, random
  salt) from the `key` field in `./data/config.json`, generated on first
  run with file mode 600. The master password only gates access — which is
  why it can be reset without data loss.
- ⚠ That makes `config.json` the real secret: anyone holding the `./data`
  directory can decrypt the database. Keep it private and backed up — if
  `config.json` is lost, the encrypted data is gone for good.
- Encrypted at rest: account, password, info, and descriptions on the
  credentials page; file descriptions; journal titles and bodies.
  Plaintext by design: environment/category names, filenames, tags (needed
  for badges, sorting, and filtering), and uploaded file contents.
- 2FA is standard TOTP (RFC 6238), 30-second codes. Sessions and derived
  keys live only in server memory, never on disk or in cookies.
- This is a personal tool. If you expose it beyond localhost, put it
  behind HTTPS (e.g. a reverse proxy).

## Data layout & backup

Everything lives in the mounted `./data` directory:

    data/
      config.json          ← encryption key (mode 600) — CRITICAL to back up
      credentials.db       ← SQLite: credentials, journal, file metadata
                             (sensitive columns are Fernet ciphertext)
      uploads/2026/07/…    ← uploaded files, organized by year/month,
                             stored under their ORIGINAL Unicode names
                             (only path separators / unsafe chars stripped;
                             "(1)", "(2)"… suffix on collisions)

Journal entries are not files — they are encrypted rows inside
`credentials.db`, readable only through the app.

**Backup = copy the `./data` directory** (ideally while the container is
stopped, so SQLite is quiescent):

    docker stop credentials-page
    tar czf vault-backup-$(date +%F).tar.gz data/
    docker start credentials-page

Restore by extracting the archive back to `./data` and starting the
container. A backup is only decryptable with its own `config.json`, so keep
the archive as protected as the live directory. Back up regularly and after
big edits; `config.json` changes never, so any copy of it works with any
database snapshot that used it.

## Languages

Switch with the 🌐 selector (also on the login page); the choice persists in
the session. Translations live in `i18n.py` — to add a language, add a code
to `LANGS` and a dictionary to `TRANSLATIONS`.
