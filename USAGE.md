# Note: An llm wrote the following documentation, as documentation is not marked, i thought it would be useful to let it read the code and assist with usage. 

# Cadmus usage

Cadmus is a small local CLI for registering users, logging in, and storing encrypted documents with simple sharing rules.

Everything lives in the directory where you run the command. If you run `cadmus` in a different folder, you are using a different local store.

## Build and run

Build the binary from the repo root:

```sh
make
```

That creates a binary called `cadmus`.

From the repo root, run commands like this:

```sh
./cadmus --help
./cadmus auth register alice
./cadmus file list
```

## Command shape

General form:

```sh
cadmus <group> <subcommand> [args] [flags]
```

Groups:

- `auth`
- `file`

Top level help:

```sh
./cadmus --help
```

## Global flags

| Flag | Meaning |
| --- | --- |
| `-h`, `--help` | Show help |
| `-v`, `--verbose` | Enable debug logging |

Notes:

- `-v` is accepted on any command, but the current codebase does not emit extra debug output yet.
- `./cadmus auth -h` and `./cadmus file -h` print the group help.

## Auth commands

### `auth register`

Create a new local user.

```sh
./cadmus auth register <username>
```

Example:

```sh
./cadmus auth register alice
```

What happens:

- Cadmus prompts for a password on standard error.
- On success it prints:

```text
registered alice
```

Notes:

- Usernames cannot be empty.
- Usernames cannot contain `:` or line breaks.
- Usernames must be shorter than 64 characters.

### `auth login`

Log in as an existing user and create a local session file.

```sh
./cadmus auth login <username>
```

Example:

```sh
./cadmus auth login alice
```

On success:

```text
logged in as alice
```

Notes:

- You will be prompted for a password.
- File commands that touch documents require a valid login.

### `auth logout`

Remove the current local session.

```sh
./cadmus auth logout
```

On success:

```text
logged out
```

## File commands

### `file upload`

Encrypt a file, store it as an `.edoc` document, and print the new document ID.

```sh
./cadmus file upload <filepath> [-d]
```

Example:

```sh
./cadmus file upload report.txt
```

Example with delete-after-upload:

```sh
./cadmus file upload report.txt -d
```

What happens:

- You must be logged in first.
- Cadmus reads the file, optionally compresses it, encrypts it, writes a new `cadmus_doc_<doc_id>.edoc` file, and adds it to the index.
- On success it prints only the document ID, for example:

```text
00000004
```

Notes:

- Document IDs are 8 character lowercase hex strings.
- The stored filename is the basename only, not the full original path.
- `-d` deletes the original file after a successful upload.

### `file read`

Decrypt a stored document and write the original file contents to standard output.

```sh
./cadmus file read <doc_id>
```

Example:

```sh
./cadmus file read 00000004
```

Save the output back to a file:

```sh
./cadmus file read 00000004 > restored_report.txt
```

Notes:

- You must be logged in.
- You need `read` permission for that document.
- This command writes raw file bytes to standard output, so shell redirection is the normal way to save the result.

### `file share`

Grant another user access to a document.

```sh
./cadmus file share <doc_id> <username> --permission <perms>
```

Example:

```sh
./cadmus file share 00000004 bob --permission read,share
```

On success:

```text
shared 00000004 with bob
```

Valid permission names:

- `read`
- `write`
- `share`
- `delete`
- `all`

Permission format:

- Use a comma-separated list like `read,share`
- Do not put spaces inside the list

Rules:

- You must be logged in.
- The target user must already exist.
- The owner always has full access.
- To share a document, the grantor must have `share` permission.
- You cannot grant permissions you do not already have.

Note:

- `write` exists as a permission value, but there is no CLI command that uses it yet.

### `file list`

List documents visible to the current user.

```sh
./cadmus file list
```

Example output:

```text
00000002  alice  notes.txt
00000003  bob    draft.pdf
```

If nothing is visible:

```text
no documents
```

Notes:

- You must be logged in.
- This shows documents you own and documents shared with you.
- The output columns are `doc_id`, `owner`, and original filename.

### `file delete`

Delete a stored document and remove it from the index.

```sh
./cadmus file delete <doc_id>
```

Example:

```sh
./cadmus file delete 00000004
```

On success:

```text
deleted 00000004
```

Notes:

- You must be logged in.
- You need `delete` permission for that document.

## Local files Cadmus creates

Cadmus keeps all of its data in the current working directory:

| File | Purpose |
| --- | --- |
| `cadmus_users.txt` | User registry |
| `cadmus_session.bin` | Current login session |
| `cadmus_index.txt` | Document index used by `file list` |
| `cadmus_doc_<doc_id>.edoc` | Encrypted document container |

If you want one shared local store for testing, stay in the same directory for every command.

## Output and exit codes

Cadmus uses standard output for normal command output and standard error for password prompts and errors.

Examples:

- `auth register` prints `registered <username>`
- `auth login` prints `logged in as <username>`
- `auth logout` prints `logged out`
- `file upload` prints the new document ID
- `file read` prints the file contents
- `file share` prints `shared <doc_id> with <username>`
- `file list` prints matching rows or `no documents`
- `file delete` prints `deleted <doc_id>`

Exit codes:

- `0` on success
- `1` on any error

## Common errors

Cadmus prints errors in this shape:

```text
<context>: <message>
```

Examples:

- `auth login: invalid credentials`
- `file read: not authenticated`
- `file share: user not found`
- `file delete: permission denied`

Common messages:

- `invalid arguments`
- `not authenticated`
- `not found`
- `permission denied`
- `user already exists`
- `user not found`
- `invalid credentials`
- `tampered data`
- `file io error`