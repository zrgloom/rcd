# rcd — Remote Command Distribution

`rcd.py` distributes command sequences across multiple network devices over SSH or Telnet. It was originally written as a Tcl/Expect script (`rcd.exp`) and has been rewritten in Python using [pexpect](https://pexpect.readthedocs.io/) and [click](https://click.palletsprojects.com/).

Primary use cases: pushing IOS configuration, backing up startup/running configs to a TFTP server, and performing device upgrades across Cisco (and compatible) equipment. Any device reachable via SSH or Telnet with a password prompt should work.

**Platform support:** Linux only. Runs natively on Linux and under WSL (Windows Subsystem for Linux); native Windows is not supported.

### Features

- **SSH and Telnet** transport, driven by an interactive expect/send command file
- **Variables** — host-file columns (`$colname`) and regex capture groups (`$1`–`$n`) substituted into command files
- **Dynamic variables** — values queried from the device (or piped through a shell command) at runtime via the `cmd:` prefix
- **Loop control** — `LOOP`/`ENDLOOP` iterates over pipe-separated lists without reconnecting, and loops may be nested
- **IP ranges** — `lo-hi` octet ranges in the host file expand to multiple targets
- **Password management** — plain text, a file path, or a `keyring:` reference, with `--otp` support for TOTP-backed logins

---

## Install

Install directly from GitHub with pip (pulls in `click` and `pexpect` automatically):

```
pip install git+https://github.com/zrgloom/rcd.git
```

Or clone the repository and install from a local checkout:

```
git clone https://github.com/zrgloom/rcd.git
cd rcd
pip install .
```

Either method registers an `rcd` command on your `PATH` and installs the man page alongside it (see [Man Page](#man-page)). Add the `keyring` extra if you want `keyring:`-based password storage:

```
pip install "rcd[keyring] @ git+https://github.com/zrgloom/rcd.git"
```

### Install with pipx

[pipx](https://pypa.github.io/pipx/) installs `rcd` into its own isolated virtual environment while still exposing the `rcd` command on your `PATH` — useful if you don't want it mixed into a system or project Python environment:

```
pipx install git+https://github.com/zrgloom/rcd.git
```

Add the `keyring` extra the same way as with pip:

```
pipx install "rcd[keyring] @ git+https://github.com/zrgloom/rcd.git"
```

If you already have the `keyring` library (and a working backend, e.g. `python3-secretstorage`) installed via your system package manager, pass `--system-site-packages` so pipx's virtual environment can see it instead of installing a separate copy:

```
pipx install --system-site-packages git+https://github.com/zrgloom/rcd.git
```

---

## Requirements

```
pip install click pexpect
pip install keyring          # optional — only needed for keyring password storage
```

---

## Usage

```
rcd -h <hostfile> [OPTIONS] [-colname value ...]
```

| Option | Default | Description |
|---|---|---|
| `-h <hostfile>` | *(required)* | CSV host file listing target devices |
| `-t <seconds>` | `30` | Expect timeout per command |
| `--otp` | off | Wait out the 30-second TOTP window before retrying a failed login |
| `--login-failure-limit <n>` | `2` | Max login attempts per device before skipping |
| `-colname value` | — | Supply or override any host-file column on the command line |
| `--man` | — | Show the man page and exit |

Use `--help` for the built-in help text.

---

## Man Page

The man page (`man/man1/rcd.1`) is bundled with the package, so `rcd --man` (or `./rcd.py --man`) always works after `pip install` — it opens via `man` on Linux/macOS, or falls back to a plain-text pager on platforms without `man` (e.g. Windows).

`pip` has no portable way to install the page into a system man directory (e.g. `/usr/share/man/man1`), so `man rcd` won't work out of the box. To enable it on Linux/macOS:

```
sudo install -Dm644 man/man1/rcd.1 /usr/local/share/man/man1/rcd.1
sudo mandb   # or `makewhatis` / `/etc/man_db.conf`-triggered update, depending on distro
```

---

## Host File

The host file is a CSV file. The first non-comment line is the **header** (column names); every subsequent line is one device entry. Lines beginning with `#` are comments.

```
# file: hosts
ip,login,pass,enabpass,proto,tftp,cfile
192.168.20.10,root,topsecret,topsecret,ssh,,./cisco.generic
192.168.10.55,root,topsecret,topsecret,ssh,,./cisco.generic
```

Omitted values fall back to the matching `-colname value` argument supplied on the command line. In the example above `tftp` is blank for every device, so it is supplied once:

```
./rcd.py -h hosts -tftp 192.168.254.100
```

### Mandatory columns

| Column | Description |
|---|---|
| `ip` | IP address (or range — see below) |
| `login` | Login name for SSH/Telnet authentication |
| `pass` | Password (see [Password management](#password-management)) |
| `proto` | Transport protocol: `ssh` or `telnet` |
| `cfile` | Path to the command file to execute on this device |

### IP ranges

Any octet can be written as `lo-hi`. All combinations are expanded, with the rightmost octet changing fastest:

```
192.168.20-21.1-3  →  192.168.20.1, 192.168.20.2, 192.168.20.3,
                       192.168.21.1, 192.168.21.2, 192.168.21.3
```

### User-defined columns

Any additional column becomes a `$variable` available in the command file. Common examples: `enabpass`, `tftp`, `contexts`, `intname`.

### Password management

The `pass` column accepts three forms:

| Form | Example | How it works |
|---|---|---|
| Plain text | `topsecret` | Used directly |
| File path | `/etc/rcd/pw.txt` | First line of the file is used |
| Keyring | `keyring:myservice` | Fetched via the Python `keyring` CLI |

The keyring backend defaults to `keyring.backends.libsecret.Keyring` (passwords stored in `~/.local/share/keyrings/`). For TOTP/OTP tokens stored in the keyring, use `--otp` so that rcd waits out the remainder of the current 30-second window before retrying after a failed login.

Enable passwords must be stored as plain text in the host file, or AAA authorization must be configured to enter privileged mode automatically.

---

## Command File

The command file drives the interactive session after login. Lines alternate strictly between **expect** and **send** roles:

- **Odd lines (1, 3, 5, …)** — expect patterns (Python regular expressions)
- **Even lines (2, 4, 6, …)** — text to send to the device

Blank send lines press Enter (useful for accepting default prompts). Lines beginning with `#` are comments. Variable references (`$colname`, `$1`–`$n`) are substituted before each line is processed.

Capture groups in expect patterns populate `$1`, `$2`, … for use in subsequent lines:

```
# file: cisco.pix
.*>
enable
[Pp]assword:
$enabpass
(\w+)#
write net $tftp:$1
.*#
logout
```

Here `(\w+)#` captures the device hostname into `$1`, which is then used in the `write net` command.

---

## LOOP / ENDLOOP

`LOOP` iterates over a pipe-separated list variable without reconnecting. The loop body follows the same expect/send alternation. After `ENDLOOP`, add an explicit expect to catch the last iteration's output.

```
.*>
enable
[Pp]assword:
$enabpass
LOOP $contexts $ctx
.*#
changeto context $ctx
.*#
write mem
ENDLOOP
.*#
logout
```

Host file entry: `contexts = admin|dmz|inside`

Loops may be nested.

---

## Dynamic Variables

Any variable value can be populated at runtime by querying the device, using the `cmd:` prefix in the host file. The variable is resolved silently the first time it is referenced and cached for the rest of the session.

**Syntax:**

```
cmd:device_cmd1;ret_pattern1;device_cmd2;ret_pattern2;... [ | os_cmd1 | os_cmd2 ]
```

Semicolons separate command/ret_pattern pairs sent/receive to/from the device. The first ` | ` (space-pipe-space) separates the device part from an optional shell pipeline passed to `/bin/sh`. For `LOOP` variables, output lines are joined with `|`.

**Examples:**

```
contexts = cmd:changeto system;.*#;show run context;.*# | grep '^context' | awk '{print $2}'
intname  = cmd:show run interface;.*# | grep nameif | awk '{print $2}'
```

Dynamic variables work in send lines, expect patterns, and `LOOP` list variables.

---

## Warning

Always test your command file on a lab device before running it in production. A mistake can leave devices in an unreachable state.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
