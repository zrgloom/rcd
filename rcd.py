#!/usr/bin/env python3
"""
rcd.py  ver 0.2.0 — Remote Command Distribution
"""

import io
import re
import shutil
import sys
import time
import subprocess
from itertools import product
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

try:
    import click
except ImportError:
    sys.exit("click is required:  pip install click")

try:
    import pexpect
except ImportError:
    sys.exit("pexpect is required:  pip install pexpect")


# ── Constants ──────────────────────────────────────────────────────────────────

MANDATORY       = {'ip', 'login', 'pass', 'proto', 'cfile'}
DEFAULT_TIMEOUT = 30
OTP_WINDOW      = 30          # seconds per TOTP token
KEYRING_BACKEND = 'keyring.backends.libsecret.Keyring'
LIST_SEP        = '|'         # separator for list variables in host file
MAN_PAGE        = Path(__file__).resolve().parent / "man" / "man1" / "rcd.1"

RED    = '\033[31;40m'
YELLOW = '\033[33;40m'
RESET  = '\033[0m'

# Type alias for a parsed command tuple.
# Variants:
#   ('expect', pattern_str)
#   ('send',   text_str)
#   ('loop',   list_var_name, item_var_name, body_commands)
CmdTuple = Union[
    Tuple[str, str],                 # 'expect' or 'send'
    Tuple[str, str, str, List[Any]], # 'loop' — body is List[CmdTuple] but recursive types need Any
]

# Mapping produced by iter_hosts; keys are host-file column names.
HostDict = Dict[str, str]


# ── IP range expansion ─────────────────────────────────────────────────────────

def expand_ip(ip_str: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """
    Expand an IP range string into a flat list of IP strings.

    Each octet may be a plain number or a lo-hi range:
        '10.0.1-3.1-254'  ->  ['10.0.1.1', '10.0.1.2', ..., '10.0.3.254']

    The last (rightmost) octet iterates fastest — same as the original.
    Returns (ip_list, None) on success or (None, error_message) on failure.
    """
    parts = ip_str.split('.')
    if len(parts) != 4:
        return None, f"'{ip_str}' is not a valid IP / IP-range"

    ranges: List[range] = []
    for p in parts:
        m = re.fullmatch(r'(\d+)-(\d+)', p)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
        elif re.fullmatch(r'\d+', p):
            lo = hi = int(p)
        else:
            return None, f"Invalid octet '{p}' in '{ip_str}'"
        if not (0 <= lo <= hi <= 255):
            return None, f"Octet range {lo}-{hi} is out of bounds in '{ip_str}'"
        ranges.append(range(lo, hi + 1))

    ips = [f"{a}.{b}.{c}.{d}" for a, b, c, d in product(*ranges)]
    return ips, None


# ── Host file parsing ──────────────────────────────────────────────────────────

def iter_hosts(
    hostfile_path: Union[str, Path],
    cli_args: Dict[str, Any],
) -> Generator[Tuple[int, Optional[HostDict], Optional[str]], None, None]:
    """
    Yield (line_no, host_dict, error) for every device entry in the host file.

    Format:
        First non-comment line  ->  comma-separated column names (header).
        Subsequent lines        ->  comma-separated values.
        Lines beginning with '#' are comments and are ignored.

    Empty fields fall back to the matching CLI argument, if one was given.
    Entries that lack mandatory fields yield (line_no, None, error_message).
    """
    lines  = Path(hostfile_path).read_text().splitlines()
    header: Optional[List[str]] = None
    lineno = 0

    for raw in lines:
        lineno += 1
        line = raw.strip()
        if not line or line.startswith('#'):
            continue

        if header is None:
            header = [h.strip() for h in line.split(',')]
            continue

        values = [v.strip() for v in line.split(',')]
        host: HostDict = {}
        for i, key in enumerate(header):
            val       = values[i] if i < len(values) else ''
            host[key] = val or cli_args.get(key, '')

        missing = [k for k in MANDATORY if not host.get(k)]
        if missing:
            yield lineno, None, f"Missing mandatory field(s): {', '.join(missing)}"
            continue

        yield lineno, host, None


# ── Password resolution ────────────────────────────────────────────────────────

def resolve_password(
    pass_spec: str,
    login: str,
    otp: bool = False,
    prev_failed: bool = False,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Resolve a password from one of three sources:

    1. Plain text  — used directly.
    2. A file path  — first line of the file is used.
    3. 'keyring:<service>'  — looked up via the Python keyring CLI.

    When otp=True and prev_failed=True the function sleeps until the current
    TOTP window expires before fetching a fresh token.

    Returns (password, None) on success or (None, error_message) on failure.
    """
    path = Path(pass_spec)
    if path.is_file():
        return path.read_text().splitlines()[0].strip(), None

    if pass_spec.lower().startswith('keyring:'):
        service = pass_spec.split(':', 1)[1]
        if otp and prev_failed:
            remaining = OTP_WINDOW - (int(time.time()) % OTP_WINDOW)
            click.echo(f"OTP cooldown — waiting {remaining}s for a new token ...", nl=False)
            time.sleep(remaining)
            click.echo(" done, retrying connection.")
        try:
            pw = subprocess.check_output(
                ['keyring', '-b', KEYRING_BACKEND, 'get', service, login],
                text=True,
            ).strip()
            return pw, None
        except subprocess.CalledProcessError as exc:
            return None, f"keyring lookup failed: {exc}"

    return pass_spec, None


# ── Command file parsing ───────────────────────────────────────────────────────
#
# Command tuples:
#   ('expect', pattern_str)
#   ('send',   text_str)
#   ('loop',   list_var_name, item_var_name, [body_commands])

_LOOP_RE    = re.compile(r'^LOOP\s+\$(\w+)\s+\$(\w+)\s*$')
_COMMENT_RE = re.compile(r'^#')


def parse_cmdfile(path: Union[str, Path]) -> List[CmdTuple]:
    """
    Parse a command file into a list of command tuples.

    Plain lines alternate between expect and send roles (same as rcd.exp).
    LOOP / ENDLOOP blocks are self-contained: they may appear wherever an
    expect line would appear, and after ENDLOOP the outer alternation
    resumes at the 'expect' position.

    Blank lines are kept — a blank send presses Enter (useful for accepting
    default prompts, as in 'copy startup tftp').
    Comment lines (starting with '#') are stripped.
    """
    raw_lines = Path(path).read_text().splitlines()
    lines     = [ln for ln in raw_lines if not _COMMENT_RE.match(ln)]
    cmds, _   = _parse_block(lines, 0)
    return cmds


def _parse_block(lines: List[str], start: int) -> Tuple[List[CmdTuple], int]:
    """
    Parse lines[start:] until EOF or an ENDLOOP token.
    Returns (command_list, next_index).
    """
    cmds: List[CmdTuple] = []
    expecting = True   # True -> next plain line is 'expect', False -> 'send'
    i         = start

    while i < len(lines):
        line = lines[i]

        if line.strip() == 'ENDLOOP':
            return cmds, i + 1

        m = _LOOP_RE.match(line.strip())
        if m:
            list_var, item_var = m.group(1), m.group(2)
            body, i = _parse_block(lines, i + 1)
            cmds.append(('loop', list_var, item_var, body))
            # After a loop block the outer alternation resumes at 'expect'.
            expecting = True
            continue

        if expecting:
            cmds.append(('expect', line))
        else:
            cmds.append(('send', line))

        expecting = not expecting
        i += 1

    if not expecting:
        click.echo(
            f"{YELLOW}Warning: command file has an unmatched expect at the end{RESET}"
        )

    return cmds, i


# ── Variable substitution ──────────────────────────────────────────────────────

def subst(text: str, variables: Dict[str, Any]) -> str:
    """
    Replace every $name reference in text with the matching entry from
    variables.  Unknown variables are left as-is.
    Numeric variables ($1, $2, ...) hold regex capture groups from the
    most recent expect match.
    """
    def replacer(m: re.Match) -> str:
        return str(variables.get(m.group(1), m.group(0)))
    return re.sub(r'\$(\w+)', replacer, text)


# ── Session ────────────────────────────────────────────────────────────────────

class Session:
    """Wraps a single pexpect child process for one device connection."""

    def __init__(self, host: HostDict, timeout: int, otp: bool = False) -> None:
        self.host       = host        # mutable dict; capture groups stored here
        self.timeout    = timeout
        self.otp        = otp         # whether to wait out the OTP window on retry
        self.child: Optional[pexpect.spawn] = None

    # ── connection / login ────────────────────────────────────────────────────

    def connect(self, prev_failed: bool = False) -> bool:
        """
        Spawn an SSH or Telnet connection and log in.
        prev_failed=True combined with otp=True triggers OTP cooldown.
        Returns True on successful authentication, False otherwise.
        """
        ip, login, proto = self.host['ip'], self.host['login'], self.host['proto']
        click.echo(f"\n{RED}Connecting to {ip}{RESET}")

        if proto == 'ssh':
            self.child = pexpect.spawn(
                f'ssh -o StrictHostKeyChecking=no '
                f'-o ConnectTimeout={self.timeout} '
                f'{login}@{ip}',
                timeout=self.timeout,
                encoding='utf-8',
            )
        else:
            self.child = pexpect.spawn(
                f'telnet {ip}',
                timeout=self.timeout,
                encoding='utf-8',
            )
        self.child.logfile_read = sys.stdout

        return self._login(prev_failed)

    def _login(self, prev_failed: bool = False) -> bool:
        ip    = self.host['ip']
        login = self.host['login']

        passwd, err = resolve_password(self.host['pass'], login, otp=self.otp, prev_failed=prev_failed)
        if err:
            click.echo(f"{YELLOW}Password error for {ip}: {err}{RESET}")
            return False

        try:
            idx = self.child.expect([
                r'[Pp]assword[: ]*',                    # 0 — SSH or 2nd Telnet prompt
                r'[Ll]ogin[: ]*|[Uu]ser[nN]ame[: ]*',  # 1 — Telnet login prompt
                pexpect.TIMEOUT,                         # 2
                pexpect.EOF,                             # 3
            ])
        except (pexpect.TIMEOUT, pexpect.EOF):
            click.echo(f"{YELLOW}No prompt received from {ip}{RESET}")
            return False

        if idx == 2:
            click.echo(f"{YELLOW}Connection to {ip} timed out{RESET}")
            return False
        if idx == 3:
            click.echo(f"{YELLOW}Connection to {ip} was refused or closed immediately{RESET}")
            return False

        if idx == 1:                     # Telnet: login name comes first
            self.child.sendline(login)
            try:
                self.child.expect(r'[Pp]assword[: ]*', timeout=self.timeout)
            except (pexpect.TIMEOUT, pexpect.EOF):
                click.echo(f"{YELLOW}No password prompt from {ip} after sending login{RESET}")
                return False

        self.child.sendline(passwd)
        try:
            self.child.expect(r'.*[>#]', timeout=self.timeout)
        except pexpect.TIMEOUT:
            click.echo(f"{YELLOW}Authentication failed on {ip} (no prompt after password){RESET}")
            return False
        except pexpect.EOF:
            click.echo(f"{YELLOW}Connection to {ip} closed after sending password{RESET}")
            return False

        # Send an empty line so the device re-displays the prompt.
        # This mirrors rcd.exp's  'send "\r"'  after the first successful
        # prompt match, ensuring the command file's first expect always has
        # a fresh prompt to match against.
        self.child.send('\r')
        return True

    # ── dynamic variable resolution ───────────────────────────────────────────

    def _resolve_dynamic_var(self, spec: str, send_refresh: bool = True) -> str:
        """
        Build a variable value at runtime by running one or more device
        commands silently and optionally filtering the output through a
        local shell pipeline.

        Syntax (after the 'cmd:' keyword):
          command1;pattern1;command2;pattern2;... [ | os_cmd1 | os_cmd2 ]

        The device part is a semicolon-separated sequence of (command,
        expect-pattern) pairs.  Each command is sent to the device; the
        matching pattern (a Python regex) marks the end of that command's
        output.  Output from all pairs is concatenated in order.

        The first ' | ' (space-pipe-space) separates the device part from
        an optional OS pipeline.  Everything after it is handed to /bin/sh
        so further pipes, awk, grep, sed, etc. work normally.

        The final list items are the non-empty output lines (after OS
        filtering), joined with LIST_SEP ('|').

        After collection a bare \\r is sent so the next expect in the
        command file has a fresh prompt to match.
        """
        # split off OS pipeline at first ' | '
        sep = spec.find(' | ')
        if sep != -1:
            device_spec = spec[:sep]
            shell_pipe: Optional[str] = spec[sep + 3:].strip()
        else:
            device_spec = spec
            shell_pipe  = None

        # parse semicolon-separated command;pattern pairs
        parts = [p.strip() for p in device_spec.split(';')]
        if len(parts) == 0 or len(parts) % 2 != 0:
            click.echo(
                f"{YELLOW}Dynamic variable: expected an even number of"
                f" command;pattern items — got {len(parts)}{RESET}"
            )
            return ''

        pairs: List[Tuple[str, str]] = [(parts[i], parts[i + 1]) for i in range(0, len(parts), 2)]

        collected: List[str] = []
        for device_cmd, pattern in pairs:
            buf = io.StringIO()
            self.child.logfile_read = buf
            try:
                self.child.sendline(device_cmd)
                # pexpect compiles patterns with re.DOTALL so '.*#' greedily
                # matches across newlines.  If a previous command's response
                # is still pending (e.g. no expect between the last send and
                # LOOP in the command file), the first match will be that
                # stale response.  Keep consuming until buf contains the echo
                # of the command we actually sent.
                while True:
                    self.child.expect(pattern, timeout=self.timeout)
                    if device_cmd in buf.getvalue():
                        break
                    buf.truncate(0)
                    buf.seek(0)
            except pexpect.TIMEOUT:
                self.child.logfile_read = sys.stdout
                click.echo(
                    f"{YELLOW}Dynamic variable: timed out waiting for"
                    f" {pattern!r} after '{device_cmd}'{RESET}"
                )
                return ''
            except pexpect.EOF:
                self.child.logfile_read = sys.stdout
                click.echo(
                    f"{YELLOW}Dynamic variable: connection closed waiting for"
                    f" {pattern!r} after '{device_cmd}'{RESET}"
                )
                return ''
            finally:
                self.child.logfile_read = None

            # buf contains: ...echo_line\r\n[output\r\n]prompt
            # Find the echo line and discard everything up to and including it.
            lines = buf.getvalue().split('\n')
            for i, line in enumerate(lines):
                if device_cmd in line:
                    lines = lines[i + 1:]
                    break

            # Last line is the matched prompt — discard it.
            if lines:
                lines = lines[:-1]

            collected.extend(
                l.rstrip('\r') for l in lines if l.strip('\r').strip()
            )

        self.child.logfile_read = sys.stdout
        # For LOOP: send \r so the loop body's first expect has a fresh
        # prompt to match.  For SEND/EXPECT context: the device is already
        # at a clean prompt — sending \r would leave a stale prompt in the
        # buffer that the next expect would match instead of the real output.
        if send_refresh:
            self.child.send('\r')

        if shell_pipe:
            try:
                result = subprocess.run(
                    shell_pipe,
                    shell=True,
                    input='\n'.join(collected),
                    capture_output=True,
                    text=True,
                )
                items = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            except Exception as exc:
                click.echo(f"{YELLOW}Dynamic variable: shell pipeline failed: {exc}{RESET}")
                items = collected
        else:
            items = collected

        return LIST_SEP.join(items)

    def _resolve_cmd_vars(self, text: str, vars_: Dict[str, Any]) -> None:
        """
        Resolve any cmd: variables referenced in text before substitution.
        Each variable whose value starts with 'cmd:' is resolved once and
        cached in both vars_ and self.host so it is not re-executed.
        """
        for m in re.finditer(r'\$(\w+)', text):
            name = m.group(1)
            val  = vars_.get(name, '')
            if isinstance(val, str) and val.startswith('cmd:'):
                resolved          = self._resolve_dynamic_var(val[4:], send_refresh=False)
                self.host[name]   = resolved
                vars_[name]       = resolved

    # ── command execution ─────────────────────────────────────────────────────

    def run(self, commands: List[CmdTuple], extra: Optional[Dict[str, Any]] = None) -> bool:
        """
        Walk a command list and drive the pexpect session.

        extra: dict of additional variables that override host vars during
               substitution (used by LOOP to inject the current item var).

        Returns True on clean completion, False on any expect failure.
        """
        vars_: Dict[str, Any] = {**self.host, **(extra or {})}

        for cmd in commands:
            kind = cmd[0]

            if kind == 'expect':
                self._resolve_cmd_vars(cmd[1], vars_)
                pattern = subst(cmd[1], vars_)
                try:
                    self.child.expect(pattern, timeout=self.timeout)
                except pexpect.TIMEOUT:
                    click.echo(
                        f"\n{YELLOW}Timed out waiting for  {pattern!r}"
                        f"  on {self.host['ip']}{RESET}"
                    )
                    return False
                except pexpect.EOF:
                    click.echo(
                        f"\n{YELLOW}Connection closed while waiting for  {pattern!r}"
                        f"  on {self.host['ip']}{RESET}"
                    )
                    return False

                # Store regex capture groups as $1, $2, ... in both host and
                # vars_ so they are usable in subsequent lines and nested loops.
                if self.child.match:
                    for n, g in enumerate(self.child.match.groups(), start=1):
                        val               = g or ''
                        self.host[str(n)] = val
                        vars_[str(n)]     = val

            elif kind == 'send':
                self._resolve_cmd_vars(cmd[1], vars_)
                text = subst(cmd[1], vars_)
                self.child.sendline(text)

            elif kind == 'loop':
                _, list_var, item_var, body = cmd

                raw = vars_.get(list_var, '')
                if isinstance(raw, str) and raw.startswith('cmd:'):
                    raw = self._resolve_dynamic_var(raw[4:])
                    self.host[list_var] = raw
                    vars_[list_var]     = raw

                if not raw:
                    click.echo(
                        f"{YELLOW}Loop variable '${list_var}' is empty"
                        f" — skipping loop{RESET}"
                    )
                    continue

                items = [x.strip() for x in raw.split(LIST_SEP) if x.strip()]
                for item in items:
                    ok = self.run(body, extra={**(extra or {}), item_var: item})
                    if not ok:
                        return False

        return True

    # ── cleanup ───────────────────────────────────────────────────────────────

    def close(self) -> None:
        if self.child:
            try:
                self.child.close(force=True)
            except Exception:
                pass
        self.child = None


# ── CLI ────────────────────────────────────────────────────────────────────────

EXTRA_ARGS_HELP = """
Any column name defined in the host file header can also be supplied as a
'-name value' pair here to fill in blanks left in the host file.
For example: -ip 10.0.0.1 -login admin -tftp 192.168.254.100
"""


def _show_man(ctx: click.Context, param: click.Parameter, value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return
    if sys.platform != "win32" and shutil.which("man"):
        subprocess.run(["man", str(MAN_PAGE)])
    elif sys.platform == "win32":
        # click.echo_via_pager() shells out to `more` via a temp file on
        # Windows, which races the file's own cleanup and raises
        # PermissionError [WinError 32]. Just print the text instead.
        click.echo(MAN_PAGE.read_text())
    else:
        click.echo_via_pager(MAN_PAGE.read_text())
    ctx.exit()


@click.command(
    context_settings={
        # Free -h for our hostfile option; use --help for built-in help.
        "help_option_names": ["--help"],
        # Allow arbitrary -param value pairs for user-defined host columns.
        "allow_extra_args": True,
        "ignore_unknown_options": True,
    },
)
@click.option(
    "--man",
    is_flag=True,
    expose_value=False,
    is_eager=True,
    callback=_show_man,
    help="Show the rcd man page and exit.",
)
@click.option(
    "-h", "hostfile",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="CSV host file listing target devices.",
)
@click.option(
    "-t", "timeout",
    default=DEFAULT_TIMEOUT,
    show_default=True,
    type=int,
    help="Expect timeout in seconds.",
)
@click.option(
    "--otp",
    is_flag=True,
    default=False,
    help="Wait out the OTP window before retrying after a failed login.",
)
@click.option(
    "--login-failure-limit",
    default=2,
    show_default=True,
    type=int,
    help="Maximum number of login attempts per device before skipping it.",
)
@click.argument("extra_args", nargs=-1, type=click.UNPROCESSED)
def main(
    hostfile: str,
    timeout: int,
    otp: bool,
    login_failure_limit: int,
    extra_args: Tuple[str, ...],
) -> None:
    """Remote Command Distribution — distribute commands across multiple devices.

    Mandatory host file columns: ip, login, pass, proto, cfile.
    """
    # Parse any remaining -key value pairs (user-defined host columns).
    cli: Dict[str, Any] = {}
    i = 0
    toks = list(extra_args)
    while i < len(toks):
        tok = toks[i]
        if tok.startswith('-'):
            key = tok.lstrip('-')
            if i + 1 < len(toks) and not toks[i + 1].startswith('-'):
                cli[key] = toks[i + 1]
                i += 2
            else:
                cli[key] = True
                i += 1
        else:
            click.echo(f"Unexpected argument: {tok}", err=True)
            i += 1

    for lineno, host, err in iter_hosts(hostfile, cli):
        if err:
            click.echo(f"{YELLOW}{hostfile}:{lineno}: {err} — skipping{RESET}")
            continue

        try:
            commands = parse_cmdfile(host['cfile'])
        except FileNotFoundError:
            click.echo(f"Cannot open command file '{host['cfile']}' — aborting", err=True)
            raise SystemExit(1)
        except ValueError as exc:
            click.echo(f"Command file parse error: {exc} — aborting", err=True)
            raise SystemExit(1)

        ips, err = expand_ip(host['ip'])
        if err:
            click.echo(f"{YELLOW}{hostfile}:{lineno}: {err} — skipping{RESET}")
            continue

        # prev_failed persists across the IP range so that the OTP cooldown
        # (when --otp is set) also fires when moving from one IP to the next
        # after a failure — same behaviour as the original rcd.exp.
        prev_failed = False

        for ip in ips:
            sess: Optional[Session] = None
            ok      = False

            for attempt in range(1, login_failure_limit + 1):
                sess = Session({**host, 'ip': ip}, timeout, otp=otp)
                ok   = sess.connect(prev_failed=prev_failed)

                if ok:
                    prev_failed = False
                    break

                sess.close()
                prev_failed = True

                if attempt < login_failure_limit:
                    click.echo(
                        f"{YELLOW}Login attempt {attempt}/{login_failure_limit}"
                        f" failed on {ip} — retrying{RESET}"
                    )

            if not ok:
                click.echo(
                    f"{YELLOW}Skipping {ip} after {login_failure_limit}"
                    f" failed login attempt(s){RESET}"
                )
                continue

            success     = sess.run(commands)
            prev_failed = not success
            sess.close()

            if not success:
                click.echo(f"{YELLOW}Command execution failed on {ip}{RESET}")

    click.echo(f"\n\n{RED}!!!! Done !!!!{RESET}\n")


if __name__ == '__main__':
    main()
