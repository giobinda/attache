# TODO / ideas

Not committed — scratch notes.

## Vault-scoped egress gating

Gate *outbound network connections*, but only for processes that currently
hold a file open inside the vault. Closes the "an app read your private
documents and is now phoning home" gap without becoming a general-purpose
firewall.

**Why in-project, not separate:** `attache-gate` already tracks every open
handle (`PassthroughFs::handles`), so it already knows *which PIDs are
"tainted"* by vault access. That set is the whole trigger. A standalone tool
would have to reconstruct it.

### Sketch

- Maintain a set of "tainted" PIDs = any process with ≥1 live vault file
  handle (add on `open`/`create`, drop on last `release`). Keep the binary
  hash alongside, from the existing `ProcessIdentity`.
- Egress enforcement via `nftables` + `NFQUEUE` (or eBPF cgroup/sock hooks):
  a rule verdicts *new* outbound flows to a userspace decision loop.
- Decision loop: packet → owning PID (conntrack / `/proc/net`) → is it in
  the tainted set? If not, accept. If yes, run it through the same
  `AuthPolicy` (prompt: `"<comm> (<hash>…) read from the vault and now wants
  <host>:<port>"`), cache per (binary-hash, host) for the session, persist
  "always" decisions.
- Reuse verbatim: `process_info::resolve`, `policy::AuthPolicy`,
  `whitelist`, `ZenityPrompter`. Only the packet plumbing is new.

### Open questions

- Needs `CAP_NET_ADMIN` for the nft/NFQUEUE setup — another privileged
  helper, or fold into `attache-mount-helper`? Keep the "nothing privileged
  runs automatically" rule.
- Taint lifetime: does a PID stay tainted after it closes the file (it may
  have buffered the contents in memory)? Probably yes until the process
  exits — "sticky taint". Make it configurable.
- Child processes: taint should propagate to forked children (a wrapper
  script reads a file, spawns `curl`). Track by process tree.
- DNS: the connection is usually to an IP; resolve back to a name for the
  prompt, or gate at `getaddrinfo`? Showing a bare IP is bad UX.
- Per-vault vs global policy: the file whitelist lives *in* the vault so it
  travels; an egress whitelist arguably should too.
- Interaction with the existing multi-threaded FUSE dispatch and the
  prompt-timeout / no-GUI fail-closed behaviour (v0.1.1) — same rules apply.

### Prereq

Extract `gatekeeper` crate first (`policy` + `whitelist` + `process_info` +
prompter) so both the file gate and the egress gate consume one policy
engine. See also: `attache-audit` (log every allow/open, not just denials).

---

## `att config` — interactive settings menu

One entry point that walks a list of options instead of making the user
hand-edit `~/.config/attache/config` or remember six subcommands. Numbered
menu via `read` (or `zenity --list`, since zenity is already a dep) — pick
an item, it prompts for the value / confirms the action, applies it, loops
back to the menu.

### Candidate items

| Item | Backed by | Applies |
| --- | --- | --- |
| Autoclose idle timeout | `CHECK_INTERVAL_MIN` (currently hardcoded 5) → move to config file | next `att open` |
| Prompt timeout | `ATTACHE_PROMPT_TIMEOUT` → config file (currently env-only) | next `att open` |
| Display-name / mountpoint | `MOUNTPOINT` (already in config, just no UI) | next `att open` |
| Change vault password | `gocryptfs -passwd ~/.attache` (prompts old+new) | **vault must be closed** |
| Reset whitelist | existing `att reset-whitelist` / control socket | live if open |
| List / remove one whitelist entry | **new** — gate only supports reset-all today; needs a `LIST` + `REMOVE <hash>` control command and a closed-vault path in `attache-mount-helper` | live if open |
| Default export dir | new config key | `att export` |
| No-GUI behaviour | today: hardcoded fail-closed (v0.1.2). Maybe a toggle: deny vs. queue-for-`att denied` | next `att open` |

### Constraints

- **Keep the config-file invariant** (see `att` header comment): nothing
  settable here may reach a privileged operation. `CIPHERDIR` /
  `REAL_MOUNTPOINT` stay hardcoded. Timeouts, display name, export dir are
  all safe (unprivileged).
- Menu must label each item with *when* it takes effect (live / next open /
  requires-closed) and refuse the requires-closed ones while `is_mounted`.
- `change password` is the sharp one: gocryptfs `-passwd` needs the vault
  unmounted; wrong old password just fails, no lockout. Confirm twice.
- "List whitelist entries" is the missing gate capability — worth doing on
  its own (`att allow --list`) regardless of the menu; `WhitelistEntry`
  already stores `path`/`comm`/`added_at` as the human-readable labels for
  exactly this.
