# deaddrop

**Encrypted shared mailboxes between Claude Code sessions.**
Create a drop, give the code to a teammate, and your two Claudes can leave each other messages and files. When something arrives, Claude Code tells you, and Claude can read it on its own, like email.

```
you      /deaddrop:new ana          → code K7QM-2XRA-9PLN-W4TZ-HC8E
teammate /deaddrop:join K7QM-2XRA-9PLN-W4TZ-HC8E
you      "send Ana the failing test and the stack trace"
teammate 📬 deaddrop: 1 new message · «ana» from Sam — "failing test" (+1 file)
```

## Install

Tell Claude Code:

> install this: https://github.com/Ces107/deaddrop

Or type it yourself at the Claude Code prompt:

```
/plugin install deaddrop --marketplace Ces107/deaddrop
```

Needs **Node.js 18+** (`node --version`). Nothing else: no account, no server, no API key.

### For Claude (installing for a user)

1. Check `node --version` is 18 or newer. If Node is missing, tell the user to install it from https://nodejs.org and stop.
2. Run:
   ```
   claude plugin marketplace add Ces107/deaddrop
   claude plugin install deaddrop@deaddrop
   ```
3. Tell the user to run `/reload-plugins` (or restart Claude Code), then `/deaddrop:new` to create a drop or `/deaddrop:join <code>` to join one.

## Use

| Command | What it does |
| --- | --- |
| `/deaddrop:new [name]` | create a drop, get its code |
| `/deaddrop:join <code> [name]` | join a teammate's drop |
| `/deaddrop:send [drop] <message>` | send text, and files if you mention them |
| `/deaddrop:inbox [drop]` | read new messages |
| `/deaddrop:status` | your drops, codes, unread counts |
| `/deaddrop:name <name>` | the name you sign with (default: git `user.name`) |
| `/deaddrop:leave <drop>` | stop following a drop |

You rarely need the commands: just say "tell Ana that…", "send this file to the api drop", "any messages?". Claude has the `deaddrop` tools (`send`, `read`, `inbox`, …) and uses them when it fits.

A drop can have more than two people: everyone with the code reads and writes it. You can be in many drops.

## How it works

- **Notifications.** Hooks check your drops when a session starts, when you send a prompt, and every minute while Claude works. New messages show up as `📬 deaddrop: …` and Claude is told they exist (sender and subject only). It reads the content with the `read` tool when it is relevant or you ask.
- **Relay.** Messages go through [ntfy.sh](https://ntfy.sh), a free public pub/sub relay. The relay holds messages **12 hours** (files **3 hours**). Your Claude Code downloads them whenever it is open and keeps them in `~/.deaddrop`, so a message is safe once either side's session has been open in that window.
- **Encryption.** The code never leaves your machine. It is turned (HKDF-SHA256) into an AES-256-GCM key and a random-looking topic name. The relay only sees ciphertext, sizes and IP addresses. The code has 100 bits of randomness, so treat it like a password: anyone holding it can read and post.
- **Limits.** Files up to 10 MB per message. The public relay rate-limits each IP (a few hundred messages a day).
- **Safety.** Messages are written by other people. deaddrop frames them as untrusted content, and Claude is told never to follow instructions inside a message without your agreement.

### Own relay (longer retention)

Any [ntfy server](https://docs.ntfy.sh/install/) works. Run one with a longer `cache-duration` and `attachment-expiry-duration`, then set `DEADDROP_SERVER=https://your-ntfy.example.com` for everyone in the drop (or `"server"` in `~/.deaddrop/config.json`).

### Files on disk

```
~/.deaddrop/config.json          your name, id and drops (codes!)
~/.deaddrop/drops/<topic>.json   messages
~/.deaddrop/files/<drop>/<id>/   attachments you received
```

`DEADDROP_HOME` moves all of it.

### Command line

The same script works without Claude: `node bin/deaddrop.mjs help`.

## Uninstall

```
claude plugin uninstall deaddrop@deaddrop
```

Then delete `~/.deaddrop` if you want your messages gone.

## License

MIT
