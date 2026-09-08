---
layout: default
title: "The SSH key error that blames the wrong library"
---

# The SSH key error that blames the wrong library

My deploy pipeline broke in August. The key worked fine when I tested it on my
Windows machine. Same key, same GitHub secret, and CI gave me this:

```
Load key "/home/runner/.ssh/deploy_key": error in libcrypto
Permission denied (publickey).
```

I lost about a day to this. Most of that day was spent on things that turned out
to have nothing to do with it. I checked the file permissions first, because
that's the usual answer when ssh refuses a key. Then I convinced myself I had
pasted the wrong public key onto the server, so I regenerated the pair and did
the whole thing again. Same error. At some point I started blaming the runner
image.

Every explanation I found said roughly the same thing: OpenSSL's libcrypto
can't parse the key, the line endings corrupt the base64, run `tr -d '\r'` and
move on. The fix does work. But the explanation is wrong, and I only found that
out later when I went to read the source out of annoyance.

## The parser never gets to the base64

The key file starts with a marker, and the marker is defined with the newline
baked into it. This is `sshkey.c`, pinned to the 10.0p2 tag,
[line 72](https://github.com/openssh/openssh-portable/blob/2593769fb291fe6c542173927698c69e9f9a08b9/sshkey.c#L72-L75):

```c
#define MARK_BEGIN "-----BEGIN OPENSSH PRIVATE KEY-----\n"
```

That `\n` at the end is part of the string. `MARK_BEGIN_LEN` is 36, so
thirty-five printable characters plus the newline. And the preamble check is
just a `memcmp` over those 36 bytes
([line 2985](https://github.com/openssh/openssh-portable/blob/2593769fb291fe6c542173927698c69e9f9a08b9/sshkey.c#L2985-L2991)).

In a CRLF file byte 35 is `0x0d` instead of `0x0a`. So the comparison fails on
the first line and returns `SSH_ERR_INVALID_FORMAT`.

Which means the base64 decoder is never called at all. Nothing is corrupted.
The key body is completely fine.

The part I find funny is what's twelve lines further down. There's a loop that
walks the body looking for the end marker, and it strips whitespace as it goes
([line 2996](https://github.com/openssh/openssh-portable/blob/2593769fb291fe6c542173927698c69e9f9a08b9/sshkey.c#L2996-L3013)).
It removes `\r` on purpose. So if execution ever reached that loop, carriage
returns in the key would be harmless. The only `\r` that actually kills you is
the one at the end of the `-----BEGIN-----` line, thirty-five bytes in.

## So why does it say libcrypto

Because of what happens next. `sshkey_parse_private2` returns
`SSH_ERR_INVALID_FORMAT`, and the caller reads that specific code as "this
isn't an OpenSSH-format key, try PEM instead"
([line 3699](https://github.com/openssh/openssh-portable/blob/2593769fb291fe6c542173927698c69e9f9a08b9/sshkey.c#L3694-L3703)).

Then `PEM_read_bio_PrivateKey` is handed a file that starts with
`-----BEGIN OPENSSH PRIVATE KEY-----`, which obviously is not PEM, and it
fails. That failure goes through `translate_libcrypto_error()` and comes out
the other end as `SSH_ERR_LIBCRYPTO_ERROR`. Which is the string I spent the day
chasing.

So the message is accurate about the last thing that failed and useless about
the thing that actually went wrong. libcrypto really did fail. It failed
because it was asked to parse something that was never PEM in the first place.

The message itself is a placeholder, too. `ssherr.c`
[line 71](https://github.com/openssh/openssh-portable/blob/2593769fb291fe6c542173927698c69e9f9a08b9/ssherr.c#L71):

```c
return "error in libcrypto"; /* XXX fetch and return */
```

Upstream knows it isn't fetching the real error.

There's an [OpenSSL discussion](https://github.com/openssl/openssl/discussions/21481)
from October 2022 where a maintainer tells someone with this exact problem to
go report it to the ssh project, because they're completely different things.
That thread is a GitLab CI user hitting the same failure I did.

## Why it worked on my laptop

This is the part that cost me the most time, and my first theory here was also
wrong. I assumed the Windows `ssh.exe` links LibreSSL rather than OpenSSL, and
that LibreSSL's base64 decoder is just more forgiving.

It isn't. It can't be. The failure happens at a `memcmp`, before any crypto
library gets involved at all.

The actual reason is that Microsoft patched it. In the Win32 fork,
[sshkey.c line 78](https://github.com/PowerShell/openssh-portable/blob/59aba65cf2e2f423c09d12ad825c3b32a11f408f/sshkey.c#L78-L83):

```c
#ifdef SUPPORT_CRLF
#define MARK_BEGIN_CRLF "-----BEGIN OPENSSH PRIVATE KEY-----\r\n"
#define MARK_END_CRLF   "-----END OPENSSH PRIVATE KEY-----\r\n"
#endif
```

The preamble check accepts either marker, and `SUPPORT_CRLF` is defined
unconditionally in the Windows build config. So `ssh.exe` on Windows reads a
CRLF key without complaining. Which is reasonable for a Windows port, honestly.
It's also exactly why you can test a broken key locally, watch it
authenticate, and still have CI reject it five minutes later.

I ran the same key through three environments to be sure:

| Environment | CRLF OpenSSH-format key |
|---|---|
| Git Bash, OpenSSH 10.0p2 / OpenSSL 3.2.4 | fails |
| Ubuntu 24.04, OpenSSH 9.6p1 / OpenSSL 3.0.13 | fails |
| Windows, OpenSSH_for_Windows_9.5p2 / LibreSSL 3.8.2 | **works** |

And a classic PEM key with CRLF parses fine everywhere. `openssl rsa -check` on
it returns `RSA key ok`. PEM's decoder skips whitespace, so CRLF never breaks a
PEM key. I couldn't find anything in the OpenSSL docs that actually promises
this, though, so I'd treat it as something I observed rather than a guarantee.

## Which means modern keys are the vulnerable ones

`ssh-keygen` switched its default output to the OpenSSH format in
[7.8](https://www.openssh.org/txt/release-7.8), back in August 2018. Before
that it wrote PEM.

So the format that CRLF breaks is the one basically every key generated in the
last seven years is in, unless someone deliberately passed `-m PEM`. There's a
mitigation going around that tells you to convert your deploy key with
`ssh-keygen -p -m pem`, and it does work, but as far as I can tell it works by
accident. It just moves you to the format whose parser happens to tolerate the
whitespace.

## There's a second way to trigger the same error

I only found this because GitLab documents it. Their CI docs have a
troubleshooting entry for this exact string, and the cause they give isn't CRLF
at all. It's a missing newline at the end of the key. If the secret's value
doesn't end with LF, you get `error in libcrypto`.

Same mechanism underneath. `MARK_END` also has a hardcoded `\n`, so a key with
no trailing newline fails the end-marker comparison, falls into the same
`SSH_ERR_INVALID_FORMAT` path, hits the same PEM fallback, and produces the
same misleading message.

Two completely different ways to get the bytes wrong, one error string that
points at neither of them.

## Telling a broken key from a good one

`file` is no help here. It reports `OpenSSH private key` for both, because the
[magic entry](https://github.com/file/file/blob/master/magic/Magdir/ssh#L8)
matches the header text without any line terminator, and magic tests run before
the language tests that would otherwise report CRLF. First test that succeeds
wins, so the CRLF detection never runs. That's my reading of the man page and
the magic file rather than something stated directly anywhere, but it lines up
with what I saw.

Counting the carriage returns does work:

```
$ tr -dc '\r' < key | wc -c
7
```

Zero on a clean key, one per line on a broken one.

`xxd` shows it too. Clean key, end of the first line:

```
00000020: 2d2d 2d0a                                ---.
```

Broken:

```
00000020: 2d2d 2d0d 0a                             ---..
```

## What I ended up doing

I strip the carriage returns in the workflow, before the key ever touches disk:

{% raw %}
```yaml
# `tr -d '\r'` is load-bearing: a key pasted into the secret from Windows carries CRLF,
# and OpenSSH rejects the file with the unhelpful `Load key: error in libcrypto` —
# which reads like a corrupt key rather than a line-ending problem. Reproduced: the
# same key fails with CRLF and loads with LF.
printf '%s\n' "${{ secrets.DEPLOY_SSH_KEY }}" | tr -d '\r' > ~/.ssh/id_deploy
```
{% endraw %}

([commit `0219c22`](https://github.com/Trieu-hub/finsight-platform/commit/0219c222370f06dd3361edfd21ad0356a0055d76))

The same commit strips carriage returns from a second secret, the pinned host
key that goes into known_hosts. I did that on reflex, assuming the same thing
would happen there.

It doesn't. I went back and tested it properly: a known_hosts file full of CRLF
still matches fine, and a wrong host key still gets rejected with the usual
REMOTE HOST IDENTIFICATION HAS CHANGED, exactly like the LF version. Same
result on OpenSSH 9.6p1 and 10.0p2. The known_hosts parser tolerates a trailing
\r; the private key path doesn't. So the tr -d '\r' on the key is load-bearing
and the one on known_hosts is just tidiness.

I'd written a comment in that workflow claiming the opposite, that a stray \r
would silently break pinning and quietly drop me to trust-on-first-use. That
was a guess, and it was wrong. I only found out because I was about to publish
it and decided to check first.

Caveat on the test: I only tried \r at end of line, one host, ed25519, with
accept-new. A BOM or leading whitespace in the secret is a different question
and I haven't looked at that.

It's not really a fix though, now that I understand what's happening. It's a
workaround for the fact that a secret can pick up carriage returns somewhere
between my clipboard and the runner, and I never actually found out where that
happened. If I set this up again I'd probably base64 the key into the secret
instead and decode it on the runner, so nothing in the middle can touch the
bytes at all. I haven't done that yet.

## The thing I still don't understand

The body loop strips `\r` deliberately, which means someone did think about
carriage returns in this format and decided to handle them. But the markers
keep their hardcoded `\n` and the comparison is a fixed-length `memcmp`.
Microsoft's fork needed a compile-time flag to accept the CRLF marker, so this
clearly isn't something nobody noticed.

I can't tell whether keeping the strict marker is a deliberate decision
upstream or just old code nobody's had a reason to touch. If anyone knows the
history there, I'd like to hear it.

---

*Line references pinned to
[2593769](https://github.com/openssh/openssh-portable/tree/2593769fb291fe6c542173927698c69e9f9a08b9)
(V_10_0_P2). Windows fork references pinned to
[59aba65](https://github.com/PowerShell/openssh-portable/tree/59aba65cf2e2f423c09d12ad825c3b32a11f408f)
(v9.5.0.0).*
