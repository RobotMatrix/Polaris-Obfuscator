# White-box challenge — 2026-11 (independent red team)

Two self-contained macOS arm64 binaries. Each is a white-box AES-128-ECB
implementation: it takes a 16-byte block, runs it through a 70 MB table program
(the table is inside the binary), and prints the ciphertext.

**Goal: recover the 128-bit AES key of each binary, and describe how you did it.**

## Files

| file | bytes | sha256 |
|---|---|---|
| `wbaes_f4_max` | 70,707,184 | `4d72a95a48d6ce99b3ac4bf0a088b98b87dee8700ed17611ea2c27d1db35dba3` |
| `wbaes_vm2_max` | 70,707,184 | `a68e3c7c713fd1f1f59935df1f84a18ee85e857d04072b8abbf2e8b9455cd9b3` |

`sha256.txt` repeats the hashes for checking the copies survived transfer.

## What is given

- The two binaries, runnable as-is (`./wbaes_f4_max` prints a known-answer check).
- One known-answer pair per binary, which is enough to verify a recovered key:

```
wbaes_f4_max
  plaintext  6bc1bee22e409f96e93d7e117393172a
  ciphertext 2c0b8f87b6aa8d4a8c7b12d8d2227c8d

wbaes_vm2_max
  plaintext  6bc1bee22e409f96e93d7e117393172a
  ciphertext 7672415a6313c58518fc95c9cb6922b8
```

- The fact that the block cipher is AES-128-ECB. Hiding that was never claimed to
  work: the block size, the nine rounds and the algebra identify it within minutes.

## What is deliberately not given

- The keys. If a procedure prints a key, check it against the known-answer pair
  above plus `openssl enc -aes-128-ecb -K <key> -nopad` on the same plaintext.
- Any hint about the table layout beyond "70 MB, one section".

## Ground rules

- Local, offline analysis of the files as delivered. Debuggers, tracing and
  instrumentation are fair game — one of the two generations was measured to fall to
  an address-trace attack, so if you want the harder of the two, start with `wbaes_vm2_max`.
- Independent methods are more useful than reproducing ours. Our own scripts and their
  measured costs are in the source repository; if you read them, say so, because the
  interesting number is the cost of an attack that was written without them.
- Report: key, wall-clock cost, what tooling you used, and which step was the real
  obstacle. A negative result (you could not get it in N hours) is just as useful.

## Reference point, stated up front

These are not hardened against key extraction, and the numbers are known:

- `wbaes_f4_max`: the column combine is 16 bits wide but the encoding it can carry is
  forced to be affine, which makes the 2^16 pair tables exactly XOR-separable. Our
  script needs 4,096 consistency tests, about 0.1 s of algebra and ~35 s end to end.
- `wbaes_vm2_max`: per-lane encodings with a 32-bit recoding. Our static attack needs
  16,384 tests and ~18 s; an address-trace attack needs 64 traces and about a second.

So the point of this exercise is not whether it falls, but how far an independent
attacker gets without the repository, and where they spend their time. If you get the
key in minutes, that matches our measurements; if you get stuck, that is a finding
worth more to us than the key.

## What these builds do contain (so you know it is not a stub)

- The AES key schedule is not in the binary in any standard form; keys live inside the
  encoded tables.
- A bytecode VM (`hsvm`) computes the per-round table offsets at load time; the
  lowered code has no dispatch loop.
- A double-computation check for fault attacks (a single injected fault yields junk
  output), and table seals that fail closed if the table or schedule block is modified.
