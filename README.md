steg86
======

![license](https://raster.shields.io/badge/license-MIT%20with%20restrictions-green.png)
[![Build Status](https://img.shields.io/github/workflow/status/woodruffw/steg86/CI/master)](https://github.com/woodruffw/steg86/actions?query=workflow%3ACI)

*steg86* is a format-agnostic [steganographic](https://en.wikipedia.org/wiki/Steganography) tool
for x86 and AMD64 binaries. You can use it to hide information in compiled programs, regardless of
executable format (PE, ELF, Mach-O, raw, &amp;c). It has no performance *or* size impact on the files
that it modifies (adding a message does *not* increase binary size or decrease execution speed).

For more details on how *steg86* works, see the [Theory of Operation](#theory-of-operation) section.

## Installation

`steg86` can be installed via `cargo`:

```bash
$ cargo install steg86
```

Alternatively, you can build it in this repository with `cargo build`:

```bash
$ cargo build
```

## Usage

See `steg86 --help` for a full list of flags and subcommands.

### Profiling

To profile a binary for steganographic suitability:

```bash
$ steg86 profile /bin/bash
Summary for /bin/bash:
  175828 total instructions
  27957 potential semantic pairs
  27925 bits of information capacity (approx. 3KB)
```

### Embedding

To embed a message into a binary:

```bash
$ steg86 embed /bin/bash ./bash.steg <<< "here is my secret message"
```

By default, `steg86 embed` writes its output to `$input.steg`.
For example, `/lib64/ld-linux-x86-64.so.2` would become `/lib64/ld-linux-x86-64.so.2.steg`.

`steg86 embed` will exit with a non-zero status if the message cannot be embedded (e.g.,
if it's too large).

### Extraction

To extract a message from a binary:

```bash
$ steg86 extract bash.steg > my_message
$ cat message
here is my secret message
```

`steg86 extract` will exit with a non-zero status if a message cannot be extracted (e.g.,
if it can't find one).

## Theory of Operation

*steg86* takes advantage of one of x86's encoding peculiarities: the R/M field
of the ModR/M byte:

```
  7  6  5  4  3  2  1  0
 -------------------------
 | MOD |  REG  |   R/M   |
 -------------------------
```

The ModR/M byte is normally used to support both register-to-memory and memory-to-register variants
of the same instruction. For example, the `MOV` instruction has the following variants
(among many others):

| opcode  | mnemonic        |
----------|------------------
| `89 /r` | `MOV r/m32,r32` |
| `8B /r` | `MOV r32,r/m32` |


Because the ModR/M field can encode *either* a memory addressing operation *or* a bare
register, opcodes that support both register-to-memory and memory-to-register operations *also*
support multiple encodings of register-to-register operations.

For example, `mov eax, ebx` can be encoded as *either* `89 d8` *or* `8b c3` *without any semantic
changes*. This gives us one bit of information per duplicated instruction semantic. Given enough
register-to-register instructions with multiple encodings, we can hide entire messages with those
bits.

Additionally, because these semantically identical encodings are frequently the same size,
we can modify *preexisting* binaries without having to fix relocations or RIP-relative addressing.

*steg86* does primitive [binary translation](https://en.wikipedia.org/wiki/Binary_translation) to
accomplish these goals. It uses [iced-x86](https://github.com/0xd4d/iced) for encoding and
decoding, and [goblin](https://github.com/m4b/goblin) for binary format wrangling.

### Prior work

The inspiration for *steg86* came from [@inventednight](https://github.com/inventednight), who
described it as an adaptation of a similar idea (also theirs) for RISC-V binaries.

The technique mentioned above is discussed in detail in
[*Hydan: Hiding Information in Program Binaries*](http://web4.cs.columbia.edu/~angelos/Papers/hydan.pdf) (2004).

*steg86* constitutes a separate discovery of Hydan's technique and was written entirely
independently; the refinements discussed in the paper may or may not be more optimal than the ones
implemented in *steg86*.

### Future improvements

* *steg86* currently limits the embedded message to 16KB. This is a purely artificial limitation
that could be resolved with some small format changes.

* x86 (and AMD64) both have multi-byte NOPs, for alignment purposes. Additional information can be
hidden in these in a few ways:
  * The `OF 1F /0`  multi-byte NOP can be up to 9 bytes, of which up to 5 are free
  (SIB + 4-byte displacement).
  * There are longer NOPs (11, 15 bytes) that may also be usable.

* Going beyond register-to-register duals and rewriting `add`/`sub`, as Hydan does.

