# zsql — a compressor that understands your database

`zsql` is a lossless compressor written in Rust, built for one kind of file:
**MySQL / MariaDB dumps** (the `.sql` files `mysqldump` produces).

Ordinary compressors like gzip, zstd and xz see a backup as one long stream of
bytes. zsql reads it as tables, rows and columns. It knows that one column holds
ever-increasing IDs, the next holds timestamps a few seconds apart, and the next
holds the same 300 usernames over and over. That lets it store the same
information in far fewer bytes, and the file it restores is **byte-for-byte
identical** to the original.

## The problem

A typical application database is mostly "log" tables: sessions, logins,
events, audit trails. The backup that motivated zsql was:

- 4.8 GB of SQL every night, 975 MB after gzip
- 99% of it from two FreeRADIUS log tables (`radacct`, `radpostauth`)
- kept for 30 days, so about 29 GB of disk spent re-copying the same old rows

Better generic compression barely helps. On the real 4.8 GB dump, zstd level 9
was only 11% smaller than gzip. The data is full of unique IDs, timestamps and
MAC addresses, and in row order the patterns are hidden.

## How zsql works

### 1. Rows become columns
An SQL dump stores data one row at a time:

```
(1001,'alice','2026-11-15 10:00:01'),(1002,'bob','2026-11-15 10:00:03'),...
```

zsql pulls each column out into its own stream: all the IDs together, all the
usernames together, all the timestamps together. Similar values next to each
other compress much better. Analytics databases such as Parquet, ClickHouse and
DuckDB use the same idea.

### 2. Each column gets a model that fits it

| Data | Ordinary compressor sees | zsql stores |
|---|---|---|
| IDs `1001, 1002, 1003` | text digits | the difference from the previous row: `+1, +1, +1` |
| timestamps `'2026-11-15 10:00:01'` | 21 characters of text | seconds as a number, as the difference from the previous row, or from another time in the same row (stop time minus start time = session length) |
| microsecond timestamps | 28 characters | an integer in microseconds, delta-coded |
| decimals `12.50` | text | the whole number `1250` plus a "2 decimal places" marker |
| numbers inside quotes `'120190814014636'` | text | an integer, delta-coded |
| repeating text (usernames, reply messages, IPs) | text, over and over | each value stored once, then a small number pointing to it |
| unique text (session IDs, hashes) | text | raw. zsql notices the dictionary isn't helping and turns it off for that column |
| `NULL` | 4 characters | part of a tiny type stream that usually compresses to almost nothing |

zsql picks the best option for each column automatically. For integers it
tries both delta and plain. For timestamps it tries "previous row" and "same
row". It keeps whichever comes out smaller.

### 3. The best compressor for each stream
Every column stream is then compressed with both **zstd (level 19, long range)**
and **xz (-9e)** in parallel, and the smaller result is kept. Ordinary tools
compress the whole file one way. zsql chooses per column.

### 4. Safety first
- **Lossless, proven every time.** zsql stores a BLAKE3 checksum of the
  original dump. Decompression recomputes it and fails if a single byte differs.
- **If it isn't sure, it doesn't touch it.** Any line zsql can't parse with
  100% certainty (unusual quoting, binary data, odd formats) is stored exactly
  as it was. Strange data can cost a little size, never correctness.
- **Corruption is detected,** not silently restored.
- **Atomic writes.** A crash never leaves a half-written backup that looks
  complete.

## Results on the real database

*(4.8 GB production dump, 4-core Skylake server, under production load)*

Every zsql result below was decompressed and compared byte-for-byte with
the original dump: identical every time.

| Method | Size | vs gzip | Compress time | Restore time |
|---|---|---|---|---|
| gzip -6 (the old backup) | 974 MB | — | 4 min | — |
| zstd -3 | 917 MB | −6% | 29 s | — |
| zstd -9 | 867 MB | −11% | 2 min | — |
| zstd -19 --long | 691 MB | −29% | 75 min | — |
| xz -9e (the "maximum" classic) | 655 MB | −33% | 151 min | — |
| **zsql --fast (default)** | **542 MB** | **−44%** | **83 s** | **55 s** |
| zsql max (zstd-19 + xz-9e per column) | 530 MB* | −46% | 61 min | 77 s |

\* measured before the hex model was added. With it, max mode should come in
a little lower.

**zsql in fast mode is 17% smaller than xz -9e and 109x faster.**

On the business tables alone (invoices, ledger, payments and the rest, 151 MB
of SQL), zsql max gives **7.8 MB**, against 16.7 MB for gzip and 11.2 MB for
zstd -19.

### Where the remaining bytes are, and why nothing can remove them
More than half of the 542 MB is one column: `radpostauth.pass`, which holds
17.9 million CHAP responses. Each is 17 bytes of effectively random data, and
random data can't be compressed by any algorithm. Its floor is
17 × 17.9M ≈ 305 MB. zsql's hex model stores those values as raw bytes and
gets close to that floor. Generic compressors spend about 18–28 bytes on each
one.

## Weekly full + nightly incremental

zsql pairs with a smarter backup schedule:

- **Weekly full backup (Sunday):** the whole database, compressed with zsql.
- **Nightly incremental:** all business tables (invoices, ledger, payments,
  users: everything except the two log tables) dumped in full, plus only the
  RADIUS log rows that are new or changed since Sunday.
  - Nightly size: about 12 MB with plain zstd, smaller with zsql
  - The old way: 975 MB every night

Restoring always takes exactly **two files**, the latest full and the latest
nightly. There's no long chain of incrementals where one bad file breaks
everything after it.

## Why it's better

- **Storage:** each backup is far smaller, so you can keep months of history
  in the space 30 days used to take.
- **Speed where it counts:** in fast mode the whole 4.8 GB dump (parse, column
  modelling, compression, writing) took 74 s on a busy 4-core server. That's
  3x faster than gzip and 61x faster than `zstd -19`, with smaller output than
  either. Restoring took 51 s, and the checksum is verified as it goes.
- **Less disk and network I/O:** smaller backups are quicker to copy off-site,
  upload to cloud storage, or move over a slow link.
- **One small file:** a ~2 MB static Rust binary with no runtime and no
  dependencies to install on the server.
- **Works with pipes:** `mysqldump ... | zsql c - backup.zsql` never writes the
  uncompressed SQL to disk.

## Usage

```bash
# compress (from a file or straight from mysqldump)
mysqldump --single-transaction mydb | zsql c - mydb.zsql
zsql c --fast dump.sql dump.zsql        # zstd only: much quicker, slightly bigger

# restore (verifies the checksum)
zsql d mydb.zsql - | mysql mydb
zsql d mydb.zsql restored.sql
```

Options: `--fast` (no xz), `-l N` zstd level, `-j N` threads,
`-t table1,table2` columnarize only these tables, `--tmp DIR` scratch space.

## Honest limits

- It's built for `mysqldump` output. Any other file still compresses (it all
  takes the safe pass-through path), just without the column advantage.
- Max mode (xz -9e on every stream) is slow and meant for weekly fulls. Use
  `--fast` for nightly jobs.
- The format is new. Test your restores regularly.
