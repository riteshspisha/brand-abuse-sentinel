# `PRAGMA journal_mode = WAL` fails at once while another connection writes

**Context.** `store.db.connect` switches every connection to WAL and then applies
migrations under `BEGIN IMMEDIATE`, with a 30 s busy timeout.

**Problem.** After M6 added migration 0005,
`test_concurrent_first_start_migrates_exactly_once` failed in about a third of
runs with `database is locked` from `PRAGMA journal_mode = WAL`, never from the
migration itself (0 of 20 on main). Changing the journal mode returns SQLITE_BUSY
without calling the busy handler; a longer migration only widened the window in
which another opener held the write lock.

**Fix.** Read `PRAGMA journal_mode` first and switch only when it is not already
WAL; retry a locked switch for up to 30 s (`store/db.py:_enable_wal`). 0 of 100
rounds of six concurrent first opens fail.

**Lesson.** SQLite's busy timeout does not cover every statement; schema and
mode changes can still need their own retry.
