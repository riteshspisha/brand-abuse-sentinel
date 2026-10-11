# numpy's OpenBLAS exhausts a container PID limit on a many-core host

**Context.** The media worker (M6) runs in a sandbox container with
`--pids-limit 64` and imports `imagehash`, which imports numpy and scipy.

**Problem.** In the real container every image came back `internal_error:
RuntimeError: Resource temporarily unavailable` (EAGAIN), while the same code
passed in process. OpenBLAS starts one thread per *host* CPU when numpy is
imported; a container's CPU quota (`--cpus 1`) does not change the CPU count it
sees, so on a many-core host the thread pool alone exceeds the PID limit (threads
count as tasks).

**Fix.** Pin every thread pool to one thread in the job's environment
(`OMP_THREAD_LIMIT`, `OMP_NUM_THREADS`, `OPENBLAS_NUM_THREADS`,
`MKL_NUM_THREADS`, `NUMEXPR_NUM_THREADS`; `sandbox/media_client.py:media_spec`).
The PID limit stays as it is. `brandsentinel sandbox selftest media` catches a
regression: its valid image comes back unhashed.

**Lesson.** Limits that count tasks must be tested with the real libraries in the
real container; an in-process run never sees them.
