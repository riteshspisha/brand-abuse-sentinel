# A bind-mounted directory replaced by git is empty inside the container

**Context.** The lab web server (`docker/lab.compose.yaml`) bind-mounts
`labsites/` read-only. M5's lab demo fetched every lab site through the lab proxy.

**Problem.** Every lab host answered with nginx's 404 page, and the M4 lab tests
that had passed earlier failed the same way. Inside the container
`/srv/labsites` was empty. A branch switch or merge had removed and recreated
`labsites/` on the host after the container started. A bind mount follows the
directory inode it was created with, so the container kept the deleted
directory, while the single-file mount of `nginx.conf` still looked healthy.

**Fix.** Recreate the lab containers after any checkout that touches mounted
directories: `docker compose -f docker/lab.compose.yaml up -d --force-recreate`.
The lab tests (`tests/lab/`) catch it immediately (`status:404` instead of 200).

**Lesson.** When a long-running container serves files from the working tree
and starts returning "not found", look inside the container before suspecting
the code: `docker exec <c> ls <mount>`. Git operations replace directories.
