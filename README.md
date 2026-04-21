# Multi-Container Runtime

## Team Information

| Name | SRN |
|------|-----|
| Srujan Yalla | PES2UG24CS527 |
| Sumedh B Rao | PES2UG24CS535 |

---

## Project Overview

This project implements a lightweight Linux container runtime in C with a long-running supervisor process and a kernel-space memory monitor. The system supports multiple containers running simultaneously with namespace isolation, logging, scheduling experiments, and kernel memory enforcement.

The project consists of:

- `engine.c` — user-space runtime and supervisor
- `monitor.c` — kernel module for memory monitoring
- `monitor_ioctl.h` — shared ioctl interface
- Workload programs: `cpu_hog`, `io_pulse`, `memory_hog`

---

## Build, Load and Run Instructions

### 1. Build the Project

```bash
make
```

### 2. Load Kernel Module

```bash
sudo insmod monitor.ko
```

Verify:

```bash
ls -l /dev/container_monitor
```

### 3. Start Supervisor

```bash
sudo ./engine supervisor ./rootfs-base
```

### 4. Create Writable Root Filesystems

```bash
cp -a ./rootfs-base ./rootfs-alpha
cp -a ./rootfs-base ./rootfs-beta
```

### 5. Start Containers

```bash
sudo ./engine start alpha ./rootfs-alpha "while true; do echo hello from alpha; sleep 1; done"
sudo ./engine start alpha ../rootfs-alpha /bin/sh --soft-mib 48 --hard-mib 80
sudo ./engine start beta ../rootfs-beta /bin/sh --soft-mib 64 --hard-mib 96
```

### 6. List Containers

```bash
sudo ./engine ps
```

### 7. Inspect Logs

```bash
sudo ./engine logs alpha
# Or directly:
cat logs/alpha.log
```

### 8. Run Workloads

Workload binaries must be statically linked to run inside the Alpine rootfs:

```bash
gcc -O2 -static -o memory_hog memory_hog.c
gcc -O2 -static -o cpu_hog cpu_hog.c

cp memory_hog ./rootfs-alpha/
cp cpu_hog ./rootfs-alpha/
cp cpu_hog ./rootfs-beta/
```

Run memory limit test:

```bash
sudo ./engine start memtest ./rootfs-alpha /memory_hog --soft-mib 10 --hard-mib 20
sudo /bin/dmesg | tail -30
sudo ./engine ps
```

Run scheduling experiment:

```bash
sudo ./engine start high_prio ./rootfs-alpha /cpu_hog --nice -5
sudo ./engine start low_prio ./rootfs-beta /cpu_hog --nice 10
sudo ./engine ps
```

### 9. Stop Containers

```bash
sudo ./engine stop alpha
sudo ./engine stop beta
```

### 10. Cleanup

```bash
# Stop the supervisor first (Ctrl+C in supervisor terminal), then:
sudo rmmod monitor
sudo dmesg | tail -10
```

---

## What We Implemented

The boilerplate provided the data structure definitions, command-line parsing, `bounded_buffer_init/destroy/begin_shutdown`, `register_with_monitor`, `unregister_from_monitor`, and stub placeholders for all the core logic. The following is what we designed and implemented from scratch.

### engine.c

The boilerplate provided stubs with explicit TODO markers for 7 sections, plus the full scaffolding for `bounded_buffer_init/destroy/begin_shutdown`, `register_with_monitor`, `unregister_from_monitor`, and the CLI command parsers (`cmd_start`, `cmd_run`, `cmd_logs`, `cmd_stop`). Helper functions and struct fields needed to fulfill each TODO were added as part of that TODO's implementation.

**TODO 1 — `bounded_buffer_push()` (producer-side buffer insertion)**
Was a stub returning -1. We implemented the full push: acquires the mutex, waits on `not_full` while the buffer is at capacity (unless shutting down), writes the item at `tail`, advances `tail` modulo capacity, increments `count`, signals `not_empty`, and returns -1 early if shutdown is detected while waiting.

**TODO 2 — `bounded_buffer_pop()` (consumer-side buffer removal)**
Was a stub returning -1. We implemented the full pop: acquires the mutex, waits on `not_empty` while count is zero (unless shutting down), reads from `head`, advances `head`, decrements `count`, signals `not_full`, and returns 0 (rather than 1) when shutdown is set and the buffer is empty — the signal for the consumer thread to exit cleanly.

**TODO 3 — `logging_thread()` (log consumer thread)**
Was an empty stub returning NULL. We implemented the consumer: loops calling `bounded_buffer_pop`, opens the per-container log file at `logs/<container_id>.log` in append mode, writes the chunk with a retry loop for `EINTR`, closes the file, and exits when `pop` returns 0 (shutdown + drained). This ensures no log lines are lost even if a container exits abruptly.

**TODO 4 — `child_fn()` (clone child entrypoint)**
Was a stub returning 1. We implemented the full entrypoint: `dup2` to redirect both stdout and stderr to the pipe write fd, close the pipe write fd, `chroot` into the container rootfs, `chdir("/")`, mount `/proc` so tools like `ps` work inside the container, apply `nice` if a non-zero value was set, then `execve("/bin/sh", ["/bin/sh", "-c", command], envp)`.

**TODO 5 — `run_supervisor()` inner body (supervisor event loop)**
The boilerplate provided the init scaffolding but left the core as a TODO with 5 sub-steps. We implemented the full body and the supporting infrastructure it required:

- **`stop_requested` field** added to `container_record_t` so the `SIGCHLD` handler can distinguish a container killed by `engine stop` from one killed by the kernel module — both arrive as `SIGKILL` and are otherwise indistinguishable.
- **`sigchld_handler()`** loops `waitpid(-1, WNOHANG)` to reap all exited children without blocking, then walks the container list under `metadata_lock` to update exit code, exit signal, and state. Classification: `stop_requested` set → `CONTAINER_STOPPED`; `SIGKILL` without `stop_requested` → `CONTAINER_KILLED`; otherwise → `CONTAINER_EXITED`. Also calls `unregister_from_monitor` for the exited container.
- **`sigterm_handler()`** sets `g_ctx->should_stop = 1` to break the event loop.
- **`producer_arg_t` struct and `producer_thread()`** — each container gets one detached producer thread that reads from the pipe read-end and pushes chunks into the shared bounded buffer, exiting on EOF or shutdown.
- **`launch_container()`** implements the full container launch: create a pipe, build a `child_config_t`, allocate a clone stack, call `clone()` with `CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD`, close the write end in the supervisor, spawn the producer thread, allocate and populate a `container_record_t`, register the PID via `ioctl(MONITOR_REGISTER)`, and prepend the record to the metadata list under `metadata_lock`.
- **`handle_control_request()`** dispatches all five commands: `CMD_START` checks for a duplicate running ID then calls `launch_container`; `CMD_RUN` launches and blocks in `waitpid` until exit; `CMD_PS` walks the container list and formats a text table; `CMD_LOGS` streams the log file back in chunks using `status=1` for data and `status=2` as an end sentinel; `CMD_STOP` sets `stop_requested`, sends `SIGTERM`, polls for up to 3 seconds, then sends `SIGKILL` if the container has not yet exited.
- **The event loop itself** opens `/dev/container_monitor`, creates and binds the UNIX socket at `/tmp/mini_runtime.sock`, installs the signal handlers, spawns the logger thread, and runs a `select`-based loop accepting client connections. On shutdown it sends `SIGTERM` to all running containers, waits for all children, drains the log buffer, joins the logger thread, and frees all resources.

**TODO 6 — `send_control_request()` (CLI client)**
Was a stub printing "not implemented". We implemented the client side: creates a UNIX domain socket, connects to `/tmp/mini_runtime.sock`, sends the `control_request_t`, then receives responses in a loop — streaming log chunks (`status=1`) are written directly to stdout, the end-of-log sentinel (`status=2`) breaks the loop, and normal single responses are printed and used as the exit status.

**TODO 7 — `cmd_ps()` supervisor response (container table rendering)**
The boilerplate's `cmd_ps` sent the request but printed placeholder state names rather than real data. The actual table formatting — ID, PID, state, start timestamp, exit code — was implemented inside `handle_control_request`'s `CMD_PS` handler on the supervisor side, which builds the response string under `metadata_lock` and sends it back to the client.

---

### monitor.c

**TODO 1 — `struct monitored_entry` (linked-list node)**
We defined the `monitored_entry` struct with all required fields: `pid`, `container_id` (sized to `MONITOR_NAME_LEN`), `soft_limit_bytes`, `hard_limit_bytes`, `soft_warned` (an `int` flag to ensure the warning fires only once per container), and `struct list_head list` for kernel list linkage.

**TODO 2 — Global list and lock**
We declared `LIST_HEAD(monitored_list)` for static list initialization and `DEFINE_MUTEX(monitored_lock)` for protection. A mutex was chosen over a spinlock because both code paths that access the list — `timer_callback` and `monitor_ioctl` — run in sleepable (process) context. The timer callback uses `mod_timer` which does not run in hard IRQ context in modern kernels, so sleeping on a mutex is safe and preferable.

**TODO 3 — `timer_callback()` (periodic monitoring)**
We implemented the callback using `list_for_each_entry_safe(entry, tmp, ...)`, which is the correct safe variant for deletion during iteration. The logic handles three cases in priority order: if `get_rss_bytes` returns -1 (process exited), the entry is deleted and freed; if RSS ≥ hard limit, `kill_process` is called and the entry is removed; if RSS ≥ soft limit and `soft_warned` is 0, `log_soft_limit_event` is called and `soft_warned` is set to 1. Checking hard limit before soft limit ensures a process that jumps straight past both thresholds is killed rather than only warned.

**TODO 4 — `MONITOR_REGISTER` ioctl handler (insert)**
We allocate with `kmalloc(sizeof(*entry), GFP_KERNEL)`, check for NULL, and validate that `soft_limit_bytes <= hard_limit_bytes` (returning `-EINVAL` otherwise). Fields are copied from `req`, `container_id` is safely null-terminated using `strncpy` plus explicit termination, `soft_warned` is zeroed, `INIT_LIST_HEAD` is called, and the entry is inserted via `list_add_tail` under the mutex.

**TODO 5 — `MONITOR_UNREGISTER` ioctl handler (remove)**
We use `list_for_each_entry_safe` again (required since we delete during iteration), matching on both `entry->pid == req.pid` and `strncmp` on `container_id`. On a match, `list_del` and `kfree` are performed under the mutex, a `found` flag is set, and we break early. If no match is found, `-ENOENT` is returned to give the caller a meaningful error.

**TODO 6 — `monitor_exit()` cleanup**
After `del_timer_sync` (which guarantees the timer callback has fully stopped before proceeding), we walk the list with `list_for_each_entry_safe` under the mutex, calling `list_del` and `kfree` on every remaining entry. This ensures no memory is leaked on `rmmod`, confirmed by `dmesg` logging a clean `Module unloaded.` with no errors.

---

## Demo Screenshots

### Screenshots 1 & 2 — Multi-Container Supervision and Metadata Tracking

Two containers (`alpha` and `beta`) launched under a single supervisor. The first `engine ps` shows `alpha` running (PID 8696, started 14:29:42). After launching `beta`, the second `engine ps` shows both `alpha` (PID 8696) and `beta` (PID 8710) in `running` state simultaneously under the same supervisor process.



---

### Screenshot 3 — Bounded-Buffer Logging

Container `alpha` was started with a shell loop command. After a 4-second sleep, `cat logs/alpha.log` shows multiple `hello from alpha` lines captured through the producer-consumer logging pipeline and written to a persistent per-container log file.



---

### Screenshot 4 — CLI and IPC

`engine ps` shows container `alpha` (PID 9095) in `running` state. `engine logs alpha` is then issued — both commands are sent over the UNIX domain socket control channel (`/tmp/mini_runtime.sock`) and the supervisor responds correctly. This demonstrates the CLI-to-supervisor IPC path (Path B) working.



---

### Screenshots 5 & 6 — Soft-Limit Warning and Hard-Limit Enforcement

`dmesg` output shows the kernel module detecting memory growth in container `memtest` (PID 13181):

- **Soft limit (Screenshot 5):** `SOFT LIMIT container=memtest pid=13181 rss=17362944 limit=10485760` — RSS exceeded the 10 MiB soft threshold, warning logged to kernel log
- **Hard limit (Screenshot 6):** `HARD LIMIT container=memtest pid=13181 rss=25743360 limit=20971520` — RSS exceeded the 20 MiB hard threshold, container killed with SIGKILL

`engine ps` at the bottom confirms `memtest` (PID 13181) is in state `killed` with exit code 137 (128 + SIGKILL), reflecting the hard-limit termination in supervisor metadata.



---

### Screenshot 7 — Scheduling Experiment

Two CPU-bound containers were launched concurrently: `high_prio` (nice=-5) and `low_prio` (nice=10). The `dmesg` output shows both containers being registered and completing in interleaved fashion, confirming concurrent execution under the Linux CFS scheduler. `engine ps` shows both tracked with exit code 0. The kernel registration timestamps show `high_prio` (pid=14299) receiving more CPU time due to its lower nice value compared to `low_prio` (pid=14314).



---

### Screenshot 8 — Clean Teardown

`sudo rmmod monitor` succeeds after the supervisor releases `/dev/container_monitor`. `lsmod | grep monitor` returns nothing confirming the module is fully unloaded. `sudo dmesg | tail -10` shows `[container_monitor] Module unloaded.` as the final kernel log entry, confirming all kernel list entries were freed cleanly. No zombie processes were found during shutdown.


---

## Engineering Analysis

### 1. Isolation Mechanisms

The runtime uses Linux namespaces to isolate containers:

- **PID namespace** (`CLONE_NEWPID`) isolates the container's process tree so processes inside see only their own PIDs starting from 1
- **UTS namespace** (`CLONE_NEWUTS`) isolates hostname and domain name per container
- **Mount namespace** (`CLONE_NEWNS`) isolates the mount table so containers see only their own filesystem mounts

Each container uses `chroot()` to restrict filesystem visibility to its own rootfs directory. `/proc` is mounted inside the container so that tools like `ps` work correctly. Although containers have separate process and filesystem views, the host kernel, kernel data structures, network stack, and physical hardware remain shared across all containers.

`pivot_root` would be more secure than `chroot` as it prevents escape via `..` traversal, but `chroot` is sufficient for this project scope.

---

### 2. Supervisor and Process Lifecycle

A long-running supervisor is necessary because multiple containers must be managed concurrently and their lifecycle must be tracked after they are launched.

The supervisor:

- Launches containers using `clone()` with namespace flags
- Maintains a metadata table for each container (ID, host PID, state, start time, memory limits, exit reason, log path)
- Handles `SIGCHLD` to reap exited children with `waitpid()`, preventing zombie processes
- Handles `SIGINT`/`SIGTERM` for orderly shutdown, stopping all containers before exiting
- Listens on a UNIX domain socket for CLI commands

The parent-child relationship is fundamental: only the direct parent can reap a child. The supervisor must remain alive as long as any container is running. If the supervisor exits early, containers become orphans and their exit status is lost.

---

### 3. IPC, Threads and Synchronization

Two separate IPC mechanisms are used as required.

**Path A — Logging (pipes):**
Container stdout and stderr are redirected to pipes at `clone()` time. Producer threads in the supervisor read from these pipe file descriptors and insert log entries into a shared bounded buffer. A consumer thread removes entries from the buffer and writes them to per-container log files (e.g., `logs/alpha.log`).

The bounded buffer uses a mutex for mutual exclusion on the buffer state and condition variables to block producers when the buffer is full and to wake the consumer when new data arrives. Without synchronization, concurrent producer threads would corrupt the buffer through unsynchronized read/write of head and tail pointers, and the consumer could read partially written entries.

**Path B — Control (UNIX domain socket):**
CLI client processes connect to the supervisor's UNIX domain socket at `/tmp/mini_runtime.sock`, send a `control_request_t` struct, receive one or more `control_response_t` messages, and exit. This is a separate IPC path from the logging pipes as required.

Shared container metadata is protected by a separate `metadata_lock` mutex, distinct from the log buffer lock, to avoid contention between the control path and the logging path.

---

### 4. Memory Management and Enforcement

The kernel module reads RSS (Resident Set Size) using `get_mm_rss()` on the container's `mm_struct`. RSS counts the number of pages currently resident in physical RAM. It does not count swapped-out pages, memory-mapped files not yet faulted in, or shared library pages mapped but not touched.

| Limit Type | Behavior |
|------------|----------|
| **Soft Limit** | Logs a `KERN_WARNING` to `dmesg` once when RSS first exceeds the configured threshold; `soft_warned` flag prevents duplicate warnings |
| **Hard Limit** | Sends `SIGKILL` via `send_sig()` to the container process when RSS exceeds the hard threshold; entry is removed from the kernel list |

Enforcement belongs in kernel space because user-space processes cannot reliably monitor or kill other processes without race conditions. The kernel module runs a periodic timer directly in kernel context, has direct access to process memory accounting via `get_mm_rss()`, and can send signals atomically without being subject to scheduling delays.

When the hard limit is triggered, the supervisor detects the `SIGKILL` via `SIGCHLD`, checks that `stop_requested` is not set, and records the termination reason as `CONTAINER_KILLED` in the metadata. This is visible in `engine ps` output as state `killed` with exit code 137.

---

### 5. Scheduling Behavior

Two CPU-bound containers were launched concurrently with different nice values:

- `high_prio`: `/cpu_hog` with `--nice -5`
- `low_prio`: `/cpu_hog` with `--nice 10`

The Linux Completely Fair Scheduler (CFS) uses nice values to adjust a process's virtual runtime weight. A lower nice value increases the weight, causing the scheduler to assign a larger share of CPU time. A higher nice value decreases the weight, reducing CPU share.

From dmesg timestamps, both containers were registered with the kernel module and ran concurrently. The `high_prio` container (nice=-5) received a larger CPU share from the scheduler while `low_prio` (nice=10) was deprioritized. This demonstrates CFS's goal of weighted fairness: processes with lower nice values receive proportionally more CPU time while higher nice value processes still make progress, just more slowly.

---

## Design Decisions and Tradeoffs

| Component | Choice | Tradeoff | Reason |
|-----------|--------|----------|--------|
| Filesystem Isolation | `chroot()` | Simpler than `pivot_root` but allows escape via `..` traversal | Sufficient isolation for project scope; simpler to implement correctly |
| Supervisor Architecture | Single long-running daemon with UNIX socket at `/tmp/mini_runtime.sock` | Centralized metadata handling; socket must be cleaned up on crash | Simplifies container lifecycle control and avoids split-brain state |
| Logging System | Bounded buffer (capacity 16) with per-container producer threads and one consumer thread writing to `logs/<id>.log` | Requires mutex + two condition variables; producer threads are detached | Decouples container output capture from disk I/O; no log lines dropped on abrupt container exit |
| Kernel Monitor | Periodic 1-second timer with `list_for_each_entry_safe()` over a mutex-protected linked list | 1-second granularity means enforcement is not instantaneous | Simple and reliable; safe variant handles concurrent deletion correctly |
| IPC for Control | UNIX domain socket with fixed-size binary request/response structs | Requires cleanup of socket file on crash; fixed struct size limits message length | Bidirectional, reliable, low-latency; binary structs avoid parsing complexity |
| Termination Classification | `stop_requested` flag checked in `sigchld_handler()` | Flag must be set before signalling for classification to be correct | Cleanly distinguishes manual stop, hard-limit kill, and natural exit in metadata |
| Kernel Lock Choice | `DEFINE_MUTEX` over spinlock in `monitor.c` | Mutex can sleep; spinlock cannot | Both `timer_callback` and `monitor_ioctl` run in sleepable (process) context, making mutex safe and avoiding unnecessary busy-waiting |

---

## Scheduler Experiment Results

Two CPU-bound containers were launched simultaneously with different scheduling priorities using the statically-linked `cpu_hog` workload.

| Workload | Nice Value | PID | Kernel Registration Timestamp | Notes |
|----------|------------|-----|-------------------------------|-------|
| high_prio | -5 | 14299 | 8598.886s | Higher CPU priority — larger CFS weight |
| low_prio | 10 | 14314 | 8605.481s | Lower CPU priority — smaller CFS weight |

Both containers ran concurrently as confirmed by overlapping kernel registration timestamps in `dmesg`. The Linux CFS scheduler assigned `high_prio` a larger vruntime weight due to its lower nice value, meaning it received more CPU time per scheduling period. `low_prio` with nice=10 received a reduced CPU share. This is consistent with CFS weighted fairness: throughput is biased toward higher-priority processes while lower-priority processes still make forward progress.

---

## Cleanup Verification

The project demonstrates full cleanup after shutdown:

- All container child processes are reaped via `SIGCHLD` handler using `waitpid(-1, WNOHANG)` — no zombie processes remain
- Logging producer threads exit when their container's pipe EOF is read; the consumer thread is joined by the supervisor via `pthread_join()` after `bounded_buffer_begin_shutdown()`
- File descriptors (pipes, socket, monitor device) are closed on all paths in `run_supervisor()` cleanup
- Kernel module `monitor_exit()` calls `del_timer_sync()`, walks the list to `list_del()` + `kfree()` all remaining entries, then tears down the device
- `sudo rmmod monitor` succeeds cleanly after the supervisor releases `/dev/container_monitor`
- `dmesg` confirms `[container_monitor] Module unloaded.` as the final kernel log entry with no errors
