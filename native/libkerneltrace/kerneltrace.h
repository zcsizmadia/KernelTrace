/*
 * kerneltrace.h — Public C API for the KernelTrace native shim.
 *
 * This shim wraps libbpf and provides a stable ABI consumed by the .NET
 * P/Invoke layer (KernelTrace.Interop.NativeMethods).
 *
 * All functions are thread-compatible but NOT thread-safe.  The caller
 * (the .NET layer) serialises concurrent access via managed locks.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error reporting ─────────────────────────────────────────────────────── */

#define KT_MAX_ERROR_LEN 256

/** Error descriptor.  Returned by-value; zero Code means success. */
typedef struct kt_error {
    int32_t  code;                   /**< errno-style negative code, or 0 */
    char     message[KT_MAX_ERROR_LEN];
} kt_error_t;

static inline int kt_ok(kt_error_t e) { return e.code == 0; }

/* ── Opaque handles ──────────────────────────────────────────────────────── */

/** Represents a loaded BPF skeleton / object file session. */
typedef struct kt_session kt_session_t;

/** Represents a single probe attachment (tracepoint / kprobe / uprobe). */
typedef struct kt_attachment kt_attachment_t;

/* ── Session lifecycle ───────────────────────────────────────────────────── */

/**
 * Load a compiled BPF object file (.bpf.o) into the kernel.
 *
 * @param  path   Absolute path to the .bpf.o file.
 * @param  out    Receives the session handle on success.
 * @return        Error descriptor (code == 0 on success).
 */
kt_session_t *kt_session_load(const char *path, kt_error_t *error_out);

/**
 * Unload the BPF object and free all kernel resources.
 * After this call the handle must not be used.
 */
void kt_session_close(kt_session_t *session);

/* ── Probe attachment ────────────────────────────────────────────────────── */

/**
 * Attach a BPF program to a kernel tracepoint.
 *
 * @param  session    Active session.
 * @param  category   Tracepoint category (e.g. "syscalls").
 * @param  name       Tracepoint name  (e.g. "sys_enter_connect").
 * @param  out        Receives the attachment handle on success.
 */
kt_attachment_t *kt_attach_tracepoint(
    kt_session_t *session,
    const char   *category,
    const char   *name,
    kt_error_t   *error_out);

/**
 * Attach a BPF program to a kprobe (or kretprobe).
 *
 * @param  session      Active session.
 * @param  func_name    Kernel function name.
 * @param  ret_probe    Non-zero to attach a kretprobe instead of kprobe.
 * @param  error_out    Receives error details on failure; may be NULL.
 * @return              Attachment handle, or NULL on failure.
 */
kt_attachment_t *kt_attach_kprobe(
    kt_session_t *session,
    const char   *func_name,
    int           ret_probe,
    kt_error_t   *error_out);

/**
 * Attach a BPF program to a user-space uprobe (or uretprobe).
 *
 * @param  session       Active session.
 * @param  binary_path   Absolute path to the target ELF binary / library.
 * @param  offset        Byte offset of the probe point within the binary.
 * @param  ret_probe     Non-zero to attach a uretprobe.
 * @param  prog_section  Optional BPF program section name. NULL = first uprobe found.
 * @param  error_out     Receives error details on failure; may be NULL.
 * @return               Attachment handle, or NULL on failure.
 */
kt_attachment_t *kt_attach_uprobe(
    kt_session_t *session,
    const char   *binary_path,
    uint64_t      offset,
    int           ret_probe,
    const char   *prog_section,
    kt_error_t   *error_out);

/**
 * Detach a previously attached probe and free associated kernel resources.
 */
void kt_detach(kt_attachment_t *attachment);

/* ── Per-process filter ──────────────────────────────────────────────────── */

/**
 * Restrict event emission to a single process.
 *
 * When @p tgid is non-zero, the "kt_tgid_filter" BPF array map is updated so
 * that every probe handler's kt_should_trace() check drops events from all
 * other processes.  Pass 0 to clear the filter and resume system-wide tracing.
 *
 * Typically called with @c getpid() immediately after kt_session_load() when
 * SessionOptions.CurrentProcessOnly is true.
 *
 * Note: loading a BPF program still requires CAP_BPF + CAP_PERFMON (or root)
 * regardless of whether a filter is active.
 *
 * @param  session  Active session.
 * @param  tgid     Process (thread-group) ID to trace, or 0 for all.
 * @return          Error descriptor (code == 0 on success).
 */
void kt_session_set_tgid_filter(kt_session_t *session, uint32_t tgid, kt_error_t *error_out);

/* ── Ring buffer ─────────────────────────────────────────────────────────── */

/**
 * Return the file descriptor of the named BPF ring-buffer map.
 *
 * @param  session   Active session.
 * @param  map_name  Name of the BPF_MAP_TYPE_RINGBUF map (e.g. "events").
 * @return           A valid fd >= 0, or a negative errno on error.
 */
int kt_get_ringbuf_fd(kt_session_t *session, const char *map_name,
                      kt_error_t *error_out);

/**
 * mmap the ring-buffer memory for direct read access.
 *
 * Queries the map size via BPF syscall, then maps the full region.
 * The caller is responsible for calling kt_munmap() with the returned
 * total_size when done.
 *
 * @param  fd             Ring-buffer map fd.
 * @param  total_size_out Receives the total mmap byte count.
 * @param  data_size_out  Receives the data-region byte count.
 * @param  error_out      Receives error details on failure; may be NULL.
 * @return                Base pointer of the mmap region, or NULL on error.
 */
void *kt_mmap_ringbuf(int fd,
                      uint64_t   *total_size_out,
                      uint64_t   *data_size_out,
                      kt_error_t *error_out);

/**
 * Unmap a ring-buffer region created with kt_mmap_ringbuf.
 *
 * @param  addr        Base pointer returned by kt_mmap_ringbuf.
 * @param  total_size  The total_size_out value from kt_mmap_ringbuf.
 */
void kt_munmap(void *addr, uint64_t total_size);

/* ── epoll helpers ───────────────────────────────────────────────────────── */

/**
 * Create an epoll file descriptor and add the ring-buffer fd to it.
 *
 * @param  ringbuf_fd  Ring-buffer map fd.
 * @param  error_out   Receives error details on failure; may be NULL.
 * @return             epoll fd >= 0, or a negative errno.
 */
int kt_create_epoll(int ringbuf_fd, kt_error_t *error_out);

/**
 * Wait for events on the epoll fd.
 *
 * @param  epoll_fd    Epoll fd created by kt_create_epoll.
 * @param  timeout_ms  Milliseconds to block (0 = no wait, -1 = forever).
 * @return             Number of ready events (0 = timeout), or negative errno.
 */
int kt_poll(int epoll_fd, int timeout_ms);

/* ── Utilities ───────────────────────────────────────────────────────────── */

/** Close a file descriptor. */
void kt_close_fd(int fd);

/** Return the system page size in bytes. */
uint64_t kt_get_page_size(void);

/**
 * Query the kernel BTF (BPF Type Format) for the byte size of a struct.
 *
 * @param  struct_name  Name of the struct as defined in the BPF program.
 * @return              Byte size >= 0, or a negative errno if not found.
 */
int kt_btf_struct_size(kt_session_t *session, const char *struct_name);

/* ── BPF map operations ──────────────────────────────────────────────────── */

/** Metadata returned by @c kt_map_get_info. */
typedef struct kt_map_info {
    uint32_t type;        /**< BPF map type (BPF_MAP_TYPE_*). */
    uint32_t key_size;    /**< Size of one key in bytes. */
    uint32_t value_size;  /**< Size of one value in bytes. */
    uint32_t max_entries; /**< Maximum number of entries. */
} kt_map_info_t;

/**
 * Returns the file descriptor of any named BPF map in the loaded session.
 * Unlike @c kt_get_ringbuf_fd this works for any map type.
 *
 * @param session   Active session.
 * @param map_name  Map name as declared in the BPF source (e.g. @c "stacks").
 * @param error_out Receives error details on failure; may be NULL.
 * @return          A valid fd >= 0, or a negative errno on error.
 */
int kt_map_get_fd(kt_session_t *session, const char *map_name,
                  kt_error_t *error_out);

/**
 * Queries the kernel for map metadata (type, key/value sizes, max entries).
 *
 * @param map_fd   File descriptor of the BPF map.
 * @param info_out Receives the map metadata on success; must not be NULL.
 * @return         Error descriptor (code == 0 on success).
 */
kt_error_t kt_map_get_info(int map_fd, kt_map_info_t *info_out);

/**
 * Looks up a single entry in a BPF map.
 * Returns 0 on success, -ENOENT if the key does not exist.
 */
int kt_map_lookup(int map_fd, const void *key, void *value_out);

/**
 * Inserts or updates an entry in a BPF map.
 * @p flags: 0 = any, @c BPF_NOEXIST = insert only, @c BPF_EXIST = update only.
 * Returns 0 on success.
 */
int kt_map_update(int map_fd, const void *key, const void *value,
                  uint64_t flags);

/**
 * Deletes an entry from a BPF map.
 * Returns 0 on success, -ENOENT if the key did not exist.
 */
int kt_map_delete(int map_fd, const void *key);

/**
 * Iterates map keys in no particular order.
 * Pass NULL for @p key to get the first key.
 * Returns 0 on success, -ENOENT when there are no more keys.
 */
int kt_map_get_next_key(int map_fd, const void *key, void *next_key_out);

/* ── USDT probes ─────────────────────────────────────────────────────────── */

/**
 * Attaches a BPF program to a USDT (Userland Statically Defined Trace) probe.
 *
 * Requires libbpf >= 1.0. The BPF program section must start with @c "usdt".
 *
 * @param session       Active session.
 * @param pid           Process ID to trace, or -1 for all processes.
 * @param binary_path   Absolute path to the binary containing the USDT probe.
 * @param usdt_provider USDT provider name (e.g. @c "python").
 * @param usdt_name     USDT probe name (e.g. @c "function__entry").
 * @param prog_section  BPF program function name; NULL = first usdt program.
 * @param error_out     Receives error details on failure; may be NULL.
 * @return              Attachment handle, or NULL on failure.
 */
kt_attachment_t *kt_attach_usdt(
    kt_session_t *session,
    int           pid,
    const char   *binary_path,
    const char   *usdt_provider,
    const char   *usdt_name,
    const char   *prog_section,
    kt_error_t   *error_out);

/* ── CO-RE / Extended session loading ───────────────────────────────────── */

/** Extended options for @c kt_session_load_ext. Pass NULL for defaults. */
typedef struct kt_session_opts {
    const char *btf_custom_path; /**< Path to a custom BTF file, or NULL. */
    int         debug_output;    /**< Non-zero to enable libbpf debug output. */
} kt_session_opts_t;

/**
 * Like @c kt_session_load but accepts extended CO-RE options.
 * When @p opts is NULL, behaves identically to @c kt_session_load.
 */
kt_session_t *kt_session_load_ext(const char              *path,
                                   const kt_session_opts_t *opts,
                                   kt_error_t              *error_out);

/**
 * Checks whether vmlinux BTF is available on the running kernel.
 *
 * @return 1 if @c /sys/kernel/btf/vmlinux is present and readable, 0 otherwise.
 */
int kt_btf_available(void);

#ifdef __cplusplus
}
#endif
