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
kt_error_t kt_session_load(const char *path, kt_session_t **out);

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
kt_error_t kt_attach_tracepoint(
    kt_session_t    *session,
    const char      *category,
    const char      *name,
    kt_attachment_t **out);

/**
 * Attach a BPF program to a kprobe (or kretprobe).
 *
 * @param  session      Active session.
 * @param  func_name    Kernel function name.
 * @param  ret_probe    Non-zero to attach a kretprobe instead of kprobe.
 * @param  out          Receives the attachment handle on success.
 */
kt_error_t kt_attach_kprobe(
    kt_session_t    *session,
    const char      *func_name,
    int              ret_probe,
    kt_attachment_t **out);

/**
 * Attach a BPF program to a user-space uprobe (or uretprobe).
 *
 * @param  session       Active session.
 * @param  binary_path   Absolute path to the target ELF binary / library.
 * @param  offset        Byte offset of the probe point within the binary.
 * @param  ret_probe     Non-zero to attach a uretprobe.
 * @param  prog_section  Optional BPF program section name (e.g. "uprobe/gc_start").
 *                       Pass NULL to use the first uprobe section found.
 * @param  out           Receives the attachment handle on success.
 */
kt_error_t kt_attach_uprobe(
    kt_session_t    *session,
    const char      *binary_path,
    uint64_t         offset,
    int              ret_probe,
    const char      *prog_section,
    kt_attachment_t **out);

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
kt_error_t kt_session_set_tgid_filter(kt_session_t *session, uint32_t tgid);

/* ── Ring buffer ─────────────────────────────────────────────────────────── */

/**
 * Return the file descriptor of the named BPF ring-buffer map.
 *
 * @param  session   Active session.
 * @param  map_name  Name of the BPF_MAP_TYPE_RINGBUF map (e.g. "events").
 * @return           A valid fd >= 0, or a negative errno on error.
 */
int kt_get_ringbuf_fd(kt_session_t *session, const char *map_name);

/**
 * mmap the ring-buffer memory for direct read access.
 *
 * Returns the base pointer of the mmap region on success, or NULL on error.
 * The caller is responsible for calling kt_munmap() when done.
 *
 * Layout (per kernel ring-buffer spec):
 *   [consumer page] [producer page] [data pages × 2 (mirrored)]
 *
 * @param  fd        Ring-buffer map fd.
 * @param  data_size Number of data bytes (must be a power-of-two multiple of page_size).
 * @param  page_size System page size.
 */
void *kt_mmap_ringbuf(int fd, uint64_t data_size, uint64_t page_size);

/**
 * Unmap a ring-buffer region created with kt_mmap_ringbuf.
 *
 * @param  addr       Base pointer returned by kt_mmap_ringbuf.
 * @param  data_size  Same data_size passed to kt_mmap_ringbuf.
 * @param  page_size  System page size.
 */
void kt_munmap(void *addr, uint64_t data_size, uint64_t page_size);

/* ── epoll helpers ───────────────────────────────────────────────────────── */

/**
 * Create an epoll file descriptor and add the ring-buffer fd to it.
 *
 * @param  ringbuf_fd  Ring-buffer map fd.
 * @return             epoll fd >= 0, or a negative errno.
 */
int kt_create_epoll(int ringbuf_fd);

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
int kt_btf_struct_size(const char *struct_name);

#ifdef __cplusplus
}
#endif
