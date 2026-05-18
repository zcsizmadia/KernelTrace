/*
 * kerneltrace.c — Native shim implementation wrapping libbpf.
 *
 * Each kt_* function is annotated with __attribute__((visibility("default")))
 * so only exported symbols appear in the shared library (all others are hidden
 * via -fvisibility=hidden in CMakeLists.txt).
 */

#include "kerneltrace.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

/* ── Visibility macro ────────────────────────────────────────────────────── */
#define KT_EXPORT __attribute__((visibility("default")))

/* ── Internal helpers ────────────────────────────────────────────────────── */

static kt_error_t kt_error_from_errno(int err)
{
    kt_error_t e;
    e.code = err ? err : -EINVAL;
    strerror_r(-e.code, e.message, KT_MAX_ERROR_LEN);
    return e;
}

static kt_error_t kt_ok_result(void)
{
    kt_error_t e = {0};
    return e;
}

static int libbpf_silent_print(enum libbpf_print_level level,
                               const char *fmt, va_list args)
{
    (void)level; (void)fmt; (void)args;
    return 0;
}

/* ── Internal structs ────────────────────────────────────────────────────── */

struct kt_session {
    struct bpf_object *obj;
};

struct kt_attachment {
    struct bpf_link *link;
};

/* ── Session lifecycle ───────────────────────────────────────────────────── */

KT_EXPORT
kt_session_t *kt_session_load(const char *path, kt_error_t *error_out)
{
    if (!path) {
        if (error_out) *error_out = kt_error_from_errno(-EINVAL);
        return NULL;
    }

    /* Suppress libbpf stderr chatter — .NET layer handles errors. */
    libbpf_set_print(libbpf_silent_print);

    /* Allow unlimited locked memory (needed for BPF maps on older kernels). */
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);

    LIBBPF_OPTS(bpf_object_open_opts, opts);
    struct bpf_object *obj = bpf_object__open_file(path, &opts);
    if (!obj) {
        if (error_out) *error_out = kt_error_from_errno(-errno);
        return NULL;
    }

    int err = bpf_object__load(obj);
    if (err) {
        if (error_out) *error_out = kt_error_from_errno(err);
        bpf_object__close(obj);
        return NULL;
    }

    kt_session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        if (error_out) *error_out = kt_error_from_errno(-ENOMEM);
        bpf_object__close(obj);
        return NULL;
    }
    s->obj = obj;
    if (error_out) *error_out = kt_ok_result();
    return s;
}

KT_EXPORT
void kt_session_close(kt_session_t *session)
{
    if (!session) return;
    if (session->obj) bpf_object__close(session->obj);
    free(session);
}

/* ── Probe attachment helpers ────────────────────────────────────────────── */

static kt_attachment_t *make_attachment(struct bpf_link *link, kt_error_t *out_err)
{
    if (!link) {
        if (out_err) *out_err = kt_error_from_errno(-errno);
        return NULL;
    }

    kt_attachment_t *a = calloc(1, sizeof(*a));
    if (!a) {
        bpf_link__destroy(link);
        if (out_err) *out_err = kt_error_from_errno(-ENOMEM);
        return NULL;
    }
    a->link = link;
    if (out_err) *out_err = kt_ok_result();
    return a;
}

static struct bpf_program *find_program_by_section(struct bpf_object *obj,
                                                   const char *section)
{
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (strcmp(bpf_program__section_name(prog), section) == 0)
            return prog;
    }
    return NULL;
}

/* ── Probe attachment ────────────────────────────────────────────────────── */

KT_EXPORT
kt_attachment_t *kt_attach_tracepoint(kt_session_t *session,
                                      const char   *category,
                                      const char   *name,
                                      kt_error_t   *error_out)
{
    if (!session || !category || !name) {
        if (error_out) *error_out = kt_error_from_errno(-EINVAL);
        return NULL;
    }

    /* Build the section name "tp/category/name" that the BPF program uses. */
    char section[256];
    snprintf(section, sizeof(section), "tp/%s/%s", category, name);

    struct bpf_program *prog = find_program_by_section(session->obj, section);
    if (!prog) {
        if (error_out) {
            error_out->code = -ENOENT;
            snprintf(error_out->message, KT_MAX_ERROR_LEN,
                     "No BPF program found with section '%.218s'", section);
        }
        return NULL;
    }

    return make_attachment(bpf_program__attach(prog), error_out);
}

KT_EXPORT
kt_attachment_t *kt_attach_kprobe(kt_session_t *session,
                                  const char   *func_name,
                                  int           ret_probe,
                                  kt_error_t   *error_out)
{
    if (!session || !func_name) {
        if (error_out) *error_out = kt_error_from_errno(-EINVAL);
        return NULL;
    }

    const char *prefix = ret_probe ? "kretprobe" : "kprobe";
    char section[256];
    snprintf(section, sizeof(section), "%s/%s", prefix, func_name);

    struct bpf_program *prog = find_program_by_section(session->obj, section);
    if (!prog) {
        if (error_out) {
            error_out->code = -ENOENT;
            snprintf(error_out->message, KT_MAX_ERROR_LEN,
                     "No BPF program found with section '%.218s'", section);
        }
        return NULL;
    }

    return make_attachment(bpf_program__attach(prog), error_out);
}

KT_EXPORT
kt_attachment_t *kt_attach_uprobe(kt_session_t *session,
                                  const char   *binary_path,
                                  uint64_t      offset,
                                  int           ret_probe,
                                  const char   *prog_section,
                                  kt_error_t   *error_out)
{
    if (!session || !binary_path) {
        if (error_out) *error_out = kt_error_from_errno(-EINVAL);
        return NULL;
    }

    struct bpf_program *prog = NULL;
    const char *prefix = ret_probe ? "uretprobe" : "uprobe";

    if (prog_section) {
        /* Caller specified an exact section — find it. */
        prog = find_program_by_section(session->obj, prog_section);
        if (!prog) {
            if (error_out) {
                error_out->code = -ENOENT;
                snprintf(error_out->message, KT_MAX_ERROR_LEN,
                         "No BPF program found with section '%.218s'", prog_section);
            }
            return NULL;
        }
    } else {
        /* Fall back: use the first uprobe/uretprobe section found. */
        struct bpf_program *p;
        bpf_object__for_each_program(p, session->obj) {
            const char *sec = bpf_program__section_name(p);
            if (strncmp(sec, prefix, strlen(prefix)) == 0) {
                prog = p;
                break;
            }
        }
    }

    if (!prog) {
        if (error_out) {
            error_out->code = -ENOENT;
            snprintf(error_out->message, KT_MAX_ERROR_LEN,
                     "No BPF program found for uprobe in '%.218s'", binary_path);
        }
        return NULL;
    }

    struct bpf_link *link = bpf_program__attach_uprobe(prog, ret_probe,
                                                        -1 /* all PIDs */,
                                                        binary_path, offset);
    return make_attachment(link, error_out);
}

KT_EXPORT
void kt_detach(kt_attachment_t *attachment)
{
    if (!attachment) return;
    if (attachment->link) bpf_link__destroy(attachment->link);
    free(attachment);
}

/* ── Per-process filter ──────────────────────────────────────────────────── */

KT_EXPORT
void kt_session_set_tgid_filter(kt_session_t *session, uint32_t tgid,
                                kt_error_t *error_out)
{
    if (!session) {
        if (error_out) *error_out = kt_error_from_errno(-EINVAL);
        return;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(session->obj, "kt_tgid_filter");
    if (!map) {
        if (error_out) {
            error_out->code = -ENOENT;
            snprintf(error_out->message, KT_MAX_ERROR_LEN,
                     "BPF map 'kt_tgid_filter' not found — probe not compiled with common.h");
        }
        return;
    }

    int fd  = bpf_map__fd(map);
    __u32 key = 0;
    int err = bpf_map_update_elem(fd, &key, &tgid, BPF_ANY);
    if (error_out) {
        if (err)
            *error_out = kt_error_from_errno(err);
        else
            *error_out = kt_ok_result();
    }
}

/* ── Ring buffer ─────────────────────────────────────────────────────────── */

KT_EXPORT
int kt_get_ringbuf_fd(kt_session_t *session, const char *map_name,
                      kt_error_t *error_out)
{
    if (!session || !map_name) {
        if (error_out) *error_out = kt_error_from_errno(-EINVAL);
        return -EINVAL;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(session->obj, map_name);
    if (!map) {
        if (error_out) {
            error_out->code = -ENOENT;
            snprintf(error_out->message, KT_MAX_ERROR_LEN,
                     "BPF map '%.218s' not found", map_name);
        }
        return -ENOENT;
    }

    if (error_out) *error_out = kt_ok_result();
    return bpf_map__fd(map);
}

KT_EXPORT
void *kt_mmap_ringbuf(int fd, uint64_t *total_size_out, uint64_t *data_size_out,
                      kt_error_t *error_out)
{
    if (fd < 0 || !total_size_out || !data_size_out) {
        if (error_out) *error_out = kt_error_from_errno(-EINVAL);
        return NULL;
    }

    /* Query the ring buffer data size from the kernel via BPF syscall. */
    struct bpf_map_info info;
    memset(&info, 0, sizeof(info));
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
        if (error_out) *error_out = kt_error_from_errno(-errno);
        return NULL;
    }

    uint64_t data_size = info.max_entries;
    long ps = sysconf(_SC_PAGE_SIZE);
    uint64_t page_size = ps > 0 ? (uint64_t)ps : 4096ULL;

    /*
     * The kernel forbids PROT_WRITE on the producer page and data region.
     * Use three separate mmap calls:
     *   1. Reserve a contiguous VA range with PROT_NONE / MAP_ANONYMOUS.
     *   2. Map consumer page (offset 0) as PROT_READ|PROT_WRITE — the
     *      consumer writes its read-position here to advance the ring.
     *   3. Map producer page + data x2 (offset page_size) as PROT_READ —
     *      consumer only reads these.
     */
    uint64_t total = page_size * 2 + data_size * 2;

    /* Step 1: reserve contiguous VA. */
    void *base = mmap(NULL, (size_t)total, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        if (error_out) *error_out = kt_error_from_errno(-errno);
        return NULL;
    }

    /* Step 2: consumer page — read/write. */
    void *p = mmap(base, (size_t)page_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_FIXED, fd, 0);
    if (p == MAP_FAILED) {
        int e = errno;
        munmap(base, (size_t)total);
        if (error_out) *error_out = kt_error_from_errno(-e);
        return NULL;
    }

    /* Step 3: producer page + data (x2) — read-only. */
    size_t ro_size = (size_t)(page_size + data_size * 2);
    p = mmap((char *)base + page_size, ro_size, PROT_READ,
             MAP_SHARED | MAP_FIXED, fd, (off_t)page_size);
    if (p == MAP_FAILED) {
        int e = errno;
        munmap(base, (size_t)total);
        if (error_out) *error_out = kt_error_from_errno(-e);
        return NULL;
    }

    *total_size_out = total;
    *data_size_out  = data_size;
    if (error_out) *error_out = kt_ok_result();
    return base;
}

KT_EXPORT
void kt_munmap(void *addr, uint64_t total_size)
{
    if (addr) munmap(addr, (size_t)total_size);
}

/* ── epoll helpers ───────────────────────────────────────────────────────── */

KT_EXPORT
int kt_create_epoll(int ringbuf_fd, kt_error_t *error_out)
{
    if (ringbuf_fd < 0) {
        if (error_out) *error_out = kt_error_from_errno(-EINVAL);
        return -EINVAL;
    }

    int efd = epoll_create1(EPOLL_CLOEXEC);
    if (efd < 0) {
        if (error_out) *error_out = kt_error_from_errno(-errno);
        return -errno;
    }

    struct epoll_event ev = {
        .events  = EPOLLIN,
        .data.fd = ringbuf_fd,
    };
    if (epoll_ctl(efd, EPOLL_CTL_ADD, ringbuf_fd, &ev) < 0) {
        int err = errno;
        close(efd);
        if (error_out) *error_out = kt_error_from_errno(-err);
        return -err;
    }
    if (error_out) *error_out = kt_ok_result();
    return efd;
}

KT_EXPORT
int kt_poll(int epoll_fd, int timeout_ms)
{
    if (epoll_fd < 0) return -EINVAL;

    struct epoll_event events[8];
    int n = epoll_wait(epoll_fd, events, 8, timeout_ms);
    if (n < 0) return -errno;
    return n;
}

/* ── Utilities ───────────────────────────────────────────────────────────── */

KT_EXPORT
void kt_close_fd(int fd)
{
    if (fd >= 0) close(fd);
}

KT_EXPORT
uint64_t kt_get_page_size(void)
{
    long ps = sysconf(_SC_PAGE_SIZE);
    return ps > 0 ? (uint64_t)ps : 4096ULL;
}

KT_EXPORT
int kt_btf_struct_size(kt_session_t *session, const char *struct_name)
{
    (void)session; /* reserved for future object-local BTF lookup */
    if (!struct_name) return -EINVAL;

    /* Load the vmlinux BTF (requires /sys/kernel/btf/vmlinux). */
    struct btf *vmlinux_btf = btf__load_vmlinux_btf();
    if (!vmlinux_btf) return -ENOENT;

    int result = -ENOENT;
    int nr = btf__type_cnt(vmlinux_btf);
    for (int i = 1; i < nr; i++) {
        const struct btf_type *t = btf__type_by_id(vmlinux_btf, i);
        if (!t) continue;
        if (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT) continue;

        const char *name = btf__name_by_offset(vmlinux_btf, t->name_off);
        if (name && strcmp(name, struct_name) == 0) {
            result = (int)t->size;
            break;
        }
    }

    btf__free(vmlinux_btf);
    return result;
}

/* ── BPF map operations ──────────────────────────────────────────────────── */

KT_EXPORT
int kt_map_get_fd(kt_session_t *session, const char *map_name,
                  kt_error_t *error_out)
{
    if (!session || !map_name) {
        if (error_out) *error_out = kt_error_from_errno(EINVAL);
        return -EINVAL;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(session->obj, map_name);
    if (!map) {
        if (error_out) {
            error_out->code = -ENOENT;
            snprintf(error_out->message, KT_MAX_ERROR_LEN,
                     "BPF map '%s' not found in loaded object", map_name);
        }
        return -ENOENT;
    }

    int fd = bpf_map__fd(map);
    if (fd < 0) {
        if (error_out) *error_out = kt_error_from_errno(-fd);
    } else {
        if (error_out) *error_out = kt_ok_result();
    }
    return fd;
}

KT_EXPORT
kt_error_t kt_map_get_info(int map_fd, kt_map_info_t *info_out)
{
    if (!info_out) return kt_error_from_errno(EINVAL);

    struct bpf_map_info info;
    uint32_t info_len = sizeof(info);
    memset(&info, 0, sizeof(info));

    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) < 0) {
        return kt_error_from_errno(errno);
    }

    info_out->type        = info.type;
    info_out->key_size    = info.key_size;
    info_out->value_size  = info.value_size;
    info_out->max_entries = info.max_entries;
    return kt_ok_result();
}

KT_EXPORT
int kt_map_lookup(int map_fd, const void *key, void *value_out)
{
    return bpf_map_lookup_elem(map_fd, key, value_out);
}

KT_EXPORT
int kt_map_update(int map_fd, const void *key, const void *value,
                  uint64_t flags)
{
    return bpf_map_update_elem(map_fd, key, value, flags);
}

KT_EXPORT
int kt_map_delete(int map_fd, const void *key)
{
    return bpf_map_delete_elem(map_fd, key);
}

KT_EXPORT
int kt_map_get_next_key(int map_fd, const void *key, void *next_key_out)
{
    return bpf_map_get_next_key(map_fd, key, next_key_out);
}

/* ── USDT probes ─────────────────────────────────────────────────────────── */

KT_EXPORT
kt_attachment_t *kt_attach_usdt(
    kt_session_t *session,
    int           pid,
    const char   *binary_path,
    const char   *usdt_provider,
    const char   *usdt_name,
    const char   *prog_section,
    kt_error_t   *error_out)
{
    if (!session || !binary_path || !usdt_provider || !usdt_name) {
        if (error_out) *error_out = kt_error_from_errno(EINVAL);
        return NULL;
    }

    struct bpf_program *prog = NULL;

    if (prog_section) {
        /* Try by program (function) name first. */
        prog = bpf_object__find_program_by_name(session->obj, prog_section);
        if (!prog) {
            /* Fall back to matching the section name. */
            struct bpf_program *p;
            bpf_object__for_each_program(p, session->obj) {
                const char *sec = bpf_program__section_name(p);
                if (sec && strcmp(sec, prog_section) == 0) {
                    prog = p;
                    break;
                }
            }
        }
        if (!prog) {
            if (error_out) {
                error_out->code = -ENOENT;
                snprintf(error_out->message, KT_MAX_ERROR_LEN,
                         "BPF program '%s' not found", prog_section);
            }
            return NULL;
        }
    } else {
        /* Find the first program whose section starts with "usdt". */
        struct bpf_program *p;
        bpf_object__for_each_program(p, session->obj) {
            const char *sec = bpf_program__section_name(p);
            if (sec && strncmp(sec, "usdt", 4) == 0) {
                prog = p;
                break;
            }
        }
        if (!prog) {
            if (error_out) {
                error_out->code = -ENOENT;
                snprintf(error_out->message, KT_MAX_ERROR_LEN,
                         "No USDT BPF program found in loaded object");
            }
            return NULL;
        }
    }

    struct bpf_link *link = bpf_program__attach_usdt(
        prog, pid, binary_path, usdt_provider, usdt_name, NULL);

    if (!link) {
        if (error_out) *error_out = kt_error_from_errno(errno ? errno : EINVAL);
        return NULL;
    }

    kt_attachment_t *att = calloc(1, sizeof(*att));
    if (!att) {
        bpf_link__destroy(link);
        if (error_out) *error_out = kt_error_from_errno(ENOMEM);
        return NULL;
    }

    att->link = link;
    if (error_out) *error_out = kt_ok_result();
    return att;
}

/* ── CO-RE / Extended session loading ───────────────────────────────────── */

KT_EXPORT
kt_session_t *kt_session_load_ext(const char              *path,
                                   const kt_session_opts_t *opts,
                                   kt_error_t              *error_out)
{
    if (!path) {
        if (error_out) *error_out = kt_error_from_errno(EINVAL);
        return NULL;
    }

    /* Restore default stderr printing when debug output is requested. */
    if (opts && opts->debug_output) {
        libbpf_set_print(NULL);
    }

    struct bpf_object_open_opts open_opts;
    memset(&open_opts, 0, sizeof(open_opts));
    open_opts.sz = sizeof(open_opts);
    if (opts && opts->btf_custom_path) {
        open_opts.btf_custom_path = opts->btf_custom_path;
    }

    struct bpf_object *obj = bpf_object__open_file(path, &open_opts);
    if (!obj) {
        if (error_out) *error_out = kt_error_from_errno(errno ? errno : EINVAL);
        if (opts && opts->debug_output) libbpf_set_print(libbpf_silent_print);
        return NULL;
    }

    if (bpf_object__load(obj) < 0) {
        int err = errno;
        bpf_object__close(obj);
        if (error_out) *error_out = kt_error_from_errno(err ? err : EINVAL);
        if (opts && opts->debug_output) libbpf_set_print(libbpf_silent_print);
        return NULL;
    }

    /* Re-suppress output for subsequent operations. */
    if (opts && opts->debug_output) {
        libbpf_set_print(libbpf_silent_print);
    }

    kt_session_t *session = calloc(1, sizeof(*session));
    if (!session) {
        bpf_object__close(obj);
        if (error_out) *error_out = kt_error_from_errno(ENOMEM);
        return NULL;
    }

    session->obj = obj;
    if (error_out) *error_out = kt_ok_result();
    return session;
}

KT_EXPORT
int kt_btf_available(void)
{
    struct btf *btf = btf__load_vmlinux_btf();
    if (!btf) return 0;
    btf__free(btf);
    return 1;
}
