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
kt_error_t kt_session_load(const char *path, kt_session_t **out)
{
    if (!path || !out)
        return kt_error_from_errno(-EINVAL);

    /* Suppress libbpf stderr chatter — .NET layer handles errors. */
    libbpf_set_print(libbpf_silent_print);

    /* Allow unlimited locked memory (needed for BPF maps on older kernels). */
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);

    LIBBPF_OPTS(bpf_object_open_opts, opts);
    struct bpf_object *obj = bpf_object__open_opts(path, &opts);
    if (!obj || IS_ERR(obj)) {
        return kt_error_from_errno((int)PTR_ERR(obj));
    }

    int err = bpf_object__load(obj);
    if (err) {
        bpf_object__close(obj);
        return kt_error_from_errno(err);
    }

    kt_session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        bpf_object__close(obj);
        return kt_error_from_errno(-ENOMEM);
    }
    s->obj = obj;
    *out = s;
    return kt_ok_result();
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
    if (!link || IS_ERR(link)) {
        *out_err = kt_error_from_errno((int)PTR_ERR(link));
        return NULL;
    }

    kt_attachment_t *a = calloc(1, sizeof(*a));
    if (!a) {
        bpf_link__destroy(link);
        *out_err = kt_error_from_errno(-ENOMEM);
        return NULL;
    }
    a->link = link;
    *out_err = kt_ok_result();
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
kt_error_t kt_attach_tracepoint(kt_session_t *session,
                                 const char   *category,
                                 const char   *name,
                                 kt_attachment_t **out)
{
    if (!session || !category || !name || !out)
        return kt_error_from_errno(-EINVAL);

    /* Build the section name "tp/category/name" that the BPF program uses. */
    char section[256];
    snprintf(section, sizeof(section), "tp/%s/%s", category, name);

    struct bpf_program *prog = find_program_by_section(session->obj, section);
    if (!prog) {
        kt_error_t e;
        e.code = -ENOENT;
        snprintf(e.message, KT_MAX_ERROR_LEN,
                 "No BPF program found with section '%s'", section);
        return e;
    }

    kt_error_t err;
    *out = make_attachment(bpf_program__attach(prog), &err);
    return err;
}

KT_EXPORT
kt_error_t kt_attach_kprobe(kt_session_t    *session,
                             const char      *func_name,
                             int              ret_probe,
                             kt_attachment_t **out)
{
    if (!session || !func_name || !out)
        return kt_error_from_errno(-EINVAL);

    const char *prefix = ret_probe ? "kretprobe" : "kprobe";
    char section[256];
    snprintf(section, sizeof(section), "%s/%s", prefix, func_name);

    struct bpf_program *prog = find_program_by_section(session->obj, section);
    if (!prog) {
        kt_error_t e;
        e.code = -ENOENT;
        snprintf(e.message, KT_MAX_ERROR_LEN,
                 "No BPF program found with section '%s'", section);
        return e;
    }

    kt_error_t err;
    *out = make_attachment(bpf_program__attach(prog), &err);
    return err;
}

KT_EXPORT
kt_error_t kt_attach_uprobe(kt_session_t    *session,
                             const char      *binary_path,
                             uint64_t         offset,
                             int              ret_probe,
                             const char      *prog_section,
                             kt_attachment_t **out)
{
    if (!session || !binary_path || !out)
        return kt_error_from_errno(-EINVAL);

    struct bpf_program *prog = NULL;
    const char *prefix = ret_probe ? "uretprobe" : "uprobe";

    if (prog_section) {
        /* Caller specified an exact section — find it. */
        prog = find_program_by_section(session->obj, prog_section);
        if (!prog) {
            kt_error_t e;
            e.code = -ENOENT;
            snprintf(e.message, KT_MAX_ERROR_LEN,
                     "No BPF program found with section '%s'", prog_section);
            return e;
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
        kt_error_t e;
        e.code = -ENOENT;
        snprintf(e.message, KT_MAX_ERROR_LEN,
                 "No BPF program found for uprobe in '%s'", binary_path);
        return e;
    }

    struct bpf_link *link = bpf_program__attach_uprobe(prog, ret_probe,
                                                        -1 /* all PIDs */,
                                                        binary_path, offset);
    kt_error_t err;
    *out = make_attachment(link, &err);
    return err;
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
kt_error_t kt_session_set_tgid_filter(kt_session_t *session, uint32_t tgid)
{
    if (!session)
        return kt_error_from_errno(-EINVAL);

    struct bpf_map *map = bpf_object__find_map_by_name(session->obj, "kt_tgid_filter");
    if (!map) {
        kt_error_t e;
        e.code = -ENOENT;
        snprintf(e.message, KT_MAX_ERROR_LEN,
                 "BPF map 'kt_tgid_filter' not found — probe not compiled with common.h");
        return e;
    }

    int fd  = bpf_map__fd(map);
    __u32 key = 0;
    int err = bpf_map_update_elem(fd, &key, &tgid, BPF_ANY);
    if (err)
        return kt_error_from_errno(err);

    return kt_ok_result();
}

/* ── Ring buffer ─────────────────────────────────────────────────────────── */

KT_EXPORT
int kt_get_ringbuf_fd(kt_session_t *session, const char *map_name)
{
    if (!session || !map_name) return -EINVAL;

    struct bpf_map *map = bpf_object__find_map_by_name(session->obj, map_name);
    if (!map) return -ENOENT;

    return bpf_map__fd(map);
}

KT_EXPORT
void *kt_mmap_ringbuf(int fd, uint64_t data_size, uint64_t page_size)
{
    if (fd < 0 || data_size == 0 || page_size == 0) return NULL;

    /*
     * Ring buffer mmap layout (kernel docs/bpf/ringbuf.rst):
     *   page 0             : consumer page  (read consumer position)
     *   page 1             : producer page  (read producer position)
     *   pages 2 .. N+1     : data           (first copy)
     *   pages N+2 .. 2N+1  : data           (mirror copy, wraps automatically)
     */
    size_t total = (size_t)(page_size * 2 + data_size * 2);

    void *addr = mmap(NULL, total, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) return NULL;
    return addr;
}

KT_EXPORT
void kt_munmap(void *addr, uint64_t data_size, uint64_t page_size)
{
    if (!addr) return;
    size_t total = (size_t)(page_size * 2 + data_size * 2);
    munmap(addr, total);
}

/* ── epoll helpers ───────────────────────────────────────────────────────── */

KT_EXPORT
int kt_create_epoll(int ringbuf_fd)
{
    if (ringbuf_fd < 0) return -EINVAL;

    int efd = epoll_create1(EPOLL_CLOEXEC);
    if (efd < 0) return -errno;

    struct epoll_event ev = {
        .events  = EPOLLIN,
        .data.fd = ringbuf_fd,
    };
    if (epoll_ctl(efd, EPOLL_CTL_ADD, ringbuf_fd, &ev) < 0) {
        int err = errno;
        close(efd);
        return -err;
    }
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
int kt_btf_struct_size(const char *struct_name)
{
    if (!struct_name) return -EINVAL;

    /* Load the vmlinux BTF (requires /sys/kernel/btf/vmlinux). */
    struct btf *vmlinux_btf = btf__load_vmlinux_btf();
    if (!vmlinux_btf) return -ENOENT;

    int result = -ENOENT;
    int nr = btf__type_cnt(vmlinux_btf);
    for (int i = 1; i < nr; i++) {
        const struct btf_type *t = btf__type_by_id(vmlinux_btf, i);
        if (!t) continue;
        if (!BTF_INFO_KIND(t->info) == BTF_KIND_STRUCT) continue;

        const char *name = btf__name_by_offset(vmlinux_btf, t->name_off);
        if (name && strcmp(name, struct_name) == 0) {
            result = (int)t->size;
            break;
        }
    }

    btf__free(vmlinux_btf);
    return result;
}
