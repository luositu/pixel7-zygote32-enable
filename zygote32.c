/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Enable 32-bit support on Pixel 7 by patching vendor build.prop at runtime.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <uapi/linux/stat.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm-generic/compat.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include "kallsyms.h"

KPM_NAME("pixel7-zygote32");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("rea1");
KPM_DESCRIPTION("Patch vendor build.prop to enable zygote64_32 on Pixel 7");

// Files and constants
static const char vendor_build_prop[] = "/vendor/build.prop";
static const char overlay_build_prop[] = "/dev/kp_vendor_build.prop";

// Read whole small text file into kernel memory
// Resolve-at-runtime kernel API (avoid direct relocations)
static struct file *(*kp_filp_open)(const char *path, int flags, umode_t mode);
static loff_t (*kp_vfs_llseek)(struct file *file, loff_t offset, int whence);
static ssize_t (*kp_kernel_read)(struct file *file, void *buf, size_t count, loff_t *pos);
static ssize_t (*kp_kernel_write)(struct file *file, const void *buf, size_t count, loff_t *pos);
static int (*kp_filp_close)(struct file *file, void *id);
static void *(*kp_vmalloc)(unsigned long size);
static void (*kp_vfree)(const void *addr);

static char *read_small_file(const char *path, size_t *out_size)
{
    pr_info("zygote32: read_small_file path=%s\n", path);
    struct file *filp = kp_filp_open(path, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
        pr_err("zygote32: filp_open failed, path=%s err=%ld\n", path, PTR_ERR(filp));
        return NULL;
    }
    loff_t len = kp_vfs_llseek(filp, 0, SEEK_END);
    kp_vfs_llseek(filp, 0, SEEK_SET);
    if (len <= 0 || len > 1024 * 1024) { // 1MB guard
        pr_err("zygote32: unexpected size=%lld for %s\n", len, path);
        kp_filp_close(filp, 0);
        return NULL;
    }
    char *buf = kp_vmalloc(len + 1);
    if (!buf) {
        pr_err("zygote32: vmalloc failed size=%lld\n", len + 1);
        kp_filp_close(filp, 0);
        return NULL;
    }
    loff_t pos = 0;
    ssize_t rd = kp_kernel_read(filp, buf, len, &pos);
    if (rd != len) {
        pr_err("zygote32: kernel_read mismatch rd=%zd len=%lld\n", rd, len);
    }
    buf[len] = '\0';
    kp_filp_close(filp, 0);
    pr_info("zygote32: read_small_file ok size=%lld\n", len);
    if (out_size) *out_size = (size_t)len;
    return buf;
}

// Write buffer to file path (create/truncate)
static int write_file_all(const char *path, const char *data, size_t size, umode_t mode)
{
    pr_info("zygote32: write_file_all path=%s size=%zu mode=%o\n", path, size, mode);
    struct file *fp = kp_filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (!fp || IS_ERR(fp)) {
        pr_err("zygote32: filp_open for write failed, path=%s err=%ld\n", path, PTR_ERR(fp));
        return -ENOENT;
    }
    loff_t off = 0;
    ssize_t wr = kp_kernel_write(fp, data, size, &off);
    if (wr != size) {
        pr_err("zygote32: kernel_write mismatch wr=%zd size=%zu off=%lld\n", wr, size, off);
    }
    kp_filp_close(fp, 0);
    return off == size ? 0 : -EIO;
}

// Simple helpers
static bool starts_with(const char *line, const char *prefix)
{
    size_t lp = strlen(prefix);
    return strncmp(line, prefix, lp) == 0;
}

static bool contains(const char *s, const char *sub)
{
    return strstr(s, sub) != NULL;
}

// Build a patched build.prop in overlay_build_prop.
// Returns 0 on success, <0 on failure.
static int build_patched_build_prop(void)
{
    size_t sz = 0;
    char *orig = read_small_file(vendor_build_prop, &sz);
    if (!orig) return -ENOENT;

    // Allocate generous buffer for output
    size_t out_cap = sz + 1024;
    char *out = kp_vmalloc(out_cap);
    if (!out) {
        kp_vfree(orig);
        return -ENOMEM;
    }
    size_t out_len = 0;

    bool is_pixel7 = contains(orig, "Pixel 7");
    pr_info("zygote32: is_pixel7=%d\n", is_pixel7);

    // Iterate by lines
    const char *cur = orig;
    while (*cur) {
        const char *nl = strchr(cur, '\n');
        size_t line_len = nl ? (size_t)(nl - cur + 1) : strlen(cur);

        if (starts_with(cur, "ro.vendor.product.cpu.abilist=")) {
            const char *rep = "ro.vendor.product.cpu.abilist=arm64-v8a,armeabi-v7a,armeabi\n";
            size_t rep_len = strlen(rep);
            memcpy(out + out_len, rep, rep_len);
            out_len += rep_len;
            pr_info("zygote32: patched abilist\n");
        } else if (starts_with(cur, "ro.vendor.product.cpu.abilist32=")) {
            const char *rep = "ro.vendor.product.cpu.abilist32=armeabi-v7a,armeabi\n";
            size_t rep_len = strlen(rep);
            memcpy(out + out_len, rep, rep_len);
            out_len += rep_len;
            pr_info("zygote32: patched abilist32\n");
        } else if (starts_with(cur, "ro.zygote=zygote64")) {
            const char *rep = "ro.zygote=zygote64_32\n";
            size_t rep_len = strlen(rep);
            memcpy(out + out_len, rep, rep_len);
            out_len += rep_len;
            pr_info("zygote32: patched zygote\n");
        } else {
            memcpy(out + out_len, cur, line_len);
            out_len += line_len;
        }

        cur += line_len;
    }

    int rc = 0;
    if (is_pixel7) {
        rc = write_file_all(overlay_build_prop, out, out_len, 0600);
    } else {
        // For non-Pixel 7: mirror original to overlay to keep logic uniform
        rc = write_file_all(overlay_build_prop, orig, sz, 0600);
    }
    pr_info("zygote32: build_patched_build_prop rc=%d out_len=%zu orig_sz=%zu\n", rc, out_len, sz);

    kp_vfree(out);
    kp_vfree(orig);
    return rc;
}

// openat hook: when userspace opens /vendor/build.prop for read, redirect to overlay
static void before_openat(hook_fargs4_t *args, void *udata)
{
    const char __user *ufn = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);

    // Only redirect for read-only style opens
    if ((flags & O_ACCMODE) != O_RDONLY && (flags & O_ACCMODE) != O_PATH) return;

    char path[256];
    long rc = compat_strncpy_from_user(path, ufn, sizeof(path));
    if (rc <= 0) return;
    if (strcmp(path, vendor_build_prop)) return;
    pr_info("zygote32: openat vendor build.prop flags=%x\n", flags);

    // Build overlay file once per boot when first accessed
    static int built = 0;
    if (!built) {
        int brc = build_patched_build_prop();
        pr_info("zygote32: build_patched_build_prop called rc=%d\n", brc);
        if (brc == 0) built = 1;
    }

    // Replace user buffer path with overlay path
    int cplen = compat_copy_to_user((void *)ufn, overlay_build_prop, sizeof(overlay_build_prop));
    if (cplen <= 0) {
        void __user *up = copy_to_user_stack(overlay_build_prop, sizeof(overlay_build_prop));
        args->arg1 = (uint64_t)up;
        pr_info("zygote32: redirect via stack up=%llx\n", (unsigned long long)up);
    } else {
        pr_info("zygote32: redirect via in-place copy len=%d\n", cplen);
    }
}

static long z32_init(const char *args, const char *event, void *__user reserved)
{
    // Resolve required kernel symbols once
    if (!kallsyms_lookup_name) {
        pr_err("zygote32: kallsyms_lookup_name is NULL\n");
        return -ENOENT;
    }
    kp_filp_open = (typeof(kp_filp_open))kallsyms_lookup_name("filp_open");
    kp_vfs_llseek = (typeof(kp_vfs_llseek))kallsyms_lookup_name("vfs_llseek");
    kp_kernel_read = (typeof(kp_kernel_read))kallsyms_lookup_name("kernel_read");
    kp_kernel_write = (typeof(kp_kernel_write))kallsyms_lookup_name("kernel_write");
    kp_filp_close = (typeof(kp_filp_close))kallsyms_lookup_name("filp_close");
    kp_vmalloc = (typeof(kp_vmalloc))kallsyms_lookup_name("vmalloc");
    kp_vfree = (typeof(kp_vfree))kallsyms_lookup_name("vfree");

    pr_info("zygote32: sym filp_open=%p vfs_llseek=%p kernel_read=%p kernel_write=%p filp_close=%p vmalloc=%p vfree=%p\n",
            kp_filp_open, kp_vfs_llseek, kp_kernel_read, kp_kernel_write, kp_filp_close, kp_vmalloc, kp_vfree);

    if (!kp_filp_open || !kp_vfs_llseek || !kp_kernel_read || !kp_kernel_write || !kp_filp_close || !kp_vmalloc || !kp_vfree) {
        pr_err("zygote32: resolve symbols failed\n");
        return -ENOENT;
    }

    hook_err_t rc = hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    pr_info("zygote32: hook openat rc=%d\n", rc);
    return rc;
}

static long z32_exit(void *__user reserved)
{
    unhook_syscalln(__NR_openat, before_openat, 0);
    return 0;
}

KPM_INIT(z32_init);
KPM_EXIT(z32_exit);


