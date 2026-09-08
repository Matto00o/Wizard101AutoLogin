/*
 * Wizard101 auto-login through memory injection.
 *
 * C port of w101_autologin.py, for cross-compilation to a dependency-free
 * Windows executable. Must run inside the game's Wine prefix, or on Windows.
 *
 * Ported from libs/wizlaunch/src/login.rs in Deimos-Wizard101.
 * Licensed under the GNU General Public License v3.0, see LICENSE.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOOK_INSTR_LEN 7
#define CAVE_SIZE 512
#define MAX_PATTERN 64
#define MAX_HITS 8
#define MAX_CANDIDATES 512

static const char *LOGIN_PATTERN = "41 B1 01 45 33 C0 48 8D 55 CF 48 8B 0D";
static const char *HOOK_PATTERN =
    "?? ?? ?? ?? ?? ?? ?? 48 8B 01 ?? ?? ?? ?? ?? ?? ?? FF 50 70 84";

static const char *MODULE_NAME = "WizardGraphicalClient.exe";
static const char *WINDOW_CLASS = "Wizard Graphical Client";

static int quiet = 0;

/* Print a progress line unless --quiet was given. */
static void note(const char *fmt, ...)
{
    va_list ap;
    if (quiet)
        return;
    fputs("[w101] ", stdout);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

/* Print an error line, including the calling thread's last Win32 error. */
static void fail_win(const char *fmt, ...)
{
    DWORD err = GetLastError();
    char msg[256] = {0};
    va_list ap;

    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, 0, msg, sizeof(msg) - 1, NULL);
    for (char *p = msg; *p; p++)
        if (*p == '\r' || *p == '\n')
            *p = ' ';

    fputs("[w101] error: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": Win32 error %lu (%s)\n", (unsigned long)err, msg);
}

/* Print an error line with no Win32 error attached. */
static void fail(const char *fmt, ...)
{
    va_list ap;
    fputs("[w101] error: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* Compare two ASCII strings ignoring case. Returns 0 when equal. */
static int ascii_casecmp(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        int ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        int cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb)
            return ca - cb;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

/*
 * Parse a "41 B1 ?? .." pattern string into `out`, wildcards becoming -1.
 * Returns the number of entries, or -1 if it does not fit or does not parse.
 */
static int parse_pattern(const char *text, int *out, int max)
{
    int n = 0;
    while (*text) {
        while (*text == ' ')
            text++;
        if (!*text)
            break;
        if (n >= max)
            return -1;
        if (text[0] == '?') {
            out[n++] = -1;
            while (*text == '?')
                text++;
        } else {
            char *end;
            long v = strtol(text, &end, 16);
            if (end == text || v < 0 || v > 0xFF)
                return -1;
            out[n++] = (int)v;
            text = end;
        }
    }
    return n;
}

/*
 * Find up to `max_hits` offsets in `data` matching `pat`.
 * Returns the number of matches written to `hits`.
 */
static int scan(const unsigned char *data, size_t len, const int *pat, int patlen,
                size_t *hits, int max_hits)
{
    int found = 0;
    if (patlen <= 0 || len < (size_t)patlen)
        return 0;
    for (size_t i = 0; i + (size_t)patlen <= len; i++) {
        int ok = 1;
        for (int j = 0; j < patlen; j++) {
            if (pat[j] >= 0 && data[i + j] != (unsigned char)pat[j]) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            hits[found++] = i;
            if (found >= max_hits)
                break;
        }
    }
    return found;
}

/* ---- remote process ---- */

typedef struct {
    HANDLE handle;
    DWORD pid;
} RemoteProcess;

/* Open a process for read, write and allocation. Returns 0 on success. */
static int proc_open(RemoteProcess *p, DWORD pid)
{
    p->pid = pid;
    p->handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
                                PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
                            FALSE, pid);
    if (!p->handle) {
        fail_win("OpenProcess(pid=%lu)", (unsigned long)pid);
        return -1;
    }
    return 0;
}

static void proc_close(RemoteProcess *p)
{
    if (p->handle) {
        CloseHandle(p->handle);
        p->handle = NULL;
    }
}

/* Read exactly `size` bytes at `addr`. Returns 0 on success. */
static int proc_read(RemoteProcess *p, ULONGLONG addr, void *buf, SIZE_T size)
{
    SIZE_T got = 0;
    if (!ReadProcessMemory(p->handle, (LPCVOID)(UINT_PTR)addr, buf, size, &got) ||
        got != size)
        return -1;
    return 0;
}

/* Write `size` bytes at `addr`. Returns 0 on success. */
static int proc_write(RemoteProcess *p, ULONGLONG addr, const void *buf, SIZE_T size)
{
    SIZE_T put = 0;
    if (!WriteProcessMemory(p->handle, (LPVOID)(UINT_PTR)addr, buf, size, &put) ||
        put != size)
        return -1;
    return 0;
}

/* Read a little-endian 64-bit value at `addr`. Returns 0 on success. */
static int proc_read_u64(RemoteProcess *p, ULONGLONG addr, ULONGLONG *out)
{
    return proc_read(p, addr, out, sizeof(*out));
}

/* Commit `size` bytes in the target, at `address` when non-zero. */
static ULONGLONG proc_alloc(RemoteProcess *p, SIZE_T size, int executable,
                            ULONGLONG address)
{
    DWORD protect = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    LPVOID ptr = VirtualAllocEx(p->handle, (LPVOID)(UINT_PTR)address, size,
                                MEM_COMMIT | MEM_RESERVE, protect);
    return (ULONGLONG)(UINT_PTR)ptr;
}

static void proc_free(RemoteProcess *p, ULONGLONG addr)
{
    if (addr)
        VirtualFreeEx(p->handle, (LPVOID)(UINT_PTR)addr, 0, MEM_RELEASE);
}

static ULONGLONG g_sort_near;

static int cmp_by_distance(const void *a, const void *b)
{
    ULONGLONG ua = *(const ULONGLONG *)a, ub = *(const ULONGLONG *)b;
    ULONGLONG da = ua > g_sort_near ? ua - g_sort_near : g_sort_near - ua;
    ULONGLONG db = ub > g_sort_near ? ub - g_sort_near : g_sort_near - ub;
    return da < db ? -1 : (da > db ? 1 : 0);
}

/*
 * Allocate `size` executable bytes within +-2 GB of `anchor`, the reach of an
 * E9 rel32 jump. Free regions are tried closest-first. Returns 0 on failure.
 */
static ULONGLONG proc_alloc_near(RemoteProcess *p, ULONGLONG anchor, SIZE_T size)
{
    const ULONGLONG gran = 0x10000ULL;
    const ULONGLONG span = 0x7FFF0000ULL;
    ULONGLONG low = anchor > span + 0x10000ULL ? anchor - span : 0x10000ULL;
    ULONGLONG high = anchor + span;
    ULONGLONG candidates[MAX_CANDIDATES];
    int n = 0;

    for (ULONGLONG addr = low; addr < high && n < MAX_CANDIDATES;) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(p->handle, (LPCVOID)(UINT_PTR)addr, &mbi, sizeof(mbi)))
            break;
        if (mbi.RegionSize == 0)
            break;
        ULONGLONG base = (ULONGLONG)(UINT_PTR)mbi.BaseAddress;
        ULONGLONG rsize = (ULONGLONG)mbi.RegionSize;
        if (mbi.State == MEM_FREE && rsize >= size) {
            ULONGLONG start = ((base > low ? base : low) + gran - 1) & ~(gran - 1);
            ULONGLONG limit = base + rsize;
            if (limit > high)
                limit = high;
            if (limit >= size && start <= limit - size) {
                ULONGLONG stop = limit - size;
                ULONGLONG best = anchor < start ? start : (anchor > stop ? stop : anchor);
                candidates[n++] = best & ~(gran - 1);
            }
        }
        addr = base + rsize;
    }

    g_sort_near = anchor;
    qsort(candidates, (size_t)n, sizeof(candidates[0]), cmp_by_distance);

    for (int i = 0; i < n; i++) {
        if (candidates[i] < low || candidates[i] + size > high)
            continue;
        ULONGLONG ptr = proc_alloc(p, size, 1, candidates[i]);
        if (ptr)
            return ptr;
    }
    return 0;
}

/* Look up a module by name. Returns 0 on success. */
static int proc_module(RemoteProcess *p, const char *name, ULONGLONG *base, DWORD *size)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                           p->pid);
    MODULEENTRY32 entry;
    int rc = -1;

    if (snap == INVALID_HANDLE_VALUE) {
        fail_win("CreateToolhelp32Snapshot(MODULE)");
        return -1;
    }
    entry.dwSize = sizeof(entry);
    if (Module32First(snap, &entry)) {
        do {
            if (ascii_casecmp(entry.szModule, name) == 0) {
                *base = (ULONGLONG)(UINT_PTR)entry.modBaseAddr;
                *size = entry.modBaseSize;
                rc = 0;
                break;
            }
        } while (Module32Next(snap, &entry));
    }
    CloseHandle(snap);
    if (rc != 0)
        fail("module '%s' not found in pid %lu", name, (unsigned long)p->pid);
    return rc;
}

/*
 * Read a whole module region by region, zero-filling unreadable gaps.
 * A single 55 MB read fails outright if any page in the range is unreadable,
 * and offsets must stay faithful to the image.
 */
static unsigned char *proc_read_module_image(RemoteProcess *p, ULONGLONG base, DWORD size)
{
    unsigned char *image = calloc(1, size);
    ULONGLONG end = base + size;

    if (!image) {
        fail("out of memory reading a %lu byte module", (unsigned long)size);
        return NULL;
    }
    for (ULONGLONG addr = base; addr < end;) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(p->handle, (LPCVOID)(UINT_PTR)addr, &mbi, sizeof(mbi)))
            break;
        if (mbi.RegionSize == 0)
            break;
        ULONGLONG region_end = (ULONGLONG)(UINT_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (region_end > end)
            region_end = end;
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
            region_end > addr)
            proc_read(p, addr, image + (addr - base), (SIZE_T)(region_end - addr));
        addr = region_end;
    }
    return image;
}

/* ---- thread freezing ---- */

typedef struct {
    HANDLE *handles;
    int count;
} FrozenThreads;

/*
 * Suspend every thread of the process.
 *
 * WriteProcessMemory is not atomic: a thread parked on the instruction being
 * overwritten could otherwise execute a half-written opcode. Always pair with
 * threads_resume.
 */
static void threads_freeze(FrozenThreads *f, RemoteProcess *p, int enabled)
{
    HANDLE snap;
    THREADENTRY32 entry;

    f->handles = NULL;
    f->count = 0;
    if (!enabled)
        return;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    f->handles = calloc(4096, sizeof(HANDLE));
    if (!f->handles) {
        CloseHandle(snap);
        return;
    }
    entry.dwSize = sizeof(entry);
    if (Thread32First(snap, &entry)) {
        do {
            if (entry.th32OwnerProcessID != p->pid || f->count >= 4096)
                continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
            if (!h)
                continue;
            if (SuspendThread(h) == (DWORD)-1)
                CloseHandle(h);
            else
                f->handles[f->count++] = h;
        } while (Thread32Next(snap, &entry));
    }
    CloseHandle(snap);
}

static void threads_resume(FrozenThreads *f)
{
    for (int i = 0; i < f->count; i++) {
        ResumeThread(f->handles[i]);
        CloseHandle(f->handles[i]);
    }
    free(f->handles);
    f->handles = NULL;
    f->count = 0;
}

/* ---- windows ---- */

static HWND g_found_window;

static BOOL CALLBACK find_client_window(HWND hwnd, LPARAM lparam)
{
    char cls[64] = {0};
    (void)lparam;
    GetClassNameA(hwnd, cls, sizeof(cls) - 1);
    if (strcmp(cls, WINDOW_CLASS) == 0) {
        g_found_window = hwnd;
        return FALSE;
    }
    return TRUE;
}

/*
 * Block until a client window appears and return its pid, or 0 on timeout.
 */
static DWORD wait_for_client(double timeout)
{
    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)(timeout * 1000.0);
    for (;;) {
        g_found_window = NULL;
        EnumWindows(find_client_window, 0);
        if (g_found_window) {
            DWORD pid = 0;
            GetWindowThreadProcessId(g_found_window, &pid);
            if (pid) {
                note("found client window (hwnd %p, pid %lu)", (void *)g_found_window,
                     (unsigned long)pid);
                return pid;
            }
        }
        if (GetTickCount64() > deadline) {
            fail("no '%s' window appeared within %.0fs", WINDOW_CLASS, timeout);
            return 0;
        }
        Sleep(500);
    }
}

/* ---- payload ---- */

static void put_u64(unsigned char *dst, ULONGLONG v)
{
    for (int i = 0; i < 8; i++)
        dst[i] = (unsigned char)(v >> (8 * i));
}

static void put_i32(unsigned char *dst, int v)
{
    for (int i = 0; i < 4; i++)
        dst[i] = (unsigned char)((unsigned int)v >> (8 * i));
}

static int get_i32(const unsigned char *src)
{
    unsigned int v = (unsigned int)src[0] | ((unsigned int)src[1] << 8) |
                     ((unsigned int)src[2] << 16) | ((unsigned int)src[3] << 24);
    return (int)v;
}

/*
 * Build the game's 32-byte string struct: {ptr@0, 0@8, len@16, cap@24}.
 * `len` excludes the terminating null.
 */
static void build_string_struct(unsigned char out[32], ULONGLONG data_addr, ULONGLONG len)
{
    memset(out, 0, 32);
    put_u64(out + 0, data_addr);
    put_u64(out + 16, len);
    put_u64(out + 24, len);
}

/*
 * Assemble the code-cave payload that dispatches the login command.
 *
 * The payload tests `flag_addr`, and when set calls the game's command
 * dispatcher, clears the flag, re-executes `orig_instr` and jumps to
 * `ret_addr`. `block_addr` is where the payload will be written, and is needed
 * to compute the trailing relative jump. Returns the payload length.
 */
static int build_login_bytecode(unsigned char *bc, ULONGLONG block_addr,
                                ULONGLONG flag_addr, ULONGLONG string_struct_addr,
                                ULONGLONG dat_addr, ULONGLONG func_addr,
                                const unsigned char *orig_instr, ULONGLONG ret_addr)
{
    static const unsigned char PUSHES[] = {0x50, 0x51, 0x52, 0x41, 0x50,
                                           0x41, 0x51, 0x41, 0x52, 0x41, 0x53};
    static const unsigned char POPS[] = {0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59,
                                         0x41, 0x58, 0x5A, 0x59, 0x58};
    int n = 0, skip_fixup, skip_target;
    ULONGLONG jmp_from;

    bc[n++] = 0x50;                                     /* push rax */
    bc[n++] = 0x48; bc[n++] = 0xB8;                     /* mov rax, flag_addr */
    put_u64(bc + n, flag_addr); n += 8;
    bc[n++] = 0x80; bc[n++] = 0x38; bc[n++] = 0x01;     /* cmp byte [rax], 1 */
    bc[n++] = 0x58;                                     /* pop rax */
    bc[n++] = 0x0F; bc[n++] = 0x85;                     /* jne skip */
    skip_fixup = n;
    n += 4;

    memcpy(bc + n, PUSHES, sizeof(PUSHES)); n += (int)sizeof(PUSHES);
    bc[n++] = 0x48; bc[n++] = 0x83; bc[n++] = 0xEC; bc[n++] = 0x28;  /* sub rsp, 0x28 */
    bc[n++] = 0x41; bc[n++] = 0xB1; bc[n++] = 0x01;     /* mov r9b, 1 */
    bc[n++] = 0x45; bc[n++] = 0x33; bc[n++] = 0xC0;     /* xor r8d, r8d */
    bc[n++] = 0x48; bc[n++] = 0xBA;                     /* mov rdx, string_struct */
    put_u64(bc + n, string_struct_addr); n += 8;
    bc[n++] = 0x48; bc[n++] = 0xB8;                     /* mov rax, dat */
    put_u64(bc + n, dat_addr); n += 8;
    bc[n++] = 0x48; bc[n++] = 0x8B; bc[n++] = 0x08;     /* mov rcx, [rax] */
    bc[n++] = 0x48; bc[n++] = 0xB8;                     /* mov rax, func */
    put_u64(bc + n, func_addr); n += 8;
    bc[n++] = 0xFF; bc[n++] = 0xD0;                     /* call rax */
    bc[n++] = 0x48; bc[n++] = 0xB8;                     /* mov rax, flag_addr */
    put_u64(bc + n, flag_addr); n += 8;
    bc[n++] = 0xC6; bc[n++] = 0x00; bc[n++] = 0x00;     /* mov byte [rax], 0 */
    bc[n++] = 0x48; bc[n++] = 0x83; bc[n++] = 0xC4; bc[n++] = 0x28;  /* add rsp, 0x28 */
    memcpy(bc + n, POPS, sizeof(POPS)); n += (int)sizeof(POPS);

    skip_target = n;
    put_i32(bc + skip_fixup, skip_target - skip_fixup - 4);

    memcpy(bc + n, orig_instr, HOOK_INSTR_LEN);
    n += HOOK_INSTR_LEN;

    bc[n++] = 0xE9;                                     /* jmp ret_addr */
    jmp_from = block_addr + (ULONGLONG)n + 4;
    put_i32(bc + n, (int)(LONGLONG)(ret_addr - jmp_from));
    n += 4;

    return n;
}

/* ---- address resolution ---- */

typedef struct {
    ULONGLONG mod_base;
    DWORD mod_size;
    ULONGLONG login;
    ULONGLONG dat;
    ULONGLONG func;
    ULONGLONG hook;
    unsigned char orig_instr[HOOK_INSTR_LEN];
} Addresses;

/*
 * Locate the dispatcher, its globals and the hook site in the target.
 *
 * Returns 0 on success. A missing pattern means the client build changed and
 * the patterns need rebuilding in a disassembler.
 */
static int resolve(RemoteProcess *p, Addresses *a)
{
    int login_pat[MAX_PATTERN], hook_pat[MAX_PATTERN];
    int login_len, hook_len, n_login, n_hook;
    size_t login_hits[MAX_HITS], hook_hits[MAX_HITS];
    unsigned char *image;

    if (proc_module(p, MODULE_NAME, &a->mod_base, &a->mod_size) != 0)
        return -1;
    note("%s @ 0x%llx (%.1f MiB)", MODULE_NAME, a->mod_base,
         a->mod_size / 1024.0 / 1024.0);

    image = proc_read_module_image(p, a->mod_base, a->mod_size);
    if (!image)
        return -1;

    login_len = parse_pattern(LOGIN_PATTERN, login_pat, MAX_PATTERN);
    hook_len = parse_pattern(HOOK_PATTERN, hook_pat, MAX_PATTERN);
    n_login = scan(image, a->mod_size, login_pat, login_len, login_hits, MAX_HITS);
    n_hook = scan(image, a->mod_size, hook_pat, hook_len, hook_hits, MAX_HITS);

    if (n_login == 0) {
        fail("LOGIN_PATTERN not found");
        free(image);
        return -1;
    }
    if (n_hook == 0) {
        fail("HOOK_PATTERN not found");
        free(image);
        return -1;
    }
    if (n_login > 1)
        note("warning: LOGIN_PATTERN matched %d times, using the first", n_login);
    if (n_hook > 1)
        note("warning: HOOK_PATTERN matched %d times, using the first", n_hook);

    a->login = a->mod_base + login_hits[0];
    a->dat = a->login + 17 + (LONGLONG)get_i32(image + login_hits[0] + 13);
    a->func = a->login + 22 + (LONGLONG)get_i32(image + login_hits[0] + 18);
    a->hook = a->mod_base + hook_hits[0];
    memcpy(a->orig_instr, image + hook_hits[0], HOOK_INSTR_LEN);

    note("login  0x%llx  (RVA 0x%llx)", a->login, (ULONGLONG)login_hits[0]);
    note("dat    0x%llx", a->dat);
    note("func   0x%llx", a->func);
    note("hook   0x%llx  (RVA 0x%llx)  orig %02x %02x %02x %02x %02x %02x %02x",
         a->hook, (ULONGLONG)hook_hits[0], a->orig_instr[0], a->orig_instr[1],
         a->orig_instr[2], a->orig_instr[3], a->orig_instr[4], a->orig_instr[5],
         a->orig_instr[6]);

    free(image);
    return 0;
}

/*
 * Block until the game's global client pointer is non-null.
 *
 * Injecting before the game populates it would pass rcx = NULL to the
 * dispatcher and crash the client. Returns 0 on success.
 */
static int wait_until_ready(RemoteProcess *p, Addresses *a, double timeout)
{
    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)(timeout * 1000.0);
    for (;;) {
        ULONGLONG ptr = 0;
        if (proc_read_u64(p, a->dat, &ptr) == 0 && ptr) {
            note("client ready ([dat] = 0x%llx)", ptr);
            return 0;
        }
        if (GetTickCount64() > deadline) {
            fail("[dat] still NULL after %.0fs, client not loaded", timeout);
            return -1;
        }
        Sleep(250);
    }
}

/*
 * Inject and run the login command, then restore the process.
 *
 * Allocations are freed and the hook site restored on every exit path.
 * Returns 0 on success.
 */
static int do_login(RemoteProcess *p, Addresses *a, const char *username,
                    const char *password, double timeout, int suspend)
{
    char cmd[1024];
    unsigned char payload[CAVE_SIZE];
    unsigned char sstruct[32];
    unsigned char jmp[HOOK_INSTR_LEN];
    unsigned char current[HOOK_INSTR_LEN];
    ULONGLONG str_data = 0, str_struct = 0, flag = 0, cave = 0;
    ULONGLONG ret_addr = a->hook + HOOK_INSTR_LEN;
    LONGLONG rel;
    int cmd_len, payload_len, rc = -1, patched = 0;
    FrozenThreads frozen;
    ULONGLONG deadline;

    cmd_len = snprintf(cmd, sizeof(cmd), "login %s %s", username, password);
    if (cmd_len <= 0 || cmd_len >= (int)sizeof(cmd)) {
        fail("credentials too long");
        return -1;
    }

    str_data = proc_alloc(p, (SIZE_T)cmd_len + 1, 0, 0);
    str_struct = proc_alloc(p, 32, 0, 0);
    flag = proc_alloc(p, 8, 0, 0);
    if (!str_data || !str_struct || !flag) {
        fail_win("VirtualAllocEx");
        goto cleanup;
    }

    cave = proc_alloc_near(p, a->hook, CAVE_SIZE);
    if (!cave) {
        fail("no executable memory available within +-2 GB of the hook site");
        goto cleanup;
    }
    note("code cave 0x%llx (hook delta %+lld)", cave, (LONGLONG)(cave - a->hook));

    build_string_struct(sstruct, str_data, (ULONGLONG)cmd_len);
    if (proc_write(p, str_data, cmd, (SIZE_T)cmd_len + 1) != 0 ||
        proc_write(p, str_struct, sstruct, sizeof(sstruct)) != 0 ||
        proc_write(p, flag, "\0\0\0\0\0\0\0\0", 8) != 0) {
        fail_win("WriteProcessMemory (payload data)");
        goto cleanup;
    }

    payload_len = build_login_bytecode(payload, cave, flag, str_struct, a->dat,
                                       a->func, a->orig_instr, ret_addr);
    if (payload_len > CAVE_SIZE) {
        fail("payload is %d bytes, cave is %d", payload_len, CAVE_SIZE);
        goto cleanup;
    }
    if (proc_write(p, cave, payload, (SIZE_T)payload_len) != 0) {
        fail_win("WriteProcessMemory (payload)");
        goto cleanup;
    }
    note("payload written (%d bytes)", payload_len);

    if (proc_write(p, flag, "\1", 1) != 0) {
        fail_win("WriteProcessMemory (arming the flag)");
        goto cleanup;
    }

    rel = (LONGLONG)cave - (LONGLONG)(a->hook + 5);
    if (rel < -0x80000000LL || rel > 0x7FFFFFFFLL) {
        fail("code cave out of rel32 range (%lld)", rel);
        goto cleanup;
    }
    jmp[0] = 0xE9;
    put_i32(jmp + 1, (int)rel);
    jmp[5] = 0x90;
    jmp[6] = 0x90;

    threads_freeze(&frozen, p, suspend);
    if (proc_read(p, a->hook, current, HOOK_INSTR_LEN) != 0 ||
        memcmp(current, a->orig_instr, HOOK_INSTR_LEN) != 0) {
        threads_resume(&frozen);
        fail("hook site changed underneath us, leaving it alone");
        goto cleanup;
    }
    if (proc_write(p, a->hook, jmp, HOOK_INSTR_LEN) != 0) {
        threads_resume(&frozen);
        fail_win("WriteProcessMemory (hook site)");
        goto cleanup;
    }
    patched = 1;
    threads_resume(&frozen);
    note("hook armed, waiting for the main thread to run it");

    deadline = GetTickCount64() + (ULONGLONG)(timeout * 1000.0);
    for (;;) {
        unsigned char v = 1;
        Sleep(50);
        if (proc_read(p, flag, &v, 1) == 0 && v == 0) {
            note("login command dispatched");
            rc = 0;
            break;
        }
        if (GetTickCount64() > deadline) {
            fail("payload never ran within %.0fs", timeout);
            break;
        }
    }

cleanup:
    if (patched) {
        threads_freeze(&frozen, p, suspend);
        if (proc_write(p, a->hook, a->orig_instr, HOOK_INSTR_LEN) == 0)
            note("original bytes restored");
        else
            fail_win("failed to restore the hook site");
        threads_resume(&frozen);
        /* let any thread still inside the cave leave it before it is freed */
        Sleep(500);
    }
    proc_free(p, str_data);
    proc_free(p, str_struct);
    proc_free(p, flag);
    proc_free(p, cave);
    return rc;
}

/*
 * Start the game client directly, skipping the launcher.
 *
 * `game_dir` is the Wizard101 install root; the client lives in its Bin
 * subdirectory, which also becomes the working directory. Returns 0 on success.
 */
static int launch_game(const char *game_dir, const char *host, const char *port, int steam)
{
    char bin_dir[MAX_PATH * 2], exe[MAX_PATH * 2], cmdline[MAX_PATH * 4];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    snprintf(bin_dir, sizeof(bin_dir), "%s\\Bin", game_dir);
    snprintf(exe, sizeof(exe), "%s\\WizardGraphicalClient.exe", bin_dir);
    if (GetFileAttributesA(exe) == INVALID_FILE_ATTRIBUTES) {
        fail("client not found: %s", exe);
        return -1;
    }
    snprintf(cmdline, sizeof(cmdline), "\"%s\"%s -L %s %s", exe,
             steam ? " -ST" : "", host, port);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(exe, cmdline, NULL, NULL, FALSE, 0, NULL, bin_dir, &si, &pi)) {
        fail_win("CreateProcess(%s)", exe);
        return -1;
    }
    note("launched %s (pid %lu)", exe, (unsigned long)pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

/*
 * Print the payload built for a fixed set of addresses, then exit.
 *
 * Lets tools/test_bytecode.py diff this implementation against the Python one
 * without a running client. The values are test vectors, not real addresses.
 */
static void dump_payload(void)
{
    static const unsigned char ORIG[HOOK_INSTR_LEN] = {0x49, 0x8B, 0x8D, 0xD8, 0x00, 0x00, 0x00};
    unsigned char payload[CAVE_SIZE];
    int n = build_login_bytecode(payload, 0x141900000ULL, 0x20000000ULL, 0x20001000ULL,
                                 0x14333A160ULL, 0x141491680ULL, ORIG, 0x141847592ULL);
    for (int i = 0; i < n; i++)
        printf("%02x", payload[i]);
    printf("\n");
}

/* ---- credentials ---- */

/*
 * Read a username and password from the first two lines of a file.
 * Returns 0 on success.
 */
static int read_credentials_file(const char *path, char *user, size_t user_size,
                                 char *pass, size_t pass_size)
{
    FILE *fh = fopen(path, "rb");
    if (!fh) {
        fail("cannot open %s", path);
        return -1;
    }
    if (!fgets(user, (int)user_size, fh) || !fgets(pass, (int)pass_size, fh)) {
        fail("%s must hold the username on line 1 and the password on line 2", path);
        fclose(fh);
        return -1;
    }
    fclose(fh);
    user[strcspn(user, "\r\n")] = 0;
    pass[strcspn(pass, "\r\n")] = 0;
    return (*user && *pass) ? 0 : -1;
}

/* Reject credentials the space-separated login command cannot represent. */
static int credentials_valid(const char *user, const char *pass)
{
    const char *fields[2] = {user, pass};
    const char *labels[2] = {"username", "password"};
    for (int i = 0; i < 2; i++) {
        for (const char *c = fields[i]; *c; c++) {
            if (*c == ' ' || *c == '\t') {
                fail("the %s contains whitespace, which 'login <user> <pass>' "
                     "cannot represent", labels[i]);
                return 0;
            }
        }
    }
    return 1;
}

/* ---- entry point ---- */

static void usage(void)
{
    fputs(
        "usage: w101_autologin [options]\n"
        "\n"
        "Wizard101 auto-login through memory injection.\n"
        "\n"
        "  --pid N                 client pid (default: find it from the window)\n"
        "  --username U            prefer W101_USER, argv is world-readable\n"
        "  --password P            prefer W101_PASS, argv is world-readable\n"
        "  --credentials-file F    username on line 1, password on line 2\n"
        "  --launch DIR            start the client from DIR first, skipping the launcher\n"
        "  --login-server H:P      login server for --launch (default login.us.wizard101.com:12000)\n"
        "  --steam                 pass -ST to the client, for the Steam build\n"
        "  --check                 read-only: resolve and print the addresses\n"
        "  --wait S                seconds to wait for the client window (default 120)\n"
        "  --ready-timeout S       seconds to wait for [dat] to become valid (default 120)\n"
        "  --timeout S             seconds to wait for the payload to run (default 10)\n"
        "  --no-suspend            do not freeze threads while patching the hook site\n"
        "  -q, --quiet             no progress output\n"
        "  --dump-payload          print the payload for fixed test addresses and exit\n"
        "  -h, --help              this message\n",
        stdout);
}

int main(int argc, char **argv)
{
    char user[256] = {0}, pass[256] = {0};
    const char *cred_file = NULL, *launch_dir = NULL;
    char host[256] = "login.us.wizard101.com", port[16] = "12000";
    double wait_secs = 120.0, ready_secs = 120.0, timeout_secs = 10.0;
    int check = 0, suspend = 1, steam = 0;
    DWORD pid = 0;
    RemoteProcess proc = {0};
    Addresses addrs;
    int rc = 1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int has_next = (i + 1 < argc);
#define NEXT() (has_next ? argv[++i] : (usage(), exit(2), ""))
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        else if (!strcmp(a, "--dump-payload")) { dump_payload(); return 0; }
        else if (!strcmp(a, "--pid")) pid = (DWORD)strtoul(NEXT(), NULL, 10);
        else if (!strcmp(a, "--username")) snprintf(user, sizeof(user), "%s", NEXT());
        else if (!strcmp(a, "--password")) snprintf(pass, sizeof(pass), "%s", NEXT());
        else if (!strcmp(a, "--credentials-file")) cred_file = NEXT();
        else if (!strcmp(a, "--launch")) launch_dir = NEXT();
        else if (!strcmp(a, "--login-server")) {
            const char *v = NEXT();
            const char *colon = strrchr(v, ':');
            if (!colon) { fail("--login-server wants host:port"); return 2; }
            snprintf(host, sizeof(host), "%.*s", (int)(colon - v), v);
            snprintf(port, sizeof(port), "%s", colon + 1);
        }
        else if (!strcmp(a, "--steam")) steam = 1;
        else if (!strcmp(a, "--check")) check = 1;
        else if (!strcmp(a, "--wait")) wait_secs = atof(NEXT());
        else if (!strcmp(a, "--ready-timeout")) ready_secs = atof(NEXT());
        else if (!strcmp(a, "--timeout")) timeout_secs = atof(NEXT());
        else if (!strcmp(a, "--no-suspend")) suspend = 0;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) quiet = 1;
        else { fail("unknown argument: %s", a); usage(); return 2; }
#undef NEXT
    }

    if (!check) {
        if (cred_file) {
            if (read_credentials_file(cred_file, user, sizeof(user), pass, sizeof(pass)) != 0)
                return 2;
        }
        if (!*user) {
            const char *e = getenv("W101_USER");
            if (e) snprintf(user, sizeof(user), "%s", e);
        }
        if (!*pass) {
            const char *e = getenv("W101_PASS");
            if (e) snprintf(pass, sizeof(pass), "%s", e);
        }
        if (!*user || !*pass) {
            fail("missing credentials: use --credentials-file, --username/--password, "
                 "or export W101_USER and W101_PASS");
            return 2;
        }
        if (!credentials_valid(user, pass))
            return 2;
    }

    if (launch_dir && launch_game(launch_dir, host, port, steam) != 0)
        return 1;

    if (!pid) {
        pid = wait_for_client(wait_secs);
        if (!pid)
            return 1;
    }
    if (proc_open(&proc, pid) != 0)
        return 1;

    if (resolve(&proc, &addrs) != 0)
        goto done;

    if (check) {
        ULONGLONG ptr = 0;
        if (proc_read_u64(&proc, addrs.dat, &ptr) == 0)
            note("[dat] = 0x%llx%s", ptr, ptr ? "" : "  (client not ready yet)");
        else
            note("[dat] not readable");
        note("check complete, nothing was written");
        rc = 0;
        goto done;
    }

    if (wait_until_ready(&proc, &addrs, ready_secs) != 0)
        goto done;
    if (do_login(&proc, &addrs, user, pass, timeout_secs, suspend) != 0)
        goto done;

    note("login sent");
    rc = 0;

done:
    /* scrub the credentials from this process before it exits */
    memset(user, 0, sizeof(user));
    memset(pass, 0, sizeof(pass));
    proc_close(&proc);
    return rc;
}
