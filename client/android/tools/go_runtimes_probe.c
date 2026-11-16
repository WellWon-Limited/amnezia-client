// Diagnostic for the Android start-up SIGSEGV (startup_crash_repro.sh): loads cgo c-shared Go libraries into one
// process in the given order, the way Qt's loader preloads libs.xml qt_libs, and prints which library owns the
// process's SIGURG / SIGSEGV / SIGBUS / SIGPIPE handlers after every load. Exit status 0 = survived the hold time;
// killed by signal 11 = the start-up crash. Emulator / test device only.
//
// Build: $NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android28-clang -O2 -o go_runtimes_probe \
//        go_runtimes_probe.c
// Usage: go_runtimes_probe [-g gap_ms] [-h hold_ms] [-q] lib1.so [lib2.so ...]
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static const char *owner(void *addr) {
    Dl_info info;
    if (addr == (void *)SIG_DFL) return "SIG_DFL";
    if (addr == (void *)SIG_IGN) return "SIG_IGN";
    if (dladdr(addr, &info) && info.dli_fname) {
        const char *base = strrchr(info.dli_fname, '/');
        return base ? base + 1 : info.dli_fname;
    }
    return "?";
}

static void report(const char *when) {
    static const int sigs[] = {SIGURG, SIGSEGV, SIGBUS, SIGPIPE};
    static const char *names[] = {"SIGURG", "SIGSEGV", "SIGBUS", "SIGPIPE"};
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        struct sigaction sa;
        sigaction(sigs[i], NULL, &sa);
        void *h = (sa.sa_flags & SA_SIGINFO) ? (void *)sa.sa_sigaction : (void *)sa.sa_handler;
        fprintf(stderr, "  after %-22s %-7s handler=%p owner=%s\n", when, names[i], h, owner(h));
    }
}

int main(int argc, char **argv) {
    int gap_ms = 0, hold_ms = 3000, quiet = 0, opt;
    while ((opt = getopt(argc, argv, "g:h:q")) != -1) {
        if (opt == 'g') gap_ms = atoi(optarg);
        else if (opt == 'h') hold_ms = atoi(optarg);
        else if (opt == 'q') quiet = 1;
        else return 2;
    }
    if (optind >= argc) {
        fprintf(stderr, "usage: %s [-g gap_ms] [-h hold_ms] [-q] lib1.so [lib2.so ...]\n", argv[0]);
        return 2;
    }
    long long t0 = now_us();
    if (!quiet) {
        fprintf(stderr, "pid %d\n", getpid());
        report("start");
    }
    for (int i = optind; i < argc; i++) {
        if (!dlopen(argv[i], RTLD_NOW | RTLD_LOCAL)) {
            fprintf(stderr, "dlopen %s: %s\n", argv[i], dlerror());
            return 2;
        }
        if (!quiet) {
            const char *base = strrchr(argv[i], '/');
            fprintf(stderr, "+%lld us loaded %s\n", now_us() - t0, argv[i]);
            report(base ? base + 1 : argv[i]);
        }
        if (gap_ms > 0 && i + 1 < argc) usleep(gap_ms * 1000);
    }
    usleep(hold_ms * 1000);
    if (!quiet) fprintf(stderr, "+%lld us survived\n", now_us() - t0);
    _exit(0);
}
