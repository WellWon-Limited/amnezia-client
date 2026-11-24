/* Host check of the stop contract of the patched hev library (recipes/hev-socks5-tunnel, patches 0001 + 0002).
 * Built and run by run_hev_stop_check.sh against the real library (macOS host build of the same sources); a
 * socketpair stands in for the tun fd (hev only sets it non-blocking and reads packets from it).
 *   1. A stop request made while no run is in progress is not kept: the next run is not stopped by it.
 *   2. A request made after a run returned is not kept for the next run either.
 *   3. A running hev stops on the non-blocking request, and how long it takes to return (the stop's added wait).
 *   4. A request re-driven from the moment a run is started always stops it, whatever the initialization stage it
 *      meets (the stop of a starting hev) - repeated.
 *   5. One request only, at a random point of the start: when it is kept (-EAGAIN) or queued (0) the run stops by
 *      itself; when nothing was kept (-ESRCH) the run keeps running - repeated (a lost stop would hang the run).
 * Exit 0 = every check passed. */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int hev_socks5_tunnel_main_from_str (const unsigned char *config_str, unsigned int config_len, int tun_fd);
int hev_socks5_tunnel_try_quit (void);

static const char config[] = "tunnel:\n  mtu: 9000\n"
                             "socks5:\n  port: 1080\n  address: 127.0.0.1\n  udp: 'udp'\n"
                             "misc:\n  log-level: error\n";

static int fails;
#define CHECK(cond, ...)                                                                                       \
    do {                                                                                                       \
        if (!(cond)) {                                                                                         \
            ++fails;                                                                                           \
            printf ("FAIL: ");                                                                                 \
            printf (__VA_ARGS__);                                                                              \
            printf ("\n");                                                                                     \
        }                                                                                                      \
    } while (0)

static double now_ms (void)
{
    struct timespec t;
    clock_gettime (CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

struct run {
    pthread_t thread;
    int fds[2];
    atomic_int returned;
    int rc;
    double returned_at;
};

static void *run_main (void *arg)
{
    struct run *r = arg;
    r->rc = hev_socks5_tunnel_main_from_str ((const unsigned char *)config, sizeof (config) - 1, r->fds[0]);
    r->returned_at = now_ms ();
    atomic_store (&r->returned, 1);
    return NULL;
}

static void start (struct run *r)
{
    memset (r, 0, sizeof (*r));
    socketpair (AF_UNIX, SOCK_DGRAM, 0, r->fds);
    pthread_create (&r->thread, NULL, run_main, r);
}

/* waits up to ms for the run to return; 1 = returned */
static int wait_return (struct run *r, int ms)
{
    double end = now_ms () + ms;
    while (now_ms () < end) {
        if (atomic_load (&r->returned))
            return 1;
        usleep (1000);
    }
    return atomic_load (&r->returned);
}

/* stops a run for good: re-drives the request until it returns (bounded) */
static int stop_and_join (struct run *r, int ms)
{
    double end = now_ms () + ms;
    while (!atomic_load (&r->returned) && now_ms () < end) {
        hev_socks5_tunnel_try_quit ();
        usleep (2000);
    }
    int ok = atomic_load (&r->returned);
    if (ok)
        pthread_join (r->thread, NULL);
    close (r->fds[0]);
    close (r->fds[1]);
    return ok;
}

static int cmp (const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

int main (void)
{
    struct run r;

    /* 1. a request with no run in progress */
    int rc = hev_socks5_tunnel_try_quit ();
    start (&r);
    usleep (300 * 1000);
    CHECK (!atomic_load (&r.returned), "1: a request made with no run in progress (rc %d) stopped the next run", rc);
    CHECK (stop_and_join (&r, 2000), "1: the run did not stop");

    /* 2. a request after a run returned */
    start (&r);
    usleep (100 * 1000);
    CHECK (stop_and_join (&r, 2000), "2: the first run did not stop");
    rc = hev_socks5_tunnel_try_quit ();
    start (&r);
    usleep (300 * 1000);
    CHECK (!atomic_load (&r.returned), "2: a request made after a run returned (rc %d) stopped the next run", rc);
    CHECK (stop_and_join (&r, 2000), "2: the second run did not stop");

    /* 3. a running hev: request -> return */
    double lat[50];
    for (int i = 0; i < 50; ++i) {
        start (&r);
        usleep (60 * 1000);
        double t0 = now_ms ();
        rc = hev_socks5_tunnel_try_quit ();
        int back = wait_return (&r, 2000);
        CHECK (rc == 0 && back, "3: a running hev (rc %d) did not return on the request", rc);
        lat[i] = back ? r.returned_at - t0 : 9999;
        stop_and_join (&r, 2000);
    }
    qsort (lat, 50, sizeof (double), cmp);
    printf ("3: running hev, request -> return: median %.2f ms, max %.2f ms (50 runs)\n", lat[25], lat[49]);

    /* 4. re-driven from the start */
    double worst = 0;
    for (int i = 0; i < 300; ++i) {
        double t0 = now_ms ();
        start (&r);
        int ok = stop_and_join (&r, 2000);
        CHECK (ok, "4: run %d did not stop under a re-driven request", i);
        if (!ok)
            break;
        if (now_ms () - t0 > worst)
            worst = now_ms () - t0;
    }
    printf ("4: re-driven stop of a starting hev: 300 runs, worst %.2f ms start -> return\n", worst);

    /* 5. one request at a random point of the start */
    int kept = 0, none = 0, queued = 0;
    srand (7);
    for (int i = 0; i < 300; ++i) {
        start (&r);
        usleep (rand () % 3000);
        rc = hev_socks5_tunnel_try_quit ();
        if (rc == 0 || rc == -EAGAIN) {
            rc == 0 ? ++queued : ++kept;
            CHECK (wait_return (&r, 2000), "5: run %d: a request taken (rc %d) was lost - the run kept running", i, rc);
        } else {
            ++none;
            usleep (20 * 1000);
            CHECK (!atomic_load (&r.returned), "5: run %d: rc %d kept nothing, yet the run stopped", i, rc);
        }
        if (!stop_and_join (&r, 2000)) {
            CHECK (0, "5: run %d never stopped", i);
            break;
        }
    }
    printf ("5: one request at a random point: queued %d, kept %d, none %d (300 runs)\n", queued, kept, none);

    printf (fails ? "hev stop check: %d FAILED\n" : "hev stop check: all passed%.0d\n", fails);
    return fails ? 1 : 0;
}
