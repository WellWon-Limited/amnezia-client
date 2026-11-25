/* Host check (review R47 H1a): a stop that meets a SOCKS UDP_ASSOCIATE answer must still end hev's run at once.
 * A SOCKS5 server double accepts hev's UDP session, holds the UDP_ASSOCIATE answer and sends it exactly when the stop
 * request is made (just after it, or just before it); the TCP control connection then stays open, as Xray's socks
 * inbound keeps it (it only discards). hev's stop zeroes each session's timeout and wakes it, but a handshake that
 * completes after that used to re-arm the UDP timeout (hev-socks5-client.c, hev_socks5_client_handshake): the
 * session, and with it the run, lived on for the whole UDP timeout. Passes when every run returns within 1 s of its
 * stop request (the UDP timeout is 5 s here). Built and run by run_hev_stop_check.sh against the real library. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
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

static double now_ms (void)
{
    struct timespec t;
    clock_gettime (CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

static char config[512];
static int fails;

struct run {
    pthread_t thread;
    int fds[2];
    atomic_int returned;
    double returned_at;
};

static void *run_main (void *arg)
{
    struct run *r = arg;
    hev_socks5_tunnel_main_from_str ((const unsigned char *)config, strlen (config), r->fds[0]);
    r->returned_at = now_ms ();
    atomic_store (&r->returned, 1);
    return NULL;
}

/* the SOCKS5 server double: one control connection per run */
static int listen_fd, relay_port;
static atomic_int associate_seen, go_answer;
static int held_conn = -1;

static int read_n (int fd, unsigned char *b, int n)
{
    int got = 0;
    while (got < n) {
        ssize_t r = read (fd, b + got, n - got);
        if (r <= 0)
            return -1;
        got += r;
    }
    return got;
}

static void *socks_server (void *arg)
{
    (void)arg;
    for (;;) {
        int c = accept (listen_fd, NULL, NULL);
        if (c < 0)
            continue;
        unsigned char b[64];
        if (read_n (c, b, 2) < 0 || read_n (c, b + 2, b[1]) < 0) { close (c); continue; }
        unsigned char method[2] = { 5, 0 };
        write (c, method, 2);
        if (read_n (c, b, 4) < 0) { close (c); continue; }
        int alen = b[3] == 1 ? 4 : b[3] == 4 ? 16 : -1;
        if (alen < 0) { unsigned char l; read_n (c, &l, 1); alen = l; }
        if (read_n (c, b + 4, alen + 2) < 0) { close (c); continue; }
        if (b[1] != 3) { close (c); continue; } /* only UDP_ASSOCIATE comes in this test */
        atomic_store (&associate_seen, 1);
        while (!atomic_load (&go_answer))
            usleep (100);
        unsigned char reply[10] = { 5, 0, 0, 1, 127, 0, 0, 1, (unsigned char)(relay_port >> 8), (unsigned char)relay_port };
        write (c, reply, sizeof (reply));
        held_conn = c; /* stays open, like Xray's socks inbound after UDP_ASSOCIATE */
    }
    return NULL;
}

static unsigned short csum (const unsigned char *p, int n)
{
    unsigned long s = 0;
    for (int i = 0; i + 1 < n; i += 2)
        s += (p[i] << 8) | p[i + 1];
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (unsigned short)~s;
}

/* one UDP packet from 10.0.0.2:<sport> to 8.8.8.8:53 into the tun side, with the 4-byte AF header of utun */
static void inject_udp (int fd, int sport)
{
    unsigned char pkt[4 + 20 + 8 + 4] = { 0 };
    unsigned int af = htonl (AF_INET);
    memcpy (pkt, &af, 4);
    unsigned char *ip = pkt + 4;
    int tot = 20 + 8 + 4;
    ip[0] = 0x45; ip[2] = tot >> 8; ip[3] = tot & 0xff; ip[8] = 64; ip[9] = 17;
    ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = 2;
    ip[16] = 8; ip[17] = 8; ip[18] = 8; ip[19] = 8;
    unsigned short c = csum (ip, 20);
    ip[10] = c >> 8; ip[11] = c & 0xff;
    unsigned char *udp = ip + 20;
    udp[0] = sport >> 8; udp[1] = sport & 0xff; udp[2] = 0; udp[3] = 53; udp[4] = 0; udp[5] = 12;
    memcpy (udp + 8, "ping", 4);
    write (fd, pkt, sizeof (pkt));
}

int main (void)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl (INADDR_LOOPBACK) };
    socklen_t al = sizeof (a);
    listen_fd = socket (AF_INET, SOCK_STREAM, 0);
    bind (listen_fd, (struct sockaddr *)&a, sizeof (a));
    listen (listen_fd, 16);
    getsockname (listen_fd, (struct sockaddr *)&a, &al);
    int socks_port = ntohs (a.sin_port);
    int relay = socket (AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ra = { .sin_family = AF_INET, .sin_addr.s_addr = htonl (INADDR_LOOPBACK) };
    socklen_t rl = sizeof (ra);
    bind (relay, (struct sockaddr *)&ra, sizeof (ra));
    getsockname (relay, (struct sockaddr *)&ra, &rl);
    relay_port = ntohs (ra.sin_port);
    snprintf (config, sizeof (config),
              "tunnel:\n  mtu: 1500\n  ipv4: 10.0.0.1\n"
              "socks5:\n  port: %d\n  address: 127.0.0.1\n  udp: 'udp'\n"
              "misc:\n  log-level: error\n  udp-read-write-timeout: 5000\n  tcp-read-write-timeout: 5000\n",
              socks_port);
    pthread_t srv;
    pthread_create (&srv, NULL, socks_server, NULL);

    int hung = 0, seen = 0;
    double worst = 0;
    for (int i = 0; i < 40; ++i) {
        const int answer_first = i % 2; /* the answer just before the stop request, or just after it */
        struct run r;
        memset (&r, 0, sizeof (r));
        socketpair (AF_UNIX, SOCK_DGRAM, 0, r.fds);
        atomic_store (&associate_seen, 0);
        atomic_store (&go_answer, 0);
        pthread_create (&r.thread, NULL, run_main, &r);
        usleep (20 * 1000);
        inject_udp (r.fds[1], 40000 + i);
        double end = now_ms () + 2000;
        while (!atomic_load (&associate_seen) && now_ms () < end)
            usleep (200);
        if (!atomic_load (&associate_seen)) {
            printf ("run %d: hev opened no UDP session (no UDP_ASSOCIATE within 2 s)\n", i);
            ++fails;
        } else {
            ++seen;
        }
        double t0 = now_ms ();
        if (answer_first) {
            atomic_store (&go_answer, 1);
            hev_socks5_tunnel_try_quit ();
        } else {
            hev_socks5_tunnel_try_quit ();
            atomic_store (&go_answer, 1);
        }
        /* the stop as the extension drives it: the request again until the run returned, up to 1 s */
        end = t0 + 1000;
        while (!atomic_load (&r.returned) && now_ms () < end) {
            hev_socks5_tunnel_try_quit ();
            usleep (5000);
        }
        if (!atomic_load (&r.returned)) {
            ++hung;
            while (!atomic_load (&r.returned))
                usleep (5000); /* it ends with the UDP timeout */
            printf ("run %d (%s): the run lived %.0f ms after its stop request\n", i,
                    answer_first ? "answer, then stop" : "stop, then answer", r.returned_at - t0);
        } else if (r.returned_at - t0 > worst) {
            worst = r.returned_at - t0;
        }
        pthread_join (r.thread, NULL);
        if (held_conn >= 0) { close (held_conn); held_conn = -1; }
        close (r.fds[0]);
        close (r.fds[1]);
    }
    printf ("UDP_ASSOCIATE answered at the stop: %d runs with a UDP session, %d did not return within 1 s, worst %.2f ms of the others\n",
            seen, hung, worst);
    fails += hung;
    printf (fails ? "hev stop/session check: %d FAILED\n" : "hev stop/session check: all passed%.0d\n", fails);
    return fails ? 1 : 0;
}
