/* service/server/tests/scan_helper.c - AVPN test stand-in for build_tribe_scan.sh (never shipped):
 *   scan_helper                 sleeps (a process to be killed or left alone)
 *   scan_helper probe [...]     a hung `amneziawg-go probe`: reads its job, never answers
 *   scan_helper --hold PORT     accepts TCP on 127.0.0.1:PORT and never answers (a stalled probe path)
 * Every mode ends by itself after 60 s (alarm), so a failed check leaves nothing behind. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    alarm(60);
    if (argc >= 2 && strcmp(argv[1], "probe") == 0) {
        char buf[65536];
        (void)read(0, buf, sizeof(buf));
        for (;;)
            pause();
    }
    if (argc >= 3 && strcmp(argv[1], "--hold") == 0) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons((unsigned short)atoi(argv[2]));
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 16) != 0)
            return 2;
        for (;;)
            (void)accept(s, NULL, NULL); /* held open, never answered */
    }
    sleep(30);
    return 0;
}
