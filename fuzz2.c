#define _GNU_SOURCE
#include <netinet/in.h>
#include "all_inclusive.h"
__AFL_FUZZ_INIT();

#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNAK         6
#define DHCPRELEASE     7
#define DHCPINFORM      8
#define DHCPLEASEQUERY  10
#define DHCPLEASEUNASSIGNED 11
#define DHCPLEASEUNKNOWN 12
#define DHCPLEASEACTIVE 13

static int validate_dhcp_packet(struct dhcp_packet *dhcp_raw, int len) {
    if (len < sizeof(struct dhcp_packet)) {
        return 0; 
    }

    uint8_t msgtype = dhcp_raw->op;
    if (msgtype < DHCPDISCOVER || msgtype > DHCPLEASEACTIVE) {
        return 0; 
    }

    return 1; 
}

int main() 
{
    path_dhcpd_conf = "./dhcpd.conf";
    struct data_string *raw;
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        
        // минимальная длина пакета
        if (len < sizeof(struct dhcp_packet)) continue;

        raw = (struct data_string *)malloc(sizeof(struct data_string));
        if (!raw) continue;
        raw->buffer = NULL;
        raw->data = buf;
        raw->len = len;
        raw->terminated = (buf[len - 1] == '\0') ? 1 : 0;

        struct dhcp_packet *dhcp_raw = (struct dhcp_packet *)malloc(sizeof(struct dhcp_packet));
        if (!dhcp_raw) {
            free(raw);
            continue;
        }

        if (len <= sizeof(struct dhcp_packet)) {
            memcpy(dhcp_raw, buf, len);
        } else {
            memcpy(dhcp_raw, buf, sizeof(struct dhcp_packet));
        }

        // валидация пакета
        if (!validate_dhcp_packet(dhcp_raw, len)) {
            free(dhcp_raw);
            free(raw);
            continue; // пропустить некорректные пакеты
        }

        struct packet p = {0};
        p.raw = dhcp_raw;
        p.packet_length = len;
        p.refcnt = 1;

        dhcp(&p);

        free(dhcp_raw);
        free(raw);
    }

    return 0;
}
