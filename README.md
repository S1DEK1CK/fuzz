
#### Шаг 1: Обновите `Makefile.am`
Добавьте `dhcpd.c` в `dhcpd_fuzz_SOURCES`, как было предложено в Подходе 2 ранее:



SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/includes -I$(top_srcdir)/bind/include -I/usr/include -DLOCALSTATEDIR='"@localstatedir@"'

dist_sysconf_DATA = dhcpd.conf.example
sbin_PROGRAMS = dhcpd dhcpd_fuzz

dhcpd_SOURCES = dhcpd.c dhcp.c bootp.c confpars.c db.c class.c failover.c \
                omapi.c mdb.c stables.c salloc.c ddns.c dhcpleasequery.c \
                dhcpv6.c mdb6.c ldap.c ldap_casa.c leasechain.c ldap_krb_helper.c

dhcpd_fuzz_SOURCES = fuzz.c dhcpd.c dhcp.c bootp.c confpars.c db.c class.c failover.c \
                     omapi.c mdb.c stables.c salloc.c ddns.c dhcpleasequery.c \
                     dhcpv6.c mdb6.c ldap.c ldap_casa.c leasechain.c ldap_krb_helper.c

dhcpd_CFLAGS = $(LDAP_CFLAGS)
dhcpd_LDADD = ../common/libdhcp.a ../omapip/libomapi.a \
              ../dhcpctl/libdhcpctl.a \
              ../bind/lib/libirs.a \
              ../bind/lib/libdns.a \
              ../bind/lib/libisccfg.a \
              ../bind/lib/libisc.a $(LDAP_LIBS)

dhcpd_fuzz_CFLAGS = $(LDAP_CFLAGS) -DFUZZING_BUILD
dhcpd_fuzz_LDADD = ../common/libdhcp.a ../omapip/libomapi.a \
                   ../dhcpctl/libdhcpctl.a \
                   ../bind/lib/libirs.a \
                   ../bind/lib/libdns.a \
                   ../bind/lib/libisccfg.a \
                   ../bind/lib/libisc.a $(LDAP_LIBS)

man_MANS = dhcpd.8 dhcpd.conf.5 dhcpd.leases.5
EXTRA_DIST = $(man_MANS)


#### Шаг 2: Обновите `fuzz.c`
Убедитесь, что `fuzz.c` использует `fuzz_main()` с условием:

#define _GNU_SOURCE
#include <netinet/in.h>
#include "all_inclusive.h"
__AFL_FUZZ_INIT();

#ifdef FUZZING_BUILD
int fuzz_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
    struct data_string *raw;
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 8) continue;

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


#### Шаг 3: Обновите `dhcpd.c`
Убедитесь, что `dhcpd.c` использует условную компиляцию:

#include "dhcpd.h"

#ifdef FUZZING_BUILD
extern int fuzz_main(int argc, char **argv);

int main(int argc, char **argv) {
    return fuzz_main(argc, argv);
}
#else
int main(int argc, char **argv) {
    // Оригинальный код main() для dhcpd
    ...
}
#endif


#### Шаг 4: Пересоберите проект
Выполните полную пересборку:

cd ~/work/dhcp
autoreconf -i
CC=afl-cc ./configure --with-bind-extra=/home/menfice/work/dhcp/bind CFLAGS="-g -O2 -Wall -fno-strict-aliasing" LDFLAGS="-L/usr/lib64 -lssl -lcrypto"
make
cd server
make dhcpd_fuzz


### Проверка результата
После сборки проверьте:

ls ~/work/dhcp/server/dhcpd_fuzz

Если файл есть, запустите фаззинг:

afl-fuzz -i input_dir -o output_dir -- ./dhcpd_fuzz



