#include <netinet/in.h>
#include "all_inclusive.h"
__AFL_FUZZ_INIT();

int main(int argc, char **argv){


struct data_string *raw;

unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;



#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 8) continue;

       
       	// создание raw
        raw = (struct data_string *)malloc(sizeof(struct data_string));
        if (!raw) continue;
        raw->buffer = NULL;                
        raw->data = buf;                   
        raw->len = len;                    
        raw->terminated = (buf[len - 1] == '\0') ? 1 : 0;

       
       	// создание dhcp_packet
        struct dhcp_packet *dhcp_raw = (struct dhcp_packet *)malloc(sizeof(struct dhcp_packet));
        if (!dhcp_raw) {
            free(raw);
            continue;
        }
       


       	// копируем данные из buf в dhcp_raw если они подходят
        if (len <= sizeof(struct dhcp_packet)) {
            memcpy(dhcp_raw, buf, len);  
        } else {
            memcpy(dhcp_raw, buf, sizeof(struct dhcp_packet));  
         }

        // создание packet
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
