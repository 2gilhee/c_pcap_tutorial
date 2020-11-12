#include <if_ether.h>

struct ethernet {
    unsigned char   h_dest[ETH_ALEN];   /* destination eth addr */
    unsigned char   h_source[ETH_ALEN]; /* source ether addr    */
    unsigned short  h_proto;            /* packet type ID field */
};
