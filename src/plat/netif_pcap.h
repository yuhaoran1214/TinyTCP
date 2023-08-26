#ifndef NETIF_PCAP_H
#define NETIF_PCAP_H

#include "net_err.h"
#include "netif.h"

/**
 * pcap网络接口驱动数据
 * 在pcap打开时传递进去的参数
 */
typedef struct _pcap_data_t {
    const char* ip;                       // 使用的网卡
    const uint8_t* hwaddr;             // 网卡的mac地址
}pcap_data_t;

extern const netif_ops_t pcap_ops;

#endif // NETIF_PCAP_H

