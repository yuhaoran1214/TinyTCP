#ifndef TCP_IN_H
#define TCP_IN_H

#include "tcp.h"

net_err_t tcp_in(pktbuf_t *buf, ipaddr_t *src_ip, ipaddr_t *dest_ip);
void tcp_seg_init (tcp_seg_t * seg, pktbuf_t * buf, ipaddr_t * local, ipaddr_t * remote);
net_err_t tcp_data_in (tcp_t * tcp, tcp_seg_t * seg);

#endif // TCP_IN_H
