#ifndef TFTP_SERVER_H
#define TFTP_SERVER_H

#include "tftp.h"

net_err_t tftpd_start (const char* dir, uint16_t port);

#endif // TFTP_SERVER_H