#ifndef TFTP_CLIENT_H
#define TFTP_CLIENT_H

#include "tftp.h"

#define TFTP_CMD_BUF_SIZE           128     // tftp客户端命令行缓存

int tftp_start (const char * ip, uint16_t port);
int tftp_get(const char * ip, uint16_t port, int block_size, const char* filename);
int tftp_put(const char* ip, uint16_t port, int block_size, const char* filename);

#endif // TFTP_CLIENT_H