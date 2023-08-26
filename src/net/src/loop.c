#include "netif.h"
#include "dbg.h"
#include "exmsg.h"

/**
 * @brief 打开环回接口
 */
static net_err_t loop_open(netif_t* netif, void* ops_data) {
    netif->type = NETIF_TYPE_LOOP;
    return NET_ERR_OK;
}

/**
 * @brief 关闭环回接口
 */
static void loop_close (struct _netif_t* netif) {
}

/**
 * @brief 启动数据包的发送
 */
static net_err_t loop_xmit (struct _netif_t* netif) {
    // 从接口取收到的数据包，然后写入接收队列，并通知主线程处理
    pktbuf_t * pktbuf = netif_get_out(netif, -1);
    if (pktbuf) {
        // 写入接收队列
        net_err_t err = netif_put_in(netif, pktbuf, -1);
        if (err < 0) {
            dbg_warning(DBG_NETIF, "netif full");
            pktbuf_free(pktbuf);
            return err;
        }
    }

    return NET_ERR_OK;
}

/**
 * @brief 环回接口驱动
 */
static const netif_ops_t loop_driver = {
    .open = loop_open,
    .close = loop_close,
    .xmit = loop_xmit,
};

/**
 * @brief 初始化环回接口
 */
net_err_t loop_init(void) {
    dbg_info(DBG_NETIF, "init loop");

    // 打开接口
    netif_t * netif = netif_open("loop", &loop_driver, (void*)0);
    if (!netif) {
        dbg_error(DBG_NETIF, "open loop error");
        return NET_ERR_NONE;
    }

     // 生成相应的地址
    ipaddr_t ip, mask;
    ipaddr_from_str(&ip, "127.0.0.1");
    ipaddr_from_str(&mask, "255.0.0.0");
    netif_set_addr(netif, &ip, &mask, (ipaddr_t*)0);
    netif_set_active(netif);

    dbg_info(DBG_NETIF, "init done");
    return NET_ERR_OK;;
}

