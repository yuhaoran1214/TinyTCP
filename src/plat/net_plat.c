#include "net_plat.h"
#include "dbg.h"

/**
 * @brief 平台初始化
 * 初始化过程中，不能开全局中断，因为协议栈还未跑起来
 * 可以进行如时钟、线程、信息输出等各种底层平台的初始化
 */
net_err_t net_plat_init(void) {
    dbg_info(DBG_PLAT, "init plat...");

    dbg_info(DBG_PLAT, "init done.");
    return NET_ERR_OK;
}

