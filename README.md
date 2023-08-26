# 1、概述

本项目是使用C/C++实现了一个小型的、移植性强的TCP/IP协议栈，核心代码行数17K+，支持多种协议，允许通过路由访问Internet

协议栈已经实现了如下功能：

**平台支持**

- 支持在Windows、Linux、Mac平台上开发学习
- 采用C99标准的C语言，不依赖特定的编译器
- 代码移植性强，可容易移植到x86和嵌入式平台，如ARM等
- 只需要操作系统提供基本的信号量、互斥锁和时间获取接口即可

**硬件支持**

- 不限定具体的网络接口类型，可支持以太网外的其它接口设备

- 支持添加多个网络接口（网卡），IP数据包会自动根据路由表发到正确的接口


- 支持回环接口，实现本机的数据包自发自收


**编程接口**

- 标准Socket接口：
  - 接口：socket、bind、connnect、close
  - 接口：sendto、recvfrom、send、recv、read、write、setsockopt

- 具体类型
  - 基于SOCK_RAW：允许应用程序收发IP数据包
  - 基于SOCK_DGRAM：允许应用程序收发UDP数据包
  - 基于SOCK_STREAM（开发中）：允许应用程序收发UDP数据包

**协议支持**

- 以太网协议：支持以太网数据包的收发和数据包的处理

- 地址解析协议ARP
  - 完整支持ARP的查询和响应过程
  - 支持无回报（免费）ARP包的发送
  - 使用可配置的大小的ARP缓存，可提升查询效率
  - 使用定时期周期性地更新ARP缓存，自动清理无效的缓存项
  - 可使用输入的ARP包和IP包进行缓存的更新，减少网络通信量

- IPv4协议
  - 支持基本的IP数据包的收发、校验和的计算
  - 支持IP数据包的分片与重组、重组超时处理
  - 内置路由表，从而可以通过路由器上网

- ICMPv4协议
  - 支持对输入的echo请求进行响应（即可以让别人ping自己）
  - 提供发送目的端口不可达的信息，以便通知其它机器访问错误

- UDP协议：基本的UDP输入输出处理，将输入包正确传递给应用程序


TCP协议：实现TCP建立连接、滑动窗口、保活机制、被动打开、超时重传等机制，可使用TCP实现数据可靠传输；

- 应用层协议：
  - 网络时间服务NTP：实现了客户端，可以查询NTP服务器获取当前时间
  - 简单文件传输协议TFTP
    - 实现TFTP客户端：可以从服务器端上传和下载文件
    - 实现TFTP服务器：允许客户端向服务器上传和下载文件
    - 支持带选项的TFTP请求处理
    - 数据包丢失时可自动重发
  - 域名解析协议DNS

# 2、基础类型定义

## 2.1 通用链表结构

使用双向链表，可以快速的对链表中的任意节点进行快速删除，而不必从表头开始遍历，找到位置后才能进行删除。

在协议栈中，链表的节点会作为其他结构体中的一个字段，然后借助链表节点，可将这些结构体数据用链表连接起来

### 2.1.1 结构定义

通用链表结构分为：通用链表结构和节点结构。

链表定义所在文件：

- 通用链表结构的定义：/src/net/net/nlist.h

```c
typedef struct _nlist_t {
    nlist_node_t * first;            // 头结点
    nlist_node_t * last;             // 尾结点
    int count;                      // 结点数量
}nlist_t;
```

- 节点结构的定义：

```c
typedef struct _nlist_node_t {
    struct _nlist_node_t* next;         // 前驱结点
    struct _nlist_node_t* pre;          // 后继结点
}nlist_node_t;
```

### 2.1.2 遍历链表

链表结点通常是作为某个结构体中的字段。在使用链表将这些结构体链接起来时，对于链表而言，它看到的只是结构体中的这些链表结点，并不知道完整的结构体。

因此，在遍历时，除了按照普通的链表遍历算法，从表头开始去遍历外，为了能够获得这个结构体中其它字段的信息，我们需要知道该结构体所在的位置。为此，课程中定义了一个宏去计算：

1.求结点在所在结构中的偏移:定义一个指向0的指针，用(struct aa *)&0->node，所得即为node字段在整个结构体的偏移

```c
#define noffset_in_parent(parent_type, node_name)    \
    ((char *)&(((parent_type*)0)->node_name))
```

2.求node所在的结构体首址：node的地址 - node的偏移，用node的真实地址-node的偏移量

```c
#define noffset_to_parent(node, parent_type, node_name)   \
    ((char *)node - noffset_in_parent(parent_type, node_name))
```

3. 进行转换: (struct aa *)addr

```c
#define nlist_entry(node, parent_type, node_name)   \
        ((parent_type *)(node ? noffset_to_parent((node), parent_type, node_name) : 0))
```

链表的遍历

```c
#define nlist_for_each(node, list)      for (node = (list)->first; node; node = node->next)
```



## 2.2 定长内存块管理

在一些系统中，内核并没有提供动态分配内存的函数，同时为了减少动态分配内存造成的内存碎片等问题，本协议栈在设计时采用固定长度的存储分配。

定长存储管理方式的实现非常简单： **预先给定一大块内存，其中有很多相同大小的内存块，用链表将这些空闲的内存块链表链接起来。在需要分配内存时，从这个链表中分配一个内存块 。**

这种方式实现非常简单，易于理解，分配和释放的效率很高，但是缺点也比较明显； 一是必须预预先将这个大块的内存分配出来，以方便建立链表；二是每次分配和释放都比较以内存块为单位 。

在后面的协议栈实现中，可以看到用起来比较简单。并且此种方法不依赖于操作系统，不需要提供任何平台提供任何类似malloc()的函数，这使得协议栈可移植到不同的平台上。

### 2.2.1 内存块管理器结构

内存管理结构的实现较简单，主要包含几个字段：空闲链表、锁和同步信号量。

其中锁结构目前只考虑多个线程进行内存分配和释放的情况，因此使用互斥信号量（锁）来控制。同时，考虑到有的线程在申请内存，有的信号要释放内存，二者可能在某些情况需要同步行为，因此添加信号量来控制。

**内存块管理器：**

```c
typedef struct _mblock_t{
    void* start;                        // 所有存储的起始地址
    nlist_t free_list;                   // 空闲的消息队列
    nlocker_t locker;                   // 访问的锁
    sys_sem_t alloc_sem;                // 分配同步用信号量
}mblock_t;
```

**锁的类型：**

```c
typedef enum _nlocker_type_t {
    NLOCKER_NONE,                   // 不需要锁
    NLOCKER_THREAD,                 // 用于线程共享的锁
    NLOCKER_INT,                    // 中断相关的锁
}nlocker_type_t;
```

```c
typedef struct _nlocker_t {
    nlocker_type_t type;                // 锁的类型

    // 根据不同的锁类型，放置不同的结构
    union {
        sys_mutex_t mutex;           // 用于线程之间访问的互斥锁
#if NETIF_USE_INT == 1
        sys_intlocker_t state;      // 中断锁
#endif
    };
}nlocker_t;
```



### 2.2.2 建立内存块链

**初始化存储块管理器**，将mem开始的内存区域划分成多个相同大小的内存块，然后用链表链接起来

```c
net_err_t mblock_init (mblock_t* mblock, void * mem, int blk_size, int cnt, nlocker_type_t share_type) {
    // 链表使用了nlist_node结构，所以大小必须合适
    dbg_assert(blk_size >= sizeof(nlist_node_t), "size error");

    // 将缓存区分割成一块块固定大小内存，插入到队列中
    uint8_t* buf = (uint8_t*)mem;
    nlist_init(&mblock->free_list);
    for (int i = 0; i < cnt; i++, buf += blk_size) {
        nlist_node_t* block = (nlist_node_t*)buf;
        nlist_node_init(block);
        nlist_insert_last(&mblock->free_list, block);
    }

    // 初始化锁
    nlocker_init(&mblock->locker, share_type);

    // 创建分配同步用的信号量，由于线程访问处理
    if (share_type != NLOCKER_NONE) {
        mblock->alloc_sem = sys_sem_create(cnt);
        if (mblock->alloc_sem == SYS_SEM_INVALID) {
            dbg_error(DBG_MBLOCK, "create sem failed.");
            nlocker_destroy(&mblock->locker);
            return NET_ERR_SYS;
        }
    }


    return NET_ERR_OK;
}
```

### 2.2.3 分配和释放内存块

当需要申请内存块时，可以从空闲列表中移除。但是这个过程有两个问题需要考虑： **一是空闲链表中是否有可供分配的内存块？二是如果没有内存块是否要等待以及等待多长时间 ？**因此，在实现内存块的申请时，有做了对以上的问题的处理。 当不需要等待时，如果有可分配的内存块，则分配出去；没有，也返回。

但是，如果需要等待，则必须借助信号量来控制其在别的线程释放了内存块之后再去从链表中取。 

- mblock添加了一个信号量，其值被设置为空闲列表中内存块的数量相同。 

- 当空闲链表为空时，信号量的值也为0，因此申请内存块的线程将等待。 

- 当其它线程释放内存块时，将唤醒等待的线程，通知该线程从链表中取。如果没有线程等，将信号量计数+1，表示其多了一块空闲内存块。

  另外，考虑到空闲链表被多个线程访问，因此需要在从链表中取出和加入内存块时，使用锁进行保护。

**分配一个空闲的存储块**

```c
void * mblock_alloc(mblock_t* mblock, int ms) {
    // 无需等待的分配，查询后直接退出
    if ((ms < 0) || (mblock->locker.type == NLOCKER_NONE)) {
        nlocker_lock(&mblock->locker);
        int count = nlist_count(&mblock->free_list);
        nlocker_unlock(&mblock->locker);

        // 没有，则直接返回了，无等待则直接退出
        if (count == 0) {
            return (void*)0;
        }
    }

    // 消耗掉一个资源
    if (mblock->locker.type != NLOCKER_NONE) {
        sys_sem_wait(mblock->alloc_sem, ms);
    }

    // 获取分配得到的项
    nlocker_lock(&mblock->locker);
    nlist_node_t* block = nlist_remove_first(&mblock->free_list);
    nlocker_unlock(&mblock->locker);
    return block;
}
```

**释放存储块**

```c
void mblock_free(mblock_t* mblock, void* block) {
    nlocker_lock(&mblock->locker);
    nlist_insert_last(&mblock->free_list, (nlist_node_t *)block);
    nlocker_unlock(&mblock->locker);

    // 释放掉一个资源，通知其它任务该资源可用
    if (mblock->locker.type != NLOCKER_NONE) {
        sys_sem_notify(mblock->alloc_sem);
    }
}
```



## 2.3 定长消息队列

本消息队列主要用于网卡驱动、应用程序与核心工作线程之间的通信。由于这其中涉及到多线程之间的通信，因此需要一种通信机制。不同操作系统提供的用于线程间通信的机制各不相同，因此本协议栈为提高可移植性，仅利用**信号量**和**锁**来实现自己的消息队列。

在设计时，需要考虑以下几个问题。其中最重要几部分工作为：

1. 多线程环境下消息队列的访问需要加锁保护
2. 写消息和读消息之间需要用信号量进行同步



在整个协议栈中，数据包需要排队，线程之间的通信消息也需要排队，因此需要借助于消息队列实现。该消息队列长度是定长的，以避免消息数量太多耗费太多资源。

### **2.3.1 定长消息队列结构**

```c
typedef struct _fixq_t{
    int size;                               // 消息容量
    void** buf;                             // 消息缓存
    int in, out, cnt;                       // 读写位置索引，消息数
    nlocker_t locker;                       // 访问的锁
    sys_sem_t recv_sem;                     // 接收消息时使用的信号量
    sys_sem_t send_sem;                     // 发送消息时使有的信号量
}fixq_t;
```

### 2.3.2 预分配消息缓存

所有的消息全部采用了预定义的方式，如msg_buffer。**这样后续应用和网卡驱动发消息时，就可以从这里分配一个空闲的消息，然后再发给工作线程。**

```c
static void * msg_tbl [ EXMSG_MSG_CNT ]; // 消息缓冲区
static fixq_t msg_queue ; // 消息队列
static exmsg_t msg_buffer [ EXMSG_MSG_CNT ]; // 消息块
static mblock_t msg_block ; // 消息分配器
```

之所以要这样做，因为很多情况下，应用程序或网卡驱动在工作线程发消息之后，并不会等工作线程处理完毕之后，而是往下消息队列写入消息之后立即做其它的工作。因此，消息需要暂存不能释放，因此该消息从某个地方预先分配，然后等工作 线程处理完之后再释放。

### **2.3.3 消息队列相关函数**

```c
net_err_t fixq_init(fixq_t * q, void ** buf, int size, nlocker_type_t share_type);
net_err_t fixq_send(fixq_t* q, void* msg, int tmo);
void * fixq_recv(fixq_t* q, int tmo);
void fixq_destroy(fixq_t * q);
int fixq_count (fixq_t *q);
```

#### 2.3.3.1 发送消息

向消息队列写入一个消息，如果消息队列满，则看下tmo，如果tmo < 0则不等待

用到了两个信号量，第一个**用于等待可用的空闲写入空间**，第二个是**用于通知读线程有消息到达。**

```c
net_err_t fixq_send(fixq_t *q, void *msg, int tmo) {
    nlocker_lock(&q->locker);
    if ((q->cnt >= q->size) && (tmo < 0)) {
        // 如果缓存已满，并且不需要等待，则立即退出
        nlocker_unlock(&q->locker);
        return NET_ERR_FULL;
    }
    nlocker_unlock(&q->locker);

    // 消耗掉一个空闲资源，如果为空则会等待
    if (sys_sem_wait(q->send_sem, tmo) < 0) {
        return NET_ERR_TMO;
    }

    // 有空闲单元写入缓存
    nlocker_lock(&q->locker);
    q->buf[q->in++] = msg;
    if (q->in >= q->size) {
        q->in = 0;
    }
    q->cnt++;
    nlocker_unlock(&q->locker);

    // 通知其它进程有消息可用
    sys_sem_notify(q->recv_sem);
    return NET_ERR_OK;
}
```

#### 2.3.3.2 接收消息

从数据包队列中取一个消息，如果无，则等待

用到了两个信号量，**第一个用于等待队列中可用的消息**；**第二个用于通知写入方有空闲的单元可用。**

```c
void *fixq_recv(fixq_t *q, int tmo) {
    // 如果缓存为空且不需要等，则立即退出
    nlocker_lock(&q->locker);
    if (!q->cnt && (tmo < 0)) {
        nlocker_unlock(&q->locker);
        return (void *)0;
    }
    nlocker_unlock(&q->locker);

    // 在信号量上等待数据包可用
    if (sys_sem_wait(q->recv_sem, tmo) < 0) {
        return (void *)0;
    }

    // 取消息
    nlocker_lock(&q->locker);
    void *msg = q->buf[q->out++];
    if (q->out >= q->size) {
        q->out = 0;
    }
    q->cnt--;
    nlocker_unlock(&q->locker);

    // 通知有空闲空间可用
    sys_sem_notify(q->send_sem);
    return msg;
}
```

### 2.3.4 为什么不采用消息拷贝的方式

所有的消息，最终都是采用传消息的指针的方式写入消息队列，这样效率更高，可以避免整个消息的两次复制，**一是写入时，二是读取时。**



## 2.4 网络数据包结构

因为不同的包的大小不同，因此不能使用定长的数据包来存储，需要让数据包的容量大小可以调整。借鉴FAT32文件系统的文件管理方式，数据包采用链式存储。

当然，也可以使用malloc动态分配每个包的内存，但容易造成内存碎片问题，效率也比较低


### **2.4.1 数据包的基本操作**

#### 2.4.1.1 添加包头和移除包头


#### 2.4.1.2 对数据包的任意位置进行读写


#### 2.4.1.3 调整大小合并数据包


### 2.4.2 数据包的整体结构图

整个包链表是一个数据包的链表，链表中每一个节点都是一个数据包，每一个数据包中有一个blk_list指针，指向一个数据块链表，数据块链表中是一个一个的数据块，里面存放着数据包的数据。


payload是实际存放数据的地方，数据在payload里存放的位置是未知的，是通过data来得到偏移量确定数据区的首地址。




### 2.4.3网络数据包结构

#### 2.4.3.1 数据块结构

```c
typedef struct _pktblk_t {
    nlist_node_t node;                       // 用于连接下一个块的结
    int size;                               // 块的大小
    uint8_t* data;                          // 当前读写位置
    uint8_t payload[PKTBUF_BLK_SIZE];       // 数据缓冲区
}pktblk_t;
```


#### 2.4.3.2 网络包类型

```c
typedef struct _pktbuf_t {
    int total_size;                         // 包的总大小
    nlist_t blk_list;                        // 包块链表
    nlist_node_t node;                       // 用于连接下一个兄弟包

    // 读写相关
    int ref;                                // 引用计数
    int pos;                                // 当前位置总的偏移量
    pktblk_t* curr_blk;                     // 当前指向的buf
    uint8_t* blk_offset;                    // 在当前buf中的偏移量
}pktbuf_t;
```


### 2.4.4 数据包管理相关函数

```c
net_err_t pktbuf_init(void);
pktbuf_t* pktbuf_alloc(int size);
void pktbuf_free (pktbuf_t * buf);
net_err_t pktbuf_add_header(pktbuf_t* buf, int size, int cont);
net_err_t pktbuf_remove_header(pktbuf_t* buf, int size);
net_err_t pktbuf_resize(pktbuf_t * buf, int to_size);
net_err_t pktbuf_join(pktbuf_t* dest, pktbuf_t* src);
net_err_t pktbuf_set_cont(pktbuf_t* buf, int size);

void pktbuf_reset_acc(pktbuf_t* buf);
int pktbuf_write(pktbuf_t* buf, uint8_t* src, int size);
int pktbuf_read(pktbuf_t* buf, uint8_t* dest, int size);
net_err_t pktbuf_seek(pktbuf_t* buf, int offset);
net_err_t pktbuf_copy(pktbuf_t* dest, pktbuf_t* src, int size);
net_err_t pktbuf_fill(pktbuf_t* buf, uint8_t v, int size);
void pktbuf_inc_ref (pktbuf_t * buf);
uint16_t pktbuf_checksum16(pktbuf_t* buf, int size, uint32_t pre_sum, int complement);
```



## 2.5 定时器结构

在整个协议栈中，有很多地方都需要用到超时处理，例如：

- ARP协议中ARP缓存表的定时扫描
- IP数据包分片重组的超时删除
- TCP重发定时、KeepAlive定时器等

这些事件中，有的是一次性处理的，即超时后执行一次定时处理函数即终止定时器；另一种是周期性的执行某个 定时函数。


由于系统中定时器数量比较多，因此在设计上需要将这些定时器用链表连接起来进行管理，并考虑到扫描定时列表的效率，采用了时长递增的方式组织。


在设计定时器是有考虑过如下两种方法：

1. 额外的定时器线程，使用sleep进行延时，然后发消息给工作线程处理定时事件或者由定时器线程处理定时事件，但是这样会需要额外的线程，栈空间，需要考虑多线程的资源访问互斥问题等，过于耗费资源
2. 完全在工作线程上处理，自行判断扫描定时器，代码上会稍复杂一点，不好理解，但是资源消耗更少。

因此，本课程中采用的是第2种方法。

### 2.5.1 定时器结构

```c
/**
 * @brief 定时器结构
 */
typedef struct _net_timer_t {
    char name[TIMER_NAME_SIZE];     // 定时器名称
    int flags;                          // 是否自动重载

    int curr;                           // 当前超时值，以毫秒计
    int reload;                         // 重载的定时值，以毫秒计

    timer_proc_t proc;                  // 定时处理函数
    void * arg;                         // 定义参数
    nlist_node_t node;                   // 链接接点
}net_timer_t;
```

```c
#define NET_TIMER_RELOAD        (1 << 0)       // 自动重载
```

如果flag的第0位是1，则说明定时器是周期性定时器

### 2.5.2 添加、取消定时器

添加定时器

```c
net_err_t net_timer_add(net_timer_t * timer, const char * name, timer_proc_t proc, void * arg, int ms, int flags) {
    dbg_info(DBG_TIMER, "insert timer: %s", name);

    plat_strncpy(timer->name, name, TIMER_NAME_SIZE);
    timer->name[TIMER_NAME_SIZE - 1] = '\0';
    timer->reload = ms;
    timer->curr = timer->reload;
    timer->proc = proc;
    timer->arg = arg;
    timer->flags = flags;

    // 插入到定时器链表中
    insert_timer(timer);

    display_timer_list();
    return NET_ERR_OK;
}
```

移除定时器

除了移除定时器本身以外，还需要将其后的定时器时间计数进行调整，这个计时器移除以后，如果有后面的计时器，将移除的定时器的时间加到后面的计时器中。

```c
void net_timer_remove (net_timer_t * timer) {
    dbg_info(DBG_TIMER, "remove timer: %s", timer->name);

    // 遍历列表，找到timer
    nlist_node_t * node;
    nlist_for_each(node, &timer_list) {
        net_timer_t * curr = nlist_entry(node, net_timer_t, node);
        if (curr != timer) {
            continue;
        }

        // 如果有后继结点，只需调整后继结点的值
        nlist_node_t * next = nlist_node_next(node);
        if (next) {
            net_timer_t * next_timer = nlist_entry(next, net_timer_t, node);
            next_timer->curr += curr->curr;
        }

        // 移除结点后结束
        nlist_remove(&timer_list, node);
        break;
    }

    // 更新完成后，显示下列表，方便观察
    display_timer_list();
}
```

### 2.5.3 插入定时器

按递增排序的方式进行插入排序。这样每次扫描时，只需要判断链表开头的定时器是否超时。 只要某个定时器没超时，那么其后面所有的定时器必定不可能超时 。

为了方便进行定时扫描，对定时器的计数值进行了调整，使得前面某个定时器的超时时间为其前面所有定时器的超时时间+自身超时时间之和。
		如此一来，扫描时只需要对第一个定时器的计数值减，当减到0时即超时。之后，只需要扫描其后所有超时为0的定时器即可。


遍历定时器链表，待插入的结点超时比当前结点超时大，先将自己的时间减一下，然后继续往下遍历。

如果超时时间和当前定时器时间相等，超时调整为0，即超时相等，插入到这个定时器后面。

比当前超时短，插入到当前之前，那么当前的超时时间要减一下

```c
/**
 * @brief 将结点按超时时间从小到达插入进链表中
 */
static void insert_timer(net_timer_t * insert) {
    nlist_node_t* node;
    nlist_node_t *pre = (nlist_node_t *)0;

    nlist_for_each(node, &timer_list) {
        net_timer_t * curr = nlist_entry(node, net_timer_t, node);

        // 待插入的结点超时比当前结点超时大，应当继续往后寻找
        // 因此，先将自己的时间减一下，然后继续往下遍历
        if (insert->curr > curr->curr) {
            insert->curr -= curr->curr;
        } else if (insert->curr == curr->curr) {
            // 相等，插入到其之后，超时调整为0，即超时相等
            insert->curr = 0;
            nlist_insert_after(&timer_list, node, &insert->node);
            return;
        } else {
            // 比当前超时短，插入到当前之前，那么当前的超时时间要减一下
            curr->curr -= insert->curr;
            if (pre) {
                nlist_insert_after(&timer_list, pre, &insert->node);
            } else {
                nlist_insert_first(&timer_list, &insert->node);
            }
            return;
        }
        pre = node;
    }

    // 找不到合适的位置，即超时比所有的都长，插入到最后
    nlist_insert_last(&timer_list, &insert->node);
}
```

### 2.5.4 打印定时器

遍历链表，打印所有的定时器，方便调试

```c
static void display_timer_list(void) {
    plat_printf("--------------- timer list ---------------\n");

    nlist_node_t* node;
    int index = 0;
    nlist_for_each(node, &timer_list) {
        net_timer_t* timer = nlist_entry(node, net_timer_t, node);

        plat_printf("%d: %s, period = %d, curr: %d ms, reload: %d ms\n",
            index++, timer->name,
            timer->flags & NET_TIMER_RELOAD ? 1 : 0,
            timer->curr, timer->reload);
    }
    plat_printf("---------------- timer list end ------------\n");
}
```

### 2.5.5 扫描定时器列表

扫描过程是比较简单的，即从表头开始扫。但是要注意， 在扫描过程中遇到超时的定时器，不要立即进行处理，因为有可能有些定时器需要重新被插入到链表中，而此时恰好正在遍历列表，有可能造成遍历错误 。

```c
/**
 * @brief 定时事件处理
 * 该函数不会被周期性的调用，其前后两次调用的时间未知
 */
net_err_t net_timer_check_tmo(int diff_ms) {
    // 需要重载的定时器链表
    nlist_t wait_list;
    nlist_init(&wait_list);

    // 遍历列表，看看是否有超时事件
    nlist_node_t* node = nlist_first(&timer_list);
    while (node) {
        // 预先取下一个，因为后面有调整结点的插入，链接关系处理不同，有可能导致整个遍历死循环
        nlist_node_t* next = nlist_node_next(node);

        // 减掉当前过去的时间，如果定时还未到，就可以退出了
        net_timer_t* timer = nlist_entry(node, net_timer_t, node);
        dbg_info(DBG_TIMER, "timer: %s, diff: %d, curr: %d, reload: %d\n",
                    timer->name, diff_ms, timer->curr, timer->reload);
        if (timer->curr > diff_ms) {
            timer->curr -= diff_ms;
            break;
        }

        // diff_time的时间可能比当前定时的时间还要大
        // 这意味着，后续可能还存在很多tmo!=0的情况需要处理
        // 所以，这里将diff_time给减掉一块，使得后续循环时能正确计算
        // 当然此时diff_time也可能为0，但为0也可能需要继续搜索，因为后面的timer的c_tmo也可能为0
        diff_ms -= timer->curr;

        // diff_time >= c_tmo，即超时时间到，包含c_tmo=0的情况
        // 定时到达，设置tmo = 0，从这里移除插入到待处理列表
        timer->curr = 0;
        nlist_remove(&timer_list, &timer->node);
        nlist_insert_last(&wait_list, &timer->node);

        // 继续搜索下一结点
        node = next;
    }

    // 执行定时函数，如果定时器需要重载，则重新插入链表
    while ((node = nlist_remove_first(&wait_list)) != (nlist_node_t*)0) {
        net_timer_t* timer = nlist_entry(node, net_timer_t, node);

        // 执行调用
        timer->proc(timer, timer->arg);

        // 重载定时器，先加入到等待插入的链表，避免破解现有的遍历
        if (timer->flags & NET_TIMER_RELOAD) {
            timer->curr = timer->reload;
            insert_timer(timer);
        }
    }

    display_timer_list();
    return NET_ERR_OK;
}
```

### 2.5.6 让工作线程处理定时事件

定时器的扫描没有使用额外的线程，因为这样会因为创建新线程而增加系统开销，同时又需要考虑与工作线程访问某些共享资源之间的冲突。因此，定时器列表的扫描也交由工作线程去处理。

定时器列表的扫描并没有采用周期性的扫描列表的方式，而是让工作线程在空闲的时间去扫描列表。虽然工作线程在不断地使用fixq_recv等消息队列中的消息，但是可以让fixq_recv允许接受一个超时时间。 通过将这个超时间设置为定时器列表的第一个定时器超时值，就可以保证工作线程最多能在定时器超时到达之前就能处理该定时，扫描定时器列表。

```c
static void work_thread (void * arg) {
    // 注意要加上\n。否则由于C库缓存的关系，字符串会被暂时缓存而不输出显示
    dbg_info(DBG_MSG, "exmsg is running....\n");

    // 先调用一下，以便获取初始时间
    net_time_t time;
    sys_time_curr(&time);

    int time_last = TIMER_SCAN_PERIOD;
    while (1) {
        // 有时间等待的等消息，这样就能够及时检查定时器也能同时检查定时消息
        int first_tmo = net_timer_first_tmo();
        exmsg_t* msg = (exmsg_t*)fixq_recv(&msg_queue, first_tmo);
        
        // 计算相比之前过去了多少时间
        int diff_ms = sys_time_goes(&time);
        time_last -= diff_ms;
        if (time_last < 0) {
            // 不准确，但是够用了，不需要那么精确
            net_timer_check_tmo(diff_ms);
            time_last = TIMER_SCAN_PERIOD;
       }
       
        if (msg) {
            // 消息到了，打印提示
            dbg_info(DBG_MSG, "recieve a msg(%p): %d", msg, msg->type);
            switch (msg->type) {
            case NET_EXMSG_NETIF_IN:          // 网络接口消息
                do_netif_in(msg);
                break;
            case NET_EXMSG_FUN:               // API消息
                do_func(msg->func);
                break;
            }

            // 释放消息
            mblock_free(&msg_block, msg);
        }
    }
}
```

定时扫描时依赖两个可移植地操作系统接口，这里的时间对应的是真实世界中时间流逝。因此，当程序因断点等原因暂停运行，时间也是在不断地流逝的。

```c
void sys_time_curr ( net_time_t * time );
int sys_time_goes ( net_time_t * pre );
```



# 3、各协议定义

## 3.1 网络接口层

#### 3.1.1 网络接口层定义

```c
typedef struct _netif_t {
    char name[NETIF_NAME_SIZE];             // 网络接口名字

    netif_hwaddr_t hwaddr;                  // 硬件地址
    ipaddr_t ipaddr;                        // ip地址
    ipaddr_t netmask;                       // 掩码
    ipaddr_t gateway;                       // 网关

    enum {                                  // 接口状态
        NETIF_CLOSED,                       // 已关注
        NETIF_OPENED,                       // 已经打开
        NETIF_ACTIVE,                       // 激活状态
    }state;

    netif_type_t type;                      // 网络接口类型
    int mtu;                                // 最大传输单元

    const netif_ops_t* ops;                 // 驱动类型
    void* ops_data;                         // 底层私有数据

    const link_layer_t* link_layer;         // 链路层结构

    nlist_node_t node;                       // 链接结点，用于多个链接网络接口
    
    fixq_t in_q;                            // 数据包输入队列
    void * in_q_buf[NETIF_INQ_SIZE];
    fixq_t out_q;                           // 数据包发送队列
    void * out_q_buf[NETIF_OUTQ_SIZE];

    // 可以在这里加入一些统计性的变量
}netif_t;
```

#### 3.1.2 硬件地址

```Cpp
typedef struct _netif_hwaddr_t {
    uint8_t len;                            // 地址长度
    uint8_t addr[NETIF_HWADDR_SIZE];        // 地址空间
}netif_hwaddr_t;
```

#### 3.1.3 网络接口类型

```cpp
typedef enum _netif_type_t {
    NETIF_TYPE_NONE = 0,                // 无类型网络接口
    NETIF_TYPE_ETHER,                   // 以太网
    NETIF_TYPE_LOOP,                    // 回环接口

    NETIF_TYPE_SIZE,
}netif_type_t;
```

#### 3.1.4 网络接口支持的操作

```cpp
typedef struct _netif_ops_t {
    net_err_t(*open) (struct _netif_t* netif, void * data);
    void (*close) (struct _netif_t* netif);

    net_err_t (*xmit)(struct _netif_t* netif);
}netif_ops_t;
```

#### 3.1.5 链路层处理接口

```cpp
typedef struct _link_layer_t {
    netif_type_t type;

    net_err_t (*open)(struct _netif_t* netif);
    void(*close)(struct _netif_t* netif);
    net_err_t (*in)(struct _netif_t* netif, pktbuf_t* buf);
    net_err_t (*out)(struct _netif_t* netif, ipaddr_t* dest, pktbuf_t* buf);
}link_layer_t;
```

#### 3.1.6 相关函数

```c
net_err_t netif_init(void);
netif_t* netif_open(const char* dev_name, const netif_ops_t* driver, void* driver_data);
net_err_t netif_set_addr(netif_t* netif, ipaddr_t* ip, ipaddr_t* netmask, ipaddr_t* gateway);
net_err_t netif_set_hwaddr(netif_t* netif, const uint8_t* hwaddr, int len);
net_err_t netif_set_active(netif_t* netif);
net_err_t netif_set_deactive(netif_t* netif);
void netif_set_default (netif_t * netif);
netif_t * netif_get_default (void);
net_err_t netif_close(netif_t* netif);
net_err_t netif_register_layer(int type, const link_layer_t* layer);

// 数据包输入输出管理
net_err_t netif_put_in(netif_t* netif, pktbuf_t* buf, int tmo);
net_err_t netif_put_out(netif_t * netif, pktbuf_t * buf, int tmo);
pktbuf_t* netif_get_in(netif_t* netif, int tmo);
pktbuf_t* netif_get_out(netif_t * netif, int tmo);
net_err_t netif_out(netif_t* netif, ipaddr_t* ipaddr, pktbuf_t* buf);
```

## 3.2 以太网协议

以太网协议的主要功能：**发送上层传来的IP数据包到相邻计算机，接收数据包提取出IP数据包上传到上层**。

以太网有很多类型。不同类型的帧具有不同的格式个MTU值。Ethernet II

<img src="D:\assets\image-20230806130857537.png" alt="image-20230806130857537" style="zoom:80%;" />

各字段的意义如下：

- 目的地址和源地址分别为帧发往哪个网卡和从哪个网卡发出。每块网卡都有一个全球唯一的地址，就像人的身份证号一样，该地址常被称为：MAC地址/硬件地址/物理地址。
- 类型：指明数据负载的数据对应于哪种上层类型协议的数据包，如IP或ARP。（有的资料中会提及这个字段也可用作长度，本课程不讨论这个问题）
- 数据负载：要发送或接收的数据字节量
- 校验：发送时一般由网卡自动填充，在接收时由网卡用于辅助检查帧的完整性和错误。如果发现校验失败，整个数据包被丢弃。

各字段大小如上图所示。 其中数据负载部分要求至少46字节，如果不够，则应当填充至46字节。数据负载部分的最大字节量，称之为最大传输单元（MTU） 。

### 3.2.1 以太网结构

```c
/**
 * @brief 以太网帧头
 */
typedef struct _ether_hdr_t {
    uint8_t dest[ETH_HWA_SIZE];         // 目标mac地址
    uint8_t src[ETH_HWA_SIZE];          // 源mac地址
    uint16_t protocol;                  // 协议/长度
}ether_hdr_t;
```

```c
/**
 * @brief 以太网帧格式
 * 肯定至少要求有1个字节的数据
 */
typedef struct _ether_pkt_t {
    ether_hdr_t hdr;                    // 帧头
    uint8_t data[ETH_MTU];              // 数据区
}ether_pkt_t;
```

内存对齐可能导致type内存对齐，使得data中前两个字节被填充了内存对齐

因此在我们使用结构体指针去访问内存中的数据时，需要考虑到对齐的问题，否则将因为对齐导致访问的位置出现偏移。

为避免出现该偏移，课程中使用了#pragma pack(1)来禁用这种对齐填充，即使用1字节的对齐。之后使用#pragma pack()来取消之前设置的对齐。

在使用GCC编译器是，还可以使用__attribute__((packed))来禁用这种对齐，例如：

```c
struct str_b {
    uint8_t a ;
    uint32_t b ;
    uint8_t c [ 1 ];
} __attribute__ (( packed ));
```



## 3.3 ARP协议

TCP/IP协议中使用IP地址来定位到主机的网络接口。IP地址与具体的物理链接类型无关，但是在将数据发送到具体的链接上时，需要知道硬件地址。

我们需要把IP地址转换成硬件地址，才能把数据包通过以太网发送到对应主机上。

ARP协议可用于实现IPv4地址到硬件地址之间的转换。本课程只讨论IPv4到以太网48位Mac地址的转换。IPv6不使用ARP协议，而使用ICMPv6中的邻居发现协议。底层协议PPP也不需要使用ARP协议。

具体转换过程：ARP协议在转换IP地址时，**先向网络中发送一个以太网广播**，请求拥有该IP地址的主机回应，在收到相应的回应之后从中提取出硬件地址。

为了避免每次都查询，协议栈应当将之前的结果进行缓存，以便下次使用。

在缓存起来后，为了保证这个表没有过于老旧，需要适当的更新。因此，需要相应的超时处理机制，对ARP表进行动态地更新。这样当有计算机退出时，或者更新IP地址后，协议栈能够自动查询更新表，从而使得表保持一个比较新的状态。

除此之外，当计算机重新启动、网卡重启时，协议栈也会发送ARP数据包来主动通知网络上的计算机更新ARP表。这样，就能够时刻保持ARP表处于一个较新的状态。

ARP地址是动态转换的，临时查询得到的这种转换地址，而不是由用户和管理员进行配置。
		我们的协议栈并未处理当多台计算机使用同一IP地址时，IP地址冲突的情况。

#### 3.3.1 实现ARP类型

ARP包

```c
typedef struct _arp_pkt_t {
    // type和len字段用于使包可用于不同类型的硬件层和协议层
    // 在我们这里，固定只支持MAC和IP转换，所以写死处理
    uint16_t htype;         // 硬件类型
    uint16_t ptype;         // 协议类型
    uint8_t hlen;           // 硬件地址长
    uint8_t plen;           // 协议地址长
    uint16_t opcode;        // 请求/响应
    uint8_t send_haddr[ETH_HWA_SIZE];       // 发送包硬件地址
    uint8_t send_paddr[IPV4_ADDR_SIZE];     // 发送包协议地址
    uint8_t target_haddr[ETH_HWA_SIZE];     // 接收方硬件地址
    uint8_t target_paddr[IPV4_ADDR_SIZE];   // 接收方协议地址
}arp_pkt_t;
```

ARP缓存表项

```c
typedef struct _arp_entry_t {
    uint8_t paddr[IPV4_ADDR_SIZE];      // 协议地址，即IP地址, 大端格式的ip地址?
    uint8_t haddr[ETH_HWA_SIZE];        // 硬件地址，即mac地址

    // 状态及标志位
    enum {
        NET_ARP_FREE = 0x1234,          // 空闲
        NET_ARP_RESOLVED,               // 稳定，已解析
        NET_ARP_WAITING,                // 挂起，有请求，但未解析成功
    } state;            // 状态位

    int tmo;                // 超时，需删除或重新请求
    int retry;              // 请求重试次数，因目标主机可能暂时未能处理，或丢包
    netif_t* netif;         // 包项所对应的网络接口，可用于发包
    nlist_node_t node;       // 下一个表项链接结点
    nlist_t buf_list;        // 待发送的数据包队列
}arp_entry_t;
```

## 3.4 ip协议

IP协议全称为“网际互连协议（Internet Protocol）”，IP协议是TCP/IP体系中的网络层协议。所有的 TCP、UDP、ICMP及IGMP数据都以I P数据报格式传输。

IP协议提供尽力而为，无连接的数据交付服务 。可以理解为不随意丢弃，但也不保证数据一定到达（尽力传递，但有可能丢包）；连续数据报通过不同路径到达，后发的先到（有的包裹抄近路，或者通过更高速的路径传递）；数据包在传递过程中可能出错。

本课程主要实现IPv4协议的三大功能。 

- 第一是封装UDP/TCP/ICMPv4等协议的数据向下发送，或者反过来提取数据交给这些协议处理。

- 第二种功能，基于IP地址进行数据包的转发，可让世界上任何两台计算机之间进行通信 ，可以跨越不同的数据链路类型。从这里我们可以看到，由于IP地址与具体链接的无关性，所以只需要知道IP地址就可以将其传递至相应的计算机。当然具体在某个链路中传递时，使用的是物理地址。
- IP协议的功能之三：对大型数据包的收发进行分片和重组。当应用层需要收发较大的数据而底层数据链路允许收发的数据大小有限时，需要IP协议对数据进行分片和重组。

#### 3.4.1 定义ip结构

**ip包头部**

 * 长度可变，最少20字节，如下结构。当包含选项时，长度变大，最多60字节
 * 不过，包含选项的包比较少见，因此一般为20字节
 * 总长最大65536，实际整个pktbuf的长度可能比total_len大，因为以太网填充的缘故
 * 因此需要total_len来判断实际有效的IP数据包长

```c
typedef struct _ipv4_hdr_t {
    union {
        struct {
#if NET_ENDIAN_LITTLE
            uint16_t shdr : 4;           // 首部长，低4字节
            uint16_t version : 4;        // 版本号
            uint16_t ds : 6;
            uint16_t ecn : 2;
#else
            uint16_t ecn : 2;
            uint16_t ds : 6;
            uint16_t version : 4;        // 版本号
            uint16_t shdr : 4;           // 首部长，低4字节
#endif
        };
        uint16_t shdr_all;
    };

    uint16_t total_len;		    // 总长度、
    uint16_t id;		        // 标识符，用于区分不同的数据报,可用于ip数据报分片与重组

    union {
        struct {
#if NET_ENDIAN_LITTLE
            uint16_t offset : 13;               // 数据报分片偏移, 以8字节为单位，从0开始算
            uint16_t more : 1;                  // 不是最后一个包，还有后续
            uint16_t disable : 1;               // 1-不允许分片，0-可以分片
            uint16_t resvered : 1;              // 保留，必须为0
#else
            uint16_t resvered : 1;              // 保留，必须为0
            uint16_t offset : 13;               // 数据报分片偏移, 以8字节为单位，从0开始算
            uint16_t more : 1;                  // 不是最后一个包，还有后续
            uint16_t disable : 1;               // 1-不允许分片，0-可以分片
#endif
        };
        uint16_t frag_all;
    };

    uint8_t ttl;                // 存活时间，每台路由器转发时减1，减到0时，该包被丢弃
    uint8_t protocol;	        // 上层协议
    uint16_t hdr_checksum;      // 首部校验和
    uint8_t	src_ip[IPV4_ADDR_SIZE];        // 源IP
    uint8_t dest_ip[IPV4_ADDR_SIZE];	   // 目标IP
}ipv4_hdr_t;
```

**IP数据包**

```c
/**
 * @brief IP数据包
 */
typedef struct _ipv4_pkt_t {
    ipv4_hdr_t hdr;              // 数据包头
    uint8_t data[1];            // 数据区
}ipv4_pkt_t;

#pragma pack()
```



## 3.5 ICMP协议

涉及ICMP协议的初始化，特指ICMPv4协议。

ICMP协议 属于网络层协议，主要用于在**主机与路由器之间传递控制信息**，包括报告错误、交换受限控制和状态信息等。当遇到IP数据无法访问目标、IP路由器无法按当前的传输速率转发数据包等情况时，会自动发送ICMP消息。

其与与 IP 协议、ARP 协议、RARP 协议及 IGMP 协议共同构成 TCP/IP 模型中的网络层。ping 和 tracert是两个常用网络管理命令，**ping 用来测试网络可达性**，**tracert 用来显示到达目的主机的路径**。ping和 tracert 都利用 ICMP 协议来实现网络功能，它们是把网络协议应用到日常网络管理的典型实例。

### 3.5.1 ICMP协议数据类型

**ICMP包头**

```c
/**
 * @brief ICMP包代码
 */
typedef enum _icmp_code_t {
    ICMPv4_ECHO = 0,                        // echo的响应码
    ICMPv4_UNREACH_PRO = 2,                 // 协议不可达
    ICMPv4_UNREACH_PORT = 3,                // 端口不可达
}icmp_code_t;

#pragma pack(1)
```

**ICMP报文**

```c
/**
 * ICMP报文
 */
typedef struct _icmpv4_pkt_t {
    icmpv4_hdr_t hdr;            // 头和数据区
    union {
        uint32_t reverse;       // 保留项
    };
    uint8_t data[1];            // 可选数据区
}icmpv4_pkt_t;

#pragma pack()
```

在添加完icmpv4的初始化接口之后，需要在IP模块中，根据IP包头中的协议字段进行判断是否为ICMPv4协议，然后交由ICMPv4模块处理。

事实上，TCP/IP协议栈中的很多地方都采用了类似操作，即基于包头中的某个字段（协议/端口），将数据包提交给不同的其它协议模块或者应用程序去处理。

```c
case NET_PROTOCOL_ICMPv4: {
        net_err_t err = icmpv4_in(src, &netif->ipaddr, buf);
        if (err < 0) {
            dbg_warning(DBG_IP, "icmp in failed.\n");
            return err;
        }
        return NET_ERR_OK;
    }
```



## 3.6 UDP协议

网络层：完成相同或不同网络中计算机之间的通讯。由 IP 协议提供的是一个不可靠、无衔接的数据报传递服务。该协议完成两个基本功用：寻址和分段

传输层：整个网络的关键部分，实现两个用户进程之间可靠的端到端通信，处理包错误、包序列等关键传输问题。

UDP通过端口号决定交给哪个进程来处理。通过 IP 地址能够将数据包交给指定的计算机，通过端口号能够将数据包交给指定的进程。因此， IP 地址端口号可以定位网络上指定计算机上的指定应用程序。通信时，双方需要互知对方的 IP 地址＋端口号。

UDP协议在IP协议之上提供最小的给功能（端口和消息边界），应用程序需要处理许多与数据包收发相关的控制工作。

- 差错检测：UDP利用校验和进行检查，但没有纠错
- 无队列管理：没有队列对数据包进行管理
- 无重复消除：对重复包不处理
- 无拥塞控制：只管往外发数据
- 无连接：不管对方在不在，只管发和收connect仅用于指定对方的地址
- 开销小：基于IP只做基本的检查和封装
- 提供端口：需要知道对方的端口号
- 保留消息边界：每次发送以单个数据包为单位，最大是64kb

UDP数据包格式：

| IPv4头 | UDP头 | 应用数据 |
| ------ | ----- | -------- |

### 3.6.1 UDP数据结构

**UDP数据包头**

```c
/**
 * UDP数据包头
 */
#pragma pack(1)

typedef struct _udp_hdr_t {
    uint16_t src_port;          // 源端口
    uint16_t dest_port;		    // 目标端口
    uint16_t total_len;	        // 整个数据包的长度
    uint16_t checksum;		    // 整个数据包的校验和
}udp_hdr_t;
```

**UDP数据包**

```c
/**
 * UDP数据包
 */
typedef struct _udp_pkt_t {
    udp_hdr_t hdr;             // UDP头部
    uint8_t data[1];            // UDP数据区
}udp_pkt_t;

#pragma pack()
```



## 3.7 TCP协议

TCP传输特点

- 基于数据流传输：应用程序看到的是类似管道流，不限制 每次发送的数据大小
- 差错检测：使用伪校验和，丢包时自动重传
- 数据自动排序：每个字节数据都有响应的编号
- 重复检测处理：重复的数据将被丢弃
- 拥塞控制
- 面向连接：通信之前需要先建立连接，结束通信要关闭连接
- 较大开销：超时重传、连接管理、滑动窗口
- 提供端口：需要知道对方的端口号

### 3.7.1 TCP数据结构

TCP数据被封装在一个IP数据报中，TCP首部的数据格式。如果不计任选字段，它通常是 20个字节

- **源端口和目的端口**（16位,16位）：每个TCP段都包含源端和目的端的端口号，用于寻找发端和收端应用进程。这两个值加上IP首部中的源端IP地址和目的端IP地址唯一确定一个TCP连接。
- **序号**（32位）：序号用来标识从TCP发端向TCP收端发送的数据字节流，它表示在这个报文段中的的第一个数据字节。

如果将字节流看作在两个应用程序间的单向流动，则 TCP用序号对每个字节进行计数。序号是32 bit的无符号数，序号到达2**32－1后又从0开始。
		当建立一个新的连接时， SYN标志变1。序号字段包含由这个主机选择的该连接的初始序号ISN（Initial Sequence Number）。该主机要发送数据的第一个字节序号为这个 ISN加1，因为SYN标志消耗了一个序号（将在下章详细介绍如何建立和终止连接，届时我们将看到 FIN标志也要占用一个序号）。
		既然每个传输的字节都被计数，确认序号包含发送确认的一端所期望收到的下一个序号。因此，确认序号应当是上次已成功收到数据字节序号加 1。只有ACK标志（下面介绍）为 1时确认序号字段才有效。
发送ACK无需任何代价，因为 32 bit的确认序号字段和A C K标志一样，总是TCP首部的一部分。因此，我们看到一旦一个连接建立起来，这个字段总是被设置， ACK标志也总是被设置为1。

TCP为应用层提供全双工服务。这意味数据能在两个方向上独立地进行传输。因此，连接的每一端必须保持每个方向上的传输数据序号

- **首部长度**（4位）：首部长度给出首部中 32 bit字的数目。需要这个值是因为任选字段的长度是可变的。这个字段占4 bit，因此T C P最多有60字节的首部。然而，没有任选字段，正常的长度是 20字节
- **保留**（6位）：在TCP首部中有6个标志比特。它们中的多个可同时被设置为 1
  - URG：紧急指针（u rgent pointer）有效（见2 0 . 8节）。
  - ACK：确认序号有效。
  - PSH：接收方应该尽快将这个报文段交给应用层。
  - RST：重建连接。
  - SYN：同步序号用来发起一个连接。这个标志和下一个标志将在第 1 8章介绍。
  - FIN：发端完成发送任务。

- **窗口大小**（16位）：TCP的流量控制由连接的每一端通过声明的窗口大小来提供。窗口大小为字节数，起始于确认序号字段指明的值，这个值是接收端正期望接收的字节。窗口大小是一个 16 bit字段，因而窗口大小最大为 65535字节

- **检验和**（16位）：检验和覆盖了整个的 TCP报文段：TCP首部和TCP数据。这是一个强制性的字段，一定是
  由发端计算和存储，并由收端进行验证。 TCP检验和的计算和 UDP检验和的计算相似，使用一个伪首部。
- **紧急指针**（16位）：只有当URG标志置1时紧急指针才有效。紧急指针是一个正的偏移量，和序号字段中的值
  相加表示紧急数据最后一个字节的序号。 TCP的紧急方式是发送端向另一端发送紧急数据的一种方式

- **选项**：最常见的可选字段是最长报文大小，又称为 MSS (Maximum Segment Size)。每个连接方通常都在通信的第一个报文段（为建立连接而设置 S Y N标志的那个段）中指明这个选项。它指明本端所能接收的最大长度的报文段。

```c
/**
 * TCP数据包头结构
 */
typedef struct _tcp_hdr_t {
    uint16_t sport;             // 源端口
    uint16_t dport;             // 目的端口

    // 全双工通信
    uint32_t seq;             // 自己的序列号
    uint32_t ack;             // 发给对方响应序列号

    union {
        uint16_t flags;       
#if NET_ENDIAN_LITTLE
        struct {
            uint16_t resv : 4;          // 保留
            uint16_t shdr : 4;          // 头部长度
            uint16_t f_fin : 1;           // 已经完成了向对方发送数据，结束整个发送
            uint16_t f_syn : 1;           // 同步，用于初始一个连接的同步序列号
            uint16_t f_rst : 1;           // 重置连接
            uint16_t f_psh : 1;           // 推送：接收方应尽快将数据传递给应用程序
            uint16_t f_ack : 1;           // 确认号字段有效
            uint16_t f_urg : 1;           // 紧急指针有效
            uint16_t f_ece : 1;           // ECN回显：发送方接收到了一个更早的拥塞通告
            uint16_t f_cwr : 1;           // 拥塞窗口减，发送方降低其发送速率
        };
#else
        struct {
            uint16_t shdr : 4;          // 头部长度
            uint16_t resv : 4;          // 保留
            uint16_t f_cwr : 1;           // 拥塞窗口减，发送方降低其发送速率
            uint16_t f_ece : 1;           // ECN回显：发送方接收到了一个更早的拥塞通告
            uint16_t f_urg : 1;           // 紧急指针有效
            uint16_t f_ack : 1;           // 确认号字段有效
            uint16_t f_psh : 1;           // 推送：接收方应尽快将数据传递给应用程序
            uint16_t f_rst : 1;           // 重置连接
            uint16_t f_syn : 1;           // 同步，用于初始一个连接的同步序列号
            uint16_t f_fin : 1;           // 已经完成了向对方发送数据，结束整个发送
        };
#endif
    };
    uint16_t win;                       // 窗口大小，实现流量控制, 窗口缩放选项可以提供更大值的支持
    uint16_t checksum;                  // 校验和
    uint16_t urgptr;                    // 紧急指针
}tcp_hdr_t;
```

**TCP选项**

```c
/**
 * @brief TCP选项
 */
typedef struct _tcp_opt_mss_t {
    uint8_t kind;
    uint8_t length;
    union {
        uint16_t mss;
    };
}tcp_opt_mss_t;
```

**SACK选项**

```c
/**
 * @brief SACK选项
 */
typedef struct _tcp_opt_sack_t {
    uint8_t kind;
    uint8_t length;
}tcp_opt_sack_t;
```

**TCP报文段结构**

```c
/**
 * @brief TCP报文段结构
 */
typedef struct _tcp_seg_t {
    ipaddr_t local_ip;               // 本地IP
    ipaddr_t remote_ip;              // 远端IP
    tcp_hdr_t * hdr;                // TCP包
    pktbuf_t * buf;                 // Buffer包
    uint32_t data_len;              // 数据长度
    uint32_t seq;                   // 起始序号
    uint32_t seq_len;               // 序列号空间长度
}tcp_seg_t;
```

**TCP数据包**

```c
/**
 * TCP数据包
 */
typedef struct _tcp_pkt_t {
    tcp_hdr_t hdr;
    uint8_t data[1];
}tcp_pkt_t;

#pragma pack()
```


