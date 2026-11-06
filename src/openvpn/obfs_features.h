/* Build systems define installed transports; absent modules default to off. */
#ifndef OBFS_FEATURES_H
#define OBFS_FEATURES_H
#ifndef OBFS_ENABLE_UDP
#define OBFS_ENABLE_UDP 0
#endif
#ifndef OBFS_ENABLE_TCP
#define OBFS_ENABLE_TCP 0
#endif
#ifndef OBFS_ENABLE_WSS
#define OBFS_ENABLE_WSS 0
#endif
#endif
