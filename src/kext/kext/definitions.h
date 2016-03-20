
#ifndef definitions_h
#define definitions_h


#define ALLOW   0
#define DENY    1

#include <sys/queue.h>

#if DEBUG
#define LOG_DEBUG(fmt, ...) printf("[SHELLGUARD DEBUG] " fmt "\n", ## __VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do {} while (0)
#endif

#define LOG_MSG(...) printf(__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[SHELLGUARD ERROR] " fmt "\n", ## __VA_ARGS__)
#define LOG_INFO(fmt, ...) printf("[SHELLGUARD INFO] " fmt "\n", ## __VA_ARGS__)

#endif /* definitions_h */
