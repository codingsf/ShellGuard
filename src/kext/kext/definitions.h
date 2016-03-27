
#ifndef definitions_h
#define definitions_h

#include <sys/queue.h>

#define ALLOW   0
#define DENY    1

#define UNSIGNED        0
#define SIGNED          1
#define DMG_LOADED      2
#define PREV_APPROVED   3
#define DEFER           4

#define QATTR_SIZE 0x1001
#define QFLAGS_STRING_ID "com.apple.quarantine"

#if DEBUG
#define LOG_DEBUG(fmt, ...) printf("[SHELLGUARD DEBUG] " fmt "\n", ## __VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do {} while (0)
#endif

#define LOG_MSG(...) printf(__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[SHELLGUARD ERROR] " fmt "\n", ## __VA_ARGS__)
#define LOG_INFO(fmt, ...) printf("[SHELLGUARD INFO] " fmt "\n", ## __VA_ARGS__)

#endif /* definitions_h */
