#ifndef LOG_H
#define LOG_H

void CleanLog (NSString *format, ...);

#ifdef SYSCALLTRACE
#define STRACE(fmt, ...) CleanLog(fmt, ##__VA_ARGS__)
#else
#define STRACE(...)
#endif

#ifdef DEBUG
//#define FFLog(fmt, ...) NSLog((@"%s\n -- %s [Line %d] " fmt), __FILE__, __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FFLog(fmt, ...) NSLog((@"%s [Line %d] " fmt), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)
// #define CLog(fmt, ...) CleanLog((@"%s:%d " fmt), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)
#define CLog(fmt, ...) CleanLog(fmt, ##__VA_ARGS__)
#define CPULog(fmt, ...) CleanLog((@"P: %d - " fmt), self.task.pid.id, ##__VA_ARGS__)
#else
// Dont log anything
#define FFLog(...)
#define CLog(...)
#endif

#endif

