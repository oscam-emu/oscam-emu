#ifndef OSCAM_GARBAGE_H_
#define OSCAM_GARBAGE_H_

#ifdef WITH_DEBUG
extern void add_garbage_debug(void *data, char *file, uint16_t line);
#define add_garbage(x) add_garbage_debug(x, __FILE__, __LINE__)
#else
extern void add_garbage(void *data);
#endif
extern void start_garbage_collector(int32_t);
extern void stop_garbage_collector(void);

#endif
