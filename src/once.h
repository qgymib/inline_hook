#ifndef __INLINE_HOOK_ONCE_H__
#define __INLINE_HOOK_ONCE_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "defs.h"

#if defined(_WIN32)
#	include <windows.h>

typedef struct pthread_once_s
{
	INIT_ONCE   guard;
}pthread_once_t;

#define PTHREAD_ONCE_INIT   { INIT_ONCE_STATIC_INIT }

API_LOCAL int pthread_once(pthread_once_t* once_control, void (*init_routine)(void));

#else
#	include <pthread.h>
#endif

#ifdef __cplusplus
}
#endif
#endif
