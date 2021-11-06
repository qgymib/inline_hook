#include "once.h"

#if defined(_WIN32)

static BOOL WINAPI _ev_once_proxy(PINIT_ONCE InitOnce, PVOID Parameter, PVOID* Context)
{
	(void)InitOnce; (void)Context;

	void (*init_routine)(void) = Parameter;
	init_routine();

	return TRUE;
}

API_LOCAL
int pthread_once(pthread_once_t* once_control, void (*init_routine)(void))
{
	return InitOnceExecuteOnce(&once_control->guard, _ev_once_proxy, (PVOID)init_routine, NULL);
}

#endif