#include "os/os.h"
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#if defined(_WIN32)
#   include <windows.h>
#else
#   include <unistd.h>
#   include <sys/mman.h>
#endif

/**
 * @brief Set memory protect mode as READ/WRITE/EXEC
 */
static int _system_protect_as_RWE(void* addr, size_t size)
{
    int flag_failure = 0;
#if defined(_WIN32)
    DWORD lpflOldProtect;
    flag_failure = 0 == VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
#elif defined(__linux__)
    flag_failure = -1 == mprotect(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC);
#else
    flag_failure = 1;
#endif
    return flag_failure ? -1 : 0;
}

/**
 * @brief Set memory protect mode as READ/EXEC
 */
static int _system_protect_as_RE(void* addr, size_t size)
{
    int flag_failure = 0;
#if defined(_WIN32)
    DWORD lpflOldProtect;
    flag_failure = 0 == VirtualProtect(addr, size, PAGE_EXECUTE_READ, &lpflOldProtect);
#elif defined(__linux__)
    flag_failure = -1 == mprotect(addr, size, PROT_READ | PROT_EXEC);
#else
    flag_failure = 1;
#endif
    return flag_failure ? -1 : 0;
}

void* _alloc_execute_memory(size_t size)
{
#if defined(_WIN32)
    return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#else
    void* ptr = NULL;
    if (posix_memalign(&ptr, _get_page_size(), size) != 0)
    {
        return NULL;
    }
    if (_system_protect_as_RWE(ptr, size) < 0)
    {
        free(ptr);
        return NULL;
    }

    return ptr;
#endif
}

size_t _get_page_size(void)
{
#if defined(_WIN32)
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    unsigned long page_size = sys_info.dwPageSize;
#elif defined(__linux__)
    long page_size = sysconf(_SC_PAGE_SIZE);
#else
    long page_size = 0;
#endif

    return page_size <= 0 ? 4096 : page_size;
}

int _system_modify_opcode(void* addr, size_t size, void (*callback)(void*), void* data)
{
    const size_t page_size = _get_page_size();

    uint8_t* start_addr = (uint8_t*)_page_of(addr, page_size);
    uint8_t* end_addr = (uint8_t*)addr + size;

    const size_t n_page = ((end_addr - start_addr - 1) / page_size) + 1;
    const size_t protect_size = page_size * n_page;

    /* Remove write protect */
    if (_system_protect_as_RWE(start_addr, protect_size) < 0)
    {
        return -1;
    }

    /* call callback */
    callback(data);

    /* Add write protect */
    int ret = _system_protect_as_RE(start_addr, protect_size);
    assert(ret == 0); (void)ret;

    return 0;
}

void _flush_instruction_cache(void* addr, size_t size)
{
#if defined(_WIN32)
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (process_handle == NULL)
    {
        return;
    }

    FlushInstructionCache(process_handle, addr, size);
    CloseHandle(process_handle);
#elif defined(__GNUC__) || defined(__clang__)
    __builtin___clear_cache(addr, (uint8_t*)addr + size);
#else
#   error "unsupport flush_instruction_cache"
#endif
}

void _free_execute_memory(void* ptr)
{
#if defined(_WIN32)
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    free(ptr);
#endif
}

void* _page_of(void* addr, size_t page_size)
{
    return (char*)((uintptr_t)addr & ~(page_size - 1));
}
