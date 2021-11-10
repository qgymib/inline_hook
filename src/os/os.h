#ifndef __UHOOK_OS_H__
#define __UHOOK_OS_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "defs.h"
#include <stddef.h>

/**
 * @brief Alloc a block of memory that has EXEC attribute
 * @param[in] size  Memory size
 * @return          Address
 */
API_LOCAL void* _alloc_execute_memory(size_t size);

/**
 * @brief Release memory alloc by #_alloc_execute_memory()
 */
API_LOCAL void _free_execute_memory(void* ptr);

API_LOCAL size_t _get_page_size(void);

API_LOCAL int _system_modify_opcode(void* addr, size_t size, void (*callback)(void*), void* data);

/**
 * @brief Flush the processor's instruction cache for the region of memory.
 *
 * Some targets require that the instruction cache be flushed, after modifying
 * memory containing code, in order to obtain deterministic behavior.
 *
 * @param[in] addr      Start address
 * @param[in] size      Address length
 */
API_LOCAL void _flush_instruction_cache(void* addr, size_t size);

/**
 * @brief Get start address of page from given address.
 * @parm[in] addr           Address to calculate
 * @param[in] page_size     Page size
 * @return                  The start address of page
 */
API_LOCAL void* _page_of(void* addr, size_t page_size);

#ifdef __cplusplus
}
#endif
#endif
