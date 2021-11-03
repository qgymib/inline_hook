include(LibFindMacros)

find_path(LIBZYDIS_INCLUDE_DIR NAMES Zydis.h)
find_library(LIBZYDIS_LIBRARY NAMES Zydis libZydis)

set(Zydis_PROCESS_INCLUDES LIBZYDIS_INCLUDE_DIR)
if(LIBZYDIS_LIBRARY)
  set(Zydis_PROCESS_LIBS LIBZYDIS_LIBRARY)
endif()

libfind_process(Zydis)