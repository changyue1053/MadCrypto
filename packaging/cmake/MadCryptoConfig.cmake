# Development host package only. No mobile platform support is implied.
if(CMAKE_CROSSCOMPILING OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8 OR
   NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
   NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  set(MadCrypto_FOUND FALSE)
  set(MadCrypto_NOT_FOUND_MESSAGE "This package contains Linux x86_64 host artifacts only")
  return()
endif()
include(CMakeFindDependencyMacro)
find_dependency(Threads)
get_filename_component(_madcrypto_prefix "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
if(TARGET MadCrypto::MadCrypto)
  get_target_property(_madcrypto_existing MadCrypto::MadCrypto IMPORTED_LOCATION)
  if(NOT _madcrypto_existing STREQUAL "${_madcrypto_prefix}/lib/libmadcrypto_ffi.a")
    set(MadCrypto_FOUND FALSE)
    set(MadCrypto_NOT_FOUND_MESSAGE "A different MadCrypto target is already loaded")
  endif()
  unset(_madcrypto_existing)
else()
  add_library(MadCrypto::MadCrypto STATIC IMPORTED)
  set_target_properties(MadCrypto::MadCrypto PROPERTIES
    IMPORTED_LOCATION "${_madcrypto_prefix}/lib/libmadcrypto_ffi.a"
    INTERFACE_INCLUDE_DIRECTORIES "${_madcrypto_prefix}/include"
    INTERFACE_LINK_LIBRARIES "Threads::Threads;${CMAKE_DL_LIBS};m")
endif()
unset(_madcrypto_prefix)
