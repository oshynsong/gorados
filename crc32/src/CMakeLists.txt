cmake_minimum_required(VERSION 2.8.12)

project(crc32lib)

set(libcrc32_files
  crc32c.cc
  sctp_crc32.c
  crc32c_intel_baseline.c
  reverse.c
  probe.cc
)

include(CheckCCompilerFlag)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}")
include(SIMDExt)

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
  message(STATUS "The compiler ${CMAKE_CXX_COMPILER} does not support C++11.")
endif()

if(HAVE_INTEL)
  list(APPEND libcrc32_files
    crc32c_intel_fast.c)
  if(HAVE_GOOD_YASM_ELF64)
    list(APPEND libcrc32_files
      crc32c_intel_fast_asm.s
      crc32c_intel_fast_zero_asm.s)
  endif(HAVE_GOOD_YASM_ELF64)
elseif(HAVE_POWER8)
  list(APPEND libcrc32_files
    crc32c_ppc.c)
  if(HAVE_PPC64LE)
    list(APPEND libcrc32_files
      crc32c_ppc_asm.S
      crc32c_ppc_fast_zero_asm.S)
  endif(HAVE_PPC64LE)
elseif(HAVE_ARMV8_CRC)
  list(APPEND libcrc32_files
    crc32c_aarch64.c)
endif(HAVE_INTEL)

if(HAVE_ARM)
  list(APPEND libcrc32_files arm.c)
elseif(HAVE_INTEL)
  list(APPEND libcrc32_files intel.c)
elseif(HAVE_POWER8)
  list(APPEND libcrc32_files ppc.c)
endif()

add_library(crc32 STATIC ${libcrc32_files})
