cmake_minimum_required(VERSION 3.20)
project(kerneltrace C)

# ── Options ───────────────────────────────────────────────────────────────────
option(KERNELTRACE_BUILD_PROBES  "Compile eBPF probe objects with clang"  ON)
option(KERNELTRACE_INSTALL_PROBES "Install compiled .bpf.o files"          ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Find libbpf ───────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

# ── Native shim shared library ────────────────────────────────────────────────
add_library(kerneltrace SHARED
    libkerneltrace/kerneltrace.c
)

target_include_directories(kerneltrace
    PUBLIC  libkerneltrace
    PRIVATE ${LIBBPF_INCLUDE_DIRS}
)

target_link_libraries(kerneltrace
    PRIVATE ${LIBBPF_LIBRARIES}
    PRIVATE elf z
)

target_compile_options(kerneltrace PRIVATE
    -Wall -Wextra -Wpedantic
    -fvisibility=hidden          # only explicitly exported symbols visible
    -O2
)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS kerneltrace
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES libkerneltrace/kerneltrace.h
    DESTINATION include/kerneltrace
)

# ── eBPF probe compilation ────────────────────────────────────────────────────
if(KERNELTRACE_BUILD_PROBES)
    find_program(CLANG clang REQUIRED)

    # ── vmlinux.h — must be provided externally (CI: vmlinux-h artifact; ─────
    # ── local: run native/scripts/gen-vmlinux.sh) ────────────────────────────
    set(VMLINUX_H "${CMAKE_CURRENT_SOURCE_DIR}/probes/vmlinux.h")
    if(NOT EXISTS "${VMLINUX_H}")
        message(FATAL_ERROR
            "vmlinux.h not found at ${VMLINUX_H}.\n"
            "Run native/scripts/gen-vmlinux.sh to generate it from the running kernel.")
    endif()

    set(BPF_ARCH "bpf")

    # ── Determine host arch for BPF target-arch define and multiarch path ─────
    # Maps CMAKE_SYSTEM_PROCESSOR → BPF __TARGET_ARCH_<x> define suffix.
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(BPF_TARGET_ARCH "arm64")
        set(MULTIARCH_TUPLE "aarch64-linux-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "armv7|arm")
        set(BPF_TARGET_ARCH "arm")
        set(MULTIARCH_TUPLE "arm-linux-gnueabihf")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
        set(BPF_TARGET_ARCH "riscv")
        set(MULTIARCH_TUPLE "riscv64-linux-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "s390x")
        set(BPF_TARGET_ARCH "s390")
        set(MULTIARCH_TUPLE "s390x-linux-gnu")
    else()
        # Default: x86_64
        set(BPF_TARGET_ARCH "x86")
        set(MULTIARCH_TUPLE "x86_64-linux-gnu")
    endif()

    # On musl-based systems (Alpine, etc.) there is no multiarch subdirectory;
    # /usr/include already contains the arch-specific headers directly.
    set(MULTIARCH_INCLUDE "/usr/include/${MULTIARCH_TUPLE}")
    if(NOT IS_DIRECTORY "${MULTIARCH_INCLUDE}")
        set(MULTIARCH_INCLUDE "/usr/include")
    endif()

    set(BPF_CFLAGS
        -O2
        -g
        -target bpf
        -D__TARGET_ARCH_${BPF_TARGET_ARCH}
        -I${CMAKE_SOURCE_DIR}/probes
        -I/usr/include/bpf
        -I${MULTIARCH_INCLUDE}
    )

    set(PROBE_SOURCES
        probes/network_monitor.bpf.c
        probes/scheduler_profiler.bpf.c
        probes/security_guard.bpf.c
        probes/fs_io.bpf.c
        probes/memory_profiler.bpf.c
        probes/block_io.bpf.c
        probes/dotnet_runtime.bpf.c
        probes/container_monitor.bpf.c
        probes/kernel_internals.bpf.c
        probes/stack_sampler.bpf.c
        probes/usdt_python.bpf.c
    )

    set(PROBE_OBJECTS)
    foreach(SRC ${PROBE_SOURCES})
        get_filename_component(NAME ${SRC} NAME_WE)
        set(OBJ ${CMAKE_CURRENT_BINARY_DIR}/${NAME}.bpf.o)

        add_custom_command(
            OUTPUT  ${OBJ}
            COMMAND ${CLANG} ${BPF_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/${SRC} -o ${OBJ}
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${SRC}
                    ${CMAKE_CURRENT_SOURCE_DIR}/probes/common.h
                    "${VMLINUX_H}"
            COMMENT "Compiling eBPF probe: ${NAME}"
        )
        list(APPEND PROBE_OBJECTS ${OBJ})
    endforeach()

    add_custom_target(ebpf_probes ALL DEPENDS ${PROBE_OBJECTS})

    if(KERNELTRACE_INSTALL_PROBES)
        install(FILES ${PROBE_OBJECTS} DESTINATION share/kerneltrace/probes)
    endif()
endif()
