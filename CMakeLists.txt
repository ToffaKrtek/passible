cmake_minimum_required(VERSION 3.19)
project(passible C)

set(CMAKE_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -g -O2")

find_package(PkgConfig REQUIRED)
pkg_check_modules(libbpf REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(libyaml REQUIRED IMPORTED_TARGET yaml-0.1)

set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/passible.bpf.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/passible.bpf.o)

add_custom_command(
  OUTPUT ${BPF_OBJ}
  COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf -c ${BPF_SRC} -o ${BPF_OBJ}
  DEPENDS ${BPF_SRC}
  COMMENT "Compiling eBPF object"
)

add_executable(passible
  src/main.c
  src/config.c
  src/bpf_loader.c
  src/event_handler.c
  src/logging.c
)

target_include_directories(passible PRIVATE src)
target_link_libraries(passible PkgConfig::libbpf PkgConfig::libyaml)

#install(TARGETS passible DESTINATION bin)
#install(FILES etc/passible/conf.yml DESTINATION etc/passible)
