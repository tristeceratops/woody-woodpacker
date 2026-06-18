#ifndef WOODY_WOODPACKER_H
#define WOODY_WOODPACKER_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <elf.h>

typedef struct s_elf64_section_headers
{
    Elf64_Shdr shdr;
    char *name_str_format;
} t_elf64_section_headers;

// custom structures to store all informations of ELF header, program headers and section headers
typedef struct s_elf64_headers
{
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr;
    t_elf64_section_headers *shdr;
} t_elf64_headers;

typedef struct s_stub_build_data
{
    int phdr_target_index;
    uint64_t vaddr;
} t_stub_build_data;

#endif