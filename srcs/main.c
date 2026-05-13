#include "woody_woodpacker.h"
#include "utils.h"
#include <stdint.h>
#include <elf.h>

//e_entry is always at bytes 0x18=24 and it's 8 bytes longs (4 in ELF 32)
Elf64_Ehdr readElfHeader(int fd)
{
	Elf64_Ehdr ehdr;

    read(fd, &ehdr, sizeof(ehdr));

    return ehdr;
}

Elf64_Phdr readProgramdHeader(int fd, const Elf64_Ehdr *ehdr, size_t index)
{
    Elf64_Phdr phdr = {0};
    off_t off = (off_t)ehdr->e_phoff + (off_t)(index * ehdr->e_phentsize);

    if (lseek(fd, off, SEEK_SET) == (off_t)-1) {
        perror("lseek program header");
        return phdr;
    }
    if (read(fd, &phdr, sizeof(phdr)) != (ssize_t)sizeof(phdr)) {
        perror("read program header");
    }
    return phdr;
}

int isElf64(int fd){
	char fileHeader[5];
	char elf64MagicBytes[6] = "\x7f\x45\x4c\x46\x02\x00";

	
	read(fd, fileHeader, 5);
	
	if (strncmp(fileHeader, elf64MagicBytes, 5) == 0)
		return 1;
	else
		return 0;
}

int main(void)
{
	int fd;
	off_t old_size;
	off_t new_size;

	char payload[] = "WOODY";

	fd = open("test/hello", O_RDWR);
	if (fd < 0){
		perror("open");
		return 1;
	}

	if (!isElf64(fd)){
		perror("not elf 64");
		return 1;
	}
    lseek(fd, 0, SEEK_SET);
	Elf64_Ehdr ehdr = readElfHeader(fd);
    Elf64_Phdr phdr = readProgramdHeader(fd, &ehdr, 0);

	printf("raw entry struct = 0x%lx\n", ehdr.e_entry);
    printf("phdr[0].p_type = %u\n", phdr.p_type);

	old_size = lseek(fd, 0, SEEK_END);
	printf("Old size: %ld\n", old_size);
	new_size = old_size + sizeof(payload);

	lseek(fd, new_size - 1, SEEK_SET);
	write(fd, "\0", 1);

	char *mapped = mmap(
		NULL,
		new_size,
		PROT_READ | PROT_WRITE,
		MAP_SHARED,
		fd,
		0);
	
	if (mapped == MAP_FAILED){
		perror("mmap");
		return 1;
	}

	for (size_t i = 0; i < sizeof(payload); i++)
		mapped[old_size + i] = payload[i];
	
	munmap(mapped, new_size);
	close(fd);

	printf("Payload appended.\n");

	return 0;
}
