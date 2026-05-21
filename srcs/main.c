#include "woody_woodpacker.h"
#include "utils.h"

int isElf64_fd(int fd)
{
	unsigned char ident[EI_NIDENT];

	if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
		return 0;
	if (read(fd, ident, EI_NIDENT) != EI_NIDENT)
		return 0;
	/* ELF magic + class 2 = 64-bit */
	return (ident[EI_MAG0] == ELFMAG0 &&
			ident[EI_MAG1] == ELFMAG1 &&
			ident[EI_MAG2] == ELFMAG2 &&
			ident[EI_MAG3] == ELFMAG3 &&
			ident[EI_CLASS] == ELFCLASS64);
}

void free_elf64_headers(t_elf64_headers *hdrs)
{
	if (!hdrs)
		return;
	if (hdrs->phdr)
		free(hdrs->phdr);
	if (hdrs->shdr)
	{
		for (size_t i = 0; i < hdrs->ehdr.e_shnum; i++)
			free(hdrs->shdr[i].name_str_format);
		free(hdrs->shdr);
	}
	free(hdrs);
}

int load_section_names(int fd, t_elf64_headers *hdrs)
{
	const Elf64_Shdr *shstr_hdr;
	char *shstrtab;

	if (!hdrs || !hdrs->shdr || hdrs->ehdr.e_shstrndx >= hdrs->ehdr.e_shnum)
		return 0;
	shstr_hdr = &hdrs->shdr[hdrs->ehdr.e_shstrndx].shdr;
	shstrtab = calloc(1, shstr_hdr->sh_size + 1);
	if (!shstrtab)
		return 0;
	if (lseek(fd, (off_t)shstr_hdr->sh_offset, SEEK_SET) == (off_t)-1)
	{
		free(shstrtab);
		return 0;
	}
	if (read(fd, shstrtab, shstr_hdr->sh_size) != (ssize_t)shstr_hdr->sh_size)
	{
		free(shstrtab);
		return 0;
	}
	for (size_t i = 0; i < hdrs->ehdr.e_shnum; i++)
	{
		if (hdrs->shdr[i].shdr.sh_name < shstr_hdr->sh_size)
			hdrs->shdr[i].name_str_format = strdup(shstrtab + hdrs->shdr[i].shdr.sh_name);
		else
			hdrs->shdr[i].name_str_format = strdup("");
		if (!hdrs->shdr[i].name_str_format)
		{
			free(shstrtab);
			return 0;
		}
	}
	free(shstrtab);
	return 1;
}

t_elf64_headers *load_elf64_headers(int fd)
{
	t_elf64_headers *hdrs = NULL;
	Elf64_Ehdr ehdr;
	ssize_t r;
	off_t off;

	if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
		return NULL;
	r = read(fd, &ehdr, sizeof(ehdr));
	if (r != (ssize_t)sizeof(ehdr))
		return NULL;

	hdrs = calloc(1, sizeof(*hdrs));
	if (!hdrs)
		return NULL;
	hdrs->ehdr = ehdr;

	if (ehdr.e_phnum > 0)
	{
		hdrs->phdr = calloc(ehdr.e_phnum, sizeof(Elf64_Phdr));
		if (!hdrs->phdr)
		{
			free_elf64_headers(hdrs);
			return NULL;
		}
		for (size_t i = 0; i < ehdr.e_phnum; i++)
		{
			off = (off_t)ehdr.e_phoff + (off_t)(i * ehdr.e_phentsize);
			if (lseek(fd, off, SEEK_SET) == (off_t)-1)
			{
				free_elf64_headers(hdrs);
				return NULL;
			}
			if (read(fd, &hdrs->phdr[i], sizeof(Elf64_Phdr)) != (ssize_t)sizeof(Elf64_Phdr))
			{
				free_elf64_headers(hdrs);
				return NULL;
			}
		}
	}

	if (ehdr.e_shnum > 0)
	{
		hdrs->shdr = calloc(ehdr.e_shnum, sizeof(t_elf64_section_headers));
		if (!hdrs->shdr)
		{
			free_elf64_headers(hdrs);
			return NULL;
		}
		for (size_t i = 0; i < ehdr.e_shnum; i++)
		{
			off = (off_t)ehdr.e_shoff + (off_t)(i * ehdr.e_shentsize);
			if (lseek(fd, off, SEEK_SET) == (off_t)-1)
			{
				free_elf64_headers(hdrs);
				return NULL;
			}
			if (read(fd, &hdrs->shdr[i], sizeof(Elf64_Shdr)) != (ssize_t)sizeof(Elf64_Shdr))
			{
				free_elf64_headers(hdrs);
				return NULL;
			}
		}
		if (!load_section_names(fd, hdrs))
		{
			free_elf64_headers(hdrs);
			return NULL;
		}
	}

	return hdrs;
}

void print_e_ident(const unsigned char ident[EI_NIDENT])
{
	printf("  e_ident: ");
	for (int i = 0; i < EI_NIDENT; ++i)
		printf("%02x ", ident[i]);
	printf("\n");
}

void print_elf64_headers(const t_elf64_headers *h)
{
	if (!h)
		return;
	const Elf64_Ehdr *e = &h->ehdr;
	print_e_ident(e->e_ident);
	printf("ELF Header:\n");
	printf("  e_type:      0x%x\n", e->e_type);
	printf("  e_machine:   0x%x\n", e->e_machine);
	printf("  e_version:   0x%x\n", e->e_version);
	printf("  e_entry:     0x%lx\n", (unsigned long)e->e_entry);
	printf("  e_phoff:     %lu\n", (unsigned long)e->e_phoff);
	printf("  e_shoff:     %lu\n", (unsigned long)e->e_shoff);
	printf("  e_flags:     0x%x\n", e->e_flags);
	printf("  e_ehsize:    %u\n", e->e_ehsize);
	printf("  e_phentsize: %u\n", e->e_phentsize);
	printf("  e_phnum:     %u\n", e->e_phnum);
	printf("  e_shentsize: %u\n", e->e_shentsize);
	printf("  e_shnum:     %u\n", e->e_shnum);
	printf("  e_shstrndx:  %u\n", e->e_shstrndx);

	if (h->phdr && e->e_phnum)
	{
		printf("\nProgram Headers (%u):\n", e->e_phnum);
		for (size_t i = 0; i < e->e_phnum; ++i)
		{
			const Elf64_Phdr *p = &h->phdr[i];
			printf(" PHDR %zu:\n", i);
			printf("  p_type:   0x%x\n", p->p_type);
			printf("  p_flags:  0x%x\n", p->p_flags);
			printf("  p_offset: %lu\n", (unsigned long)p->p_offset);
			printf("  p_vaddr:  0x%lx\n", (unsigned long)p->p_vaddr);
			printf("  p_paddr:  0x%lx\n", (unsigned long)p->p_paddr);
			printf("  p_filesz: %lu\n", (unsigned long)p->p_filesz);
			printf("  p_memsz:  %lu\n", (unsigned long)p->p_memsz);
			printf("  p_align:  %lu\n", (unsigned long)p->p_align);
		}
	}

	if (h->shdr && e->e_shnum)
	{
		printf("\nSection Headers (%u):\n", e->e_shnum);
		for (size_t i = 0; i < e->e_shnum; ++i)
		{
			const Elf64_Shdr *s = &h->shdr[i].shdr;
			printf(" SHDR %zu:\n", i);
			printf("  sh_name:      %u/%s\n", s->sh_name, h->shdr[i].name_str_format);
			printf("  sh_type:      0x%x\n", s->sh_type);
			printf("  sh_flags:     0x%lx\n", (unsigned long)s->sh_flags);
			printf("  sh_addr:      0x%lx\n", (unsigned long)s->sh_addr);
			printf("  sh_offset:    %lu\n", (unsigned long)s->sh_offset);
			printf("  sh_size:      %lu\n", (unsigned long)s->sh_size);
			printf("  sh_link:      %u\n", s->sh_link);
			printf("  sh_info:      %u\n", s->sh_info);
			printf("  sh_addralign: %lu\n", (unsigned long)s->sh_addralign);
			printf("  sh_entsize:   %lu\n", (unsigned long)s->sh_entsize);
		}
	}
}

int main(int argc, char **argv)
{
	const char *path = (argc > 1) ? argv[1] : "test/hello";
	int fd = open(path, O_RDONLY);
	if (fd < 0)
	{
		perror("open");
		return 1;
	}

	if (!isElf64_fd(fd))
	{
		fprintf(stderr, "not an ELF64 file: %s\n", path);
		close(fd);
		return 1;
	}

	t_elf64_headers *hdrs = load_elf64_headers(fd);
	if (!hdrs)
	{
		fprintf(stderr, "failed to load ELF headers\n");
		close(fd);
		return 1;
	}

	print_elf64_headers(hdrs);

	free_elf64_headers(hdrs);
	close(fd);
	return 0;
}
