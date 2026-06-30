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

off_t get_file_size(int fd)
{
	off_t current_pos;
	off_t size;

	current_pos = lseek(fd, 0, SEEK_CUR);
	if (current_pos == (off_t)-1)
		return (-1);
	size = lseek(fd, 0, SEEK_END);
	if (size == (off_t)-1)
		return (-1);
	if (lseek(fd, current_pos, SEEK_SET) == (off_t)-1)
		return (-1);
	return (size);
}

uint64_t get_entry_point(t_elf64_headers *hdrs)
{
	return hdrs->ehdr.e_entry;
}
// Gather data needed to build the stub: index of a reusable program header
// (or -1 if none available) and the maximum virtual address occupied by
// existing PT_LOAD segments. Uses `t_stub_build_data` from the header.
// more information on p_type value: https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html
t_stub_build_data get_stub_build_data(t_elf64_headers *hdrs)
{
	t_stub_build_data out;
	out.phdr_target_index = -1;
	out.vaddr = 0;

	if (!hdrs || !hdrs->phdr)
		return out;

	for (size_t i = 0; i < hdrs->ehdr.e_phnum; ++i)
	{
		if (hdrs->phdr[i].p_type == PT_LOAD)
		{
			uint64_t ph_end = hdrs->phdr[i].p_vaddr + hdrs->phdr[i].p_memsz;
			if (ph_end > out.vaddr)
				out.vaddr = ph_end;
		}
		else if (out.phdr_target_index == -1 &&
				 (hdrs->phdr[i].p_type == PT_NULL ||
				  hdrs->phdr[i].p_type == PT_GNU_STACK ||
				  hdrs->phdr[i].p_type == PT_GNU_RELRO))
		{
			out.phdr_target_index = (int)i;
		}
	}

	return out;
}

ssize_t my_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	return syscall(SYS_pwrite64, fd, buf, count, offset);
}

ssize_t my_pwritev2(int fd, const void *buf, size_t count, off_t offset)
{
	off_t pos = lseek(fd, 0, SEEK_CUR);
	lseek(fd, offset, SEEK_SET);
	ssize_t value = write(fd, buf, count);
	lseek(fd, pos, SEEK_SET);
	return value;
}

// TODO: rewrite it
int append_stub_and_set_entry(int fd, const char *signature, t_elf64_headers *hdrs)
{
	// steps for non-pie binary:
	// 1) stored original entry point
	// 2) find free program header slot(why? Because the ELF needs a program header entry to describe the new appended segment.) and the last loadable segment(why? Because the new stub must be placed after all existing mapped code and data, so it does not overwrite anything. The end of the last PT_LOAD segment gives the highest occupied virtual address, which is the reference point for placing the new payload safely.)
	// 3) compute new offset and new virtual address both aligned to 0x1000(why? Because ELF segments are normally page-aligned, and the kernel maps memory in pages. If the file offset and virtual address are not aligned the way the loader expects, the new segment may fail to load correctly or may be mapped at the wrong address.)
	// 4) patches the stub with address of signature and original entrypoint
	// 5) write padding, then stub, then signatures
	// 6) create new PT_LOAD segment covering the target region
	// 7) change e_entry to new stub

	size_t siglen;
	uint32_t siglen32; // need for patch
	uint64_t orig_entry;
	off_t file_length;
	t_stub_build_data stub_build_data;
	size_t pad;
	uint64_t new_offset;
	uint64_t new_vaddr;
	uint64_t sig_vaddr;
	unsigned char zeros[0x1000] = {0};

	unsigned char stub[41] = {
		0x52,						  // push rdx -> save the orignal rdx because we will overwrite it and we want to restore it
		0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 -> syscall number for write
		0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1 -> file descriptor stdout
		0x48, 0xbe,					  // movabs rsi, imm64 -> load rsi with the address of signature string (patched after), rsi is buffer for write
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xba, 0x00, 0x00, 0x00, 0x00, // mov edx, imm32 -> load edx with the signature length (patched at runtime)
		0x0f, 0x05,					  // syscall -> write(1, rsi, rdx)
		0x5a,						  // pop rdx
		0x48, 0xb8,					  // movabs rax, imm64 -> load rax with original entry point (patched at runtime)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xe0}; // jmp rax -> jump to original entry point

	if (fd < 0 || !signature || !hdrs || !hdrs->phdr || hdrs->ehdr.e_phnum == 0) // safety check
		return 0;

	siglen = strlen(signature);

	if (siglen <= 0)
	{
		printf("Siglen <= 0");
		return 0;
	}

	stub_build_data = get_stub_build_data(hdrs);

	if (stub_build_data.phdr_target_index == -1 || stub_build_data.vaddr == 0)
	{
		printf("index = %d / no header available\n", stub_build_data.phdr_target_index);
		return 0;
	}

	// prepare patch for stub
	orig_entry = hdrs->ehdr.e_entry;
	siglen32 = (uint32_t)siglen;
	file_length = get_file_size(fd);
	new_vaddr = (stub_build_data.vaddr + 0x0fff) & ~(uint64_t)0x0fff;
	sig_vaddr = new_vaddr + sizeof(stub);

	// patch values in stub
	memcpy(&stub[13], &sig_vaddr, sizeof(sig_vaddr));
	memcpy(&stub[22], &siglen32, sizeof(siglen32));
	memcpy(&stub[31], &orig_entry, sizeof(orig_entry));

	// need to adjust alignment
	pad = (0x1000 - ((size_t)file_length & 0x0fff)) & 0x0fff; // 0x1000 = 4096; 0x0fff = 4095
	new_offset = (uint64_t)file_length + pad;

	if (pad > 0 && my_pwrite(fd, zeros, pad, file_length) != (ssize_t)pad)
		return 0;
	if (my_pwrite(fd, stub, sizeof(stub), (off_t)new_offset) != (ssize_t)sizeof(stub))
		return 0;
	if (my_pwrite(fd, signature, siglen, (off_t)(new_offset + sizeof(stub))) != (ssize_t)siglen)
		return 0;

	Elf64_Phdr new_phdr;

	memset(&new_phdr, 0, sizeof(new_phdr));
	new_phdr.p_type = PT_LOAD;
	new_phdr.p_flags = PF_R | PF_X;
	new_phdr.p_offset = new_offset;
	new_phdr.p_vaddr = new_vaddr;
	new_phdr.p_paddr = new_vaddr;
	new_phdr.p_filesz = sizeof(stub) + siglen;
	new_phdr.p_memsz = sizeof(stub) + siglen;
	new_phdr.p_align = 0x1000;
	hdrs->phdr[stub_build_data.phdr_target_index] = new_phdr;
	hdrs->ehdr.e_entry = new_vaddr;
	if (pwrite(fd, &hdrs->ehdr, sizeof(hdrs->ehdr), 0) != (ssize_t)sizeof(hdrs->ehdr))
		return 0;
	if (pwrite(fd, hdrs->phdr, hdrs->ehdr.e_phnum * sizeof(Elf64_Phdr), hdrs->ehdr.e_phoff) !=
		(ssize_t)(hdrs->ehdr.e_phnum * sizeof(Elf64_Phdr)))
		return 0;

	return 1;
	/*
		// generated version
		struct stat st;
		Elf64_Phdr *new_phdr_slot = NULL;
		unsigned char stub[41] = {
			0x52,						  // push rdx -> save the orignal rdx because we will overwrite it and we want to restore it
			0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 -> syscall number for write
			0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1 -> file descriptor stdout
			0x48, 0xbe,					  // movabs rsi, imm64 -> load rsi with the address of signature string (patched after), rsi is buffer for write
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xba, 0x00, 0x00, 0x00, 0x00, // mov edx, imm32 -> load edx with the signature length (patched at runtime)
			0x0f, 0x05,					  // syscall -> write(1, rsi, rdx)
			0x5a,						  // pop rdx
			0x48, 0xb8,					  // movabs rax, imm64 -> load rax with original entry point (patched at runtime)
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xff, 0xe0}; // jmp rax -> jump to original entry point
		unsigned char zeros[0x1000] = {0};
		Elf64_Phdr new_phdr;
		uint64_t max_vaddr_end = 0;
		uint64_t new_offset;
		uint64_t new_vaddr;
		uint64_t sig_vaddr;
		uint64_t orig_entry;
		uint32_t siglen32;
		size_t siglen;
		size_t pad;

		if (fd < 0 || !signature || !hdrs || !hdrs->phdr || hdrs->ehdr.e_phnum == 0)
			return 0;
		if (fstat(fd, &st) < 0)
			return 0;

		siglen = strlen(signature);
		if (siglen == 0)
			return 0;

		for (size_t i = 0; i < hdrs->ehdr.e_phnum; ++i)
		{
			if (hdrs->phdr[i].p_type == PT_LOAD)
			{
				uint64_t ph_end = hdrs->phdr[i].p_vaddr + hdrs->phdr[i].p_memsz;

				if (ph_end > max_vaddr_end)
					max_vaddr_end = ph_end;
			}
			else if (!new_phdr_slot && (hdrs->phdr[i].p_type == PT_NULL ||
										hdrs->phdr[i].p_type == PT_GNU_STACK || hdrs->phdr[i].p_type == PT_GNU_RELRO))
			{
				new_phdr_slot = &hdrs->phdr[i];
			}
		}
		if (!new_phdr_slot || max_vaddr_end == 0)
			return 0;

		orig_entry = hdrs->ehdr.e_entry;
		siglen32 = (uint32_t)siglen;
		pad = (0x1000 - ((size_t)st.st_size & 0x0fff)) & 0x0fff;
		new_offset = (uint64_t)st.st_size + pad;
		new_vaddr = (max_vaddr_end + 0x0fff) & ~(uint64_t)0x0fff;
		sig_vaddr = new_vaddr + sizeof(stub);

		memcpy(&stub[13], &sig_vaddr, sizeof(sig_vaddr));
		memcpy(&stub[22], &siglen32, sizeof(siglen32));
		memcpy(&stub[31], &orig_entry, sizeof(orig_entry));

		if (pad > 0 && pwrite(fd, zeros, pad, st.st_size) != (ssize_t)pad)
			return 0;
		if (pwrite(fd, stub, sizeof(stub), (off_t)new_offset) != (ssize_t)sizeof(stub))
			return 0;
		if (pwrite(fd, signature, siglen, (off_t)(new_offset + sizeof(stub))) != (ssize_t)siglen)
			return 0;

		memset(&new_phdr, 0, sizeof(new_phdr));
		new_phdr.p_type = PT_LOAD;
		new_phdr.p_flags = PF_R | PF_X;
		new_phdr.p_offset = new_offset;
		new_phdr.p_vaddr = new_vaddr;
		new_phdr.p_paddr = new_vaddr;
		new_phdr.p_filesz = sizeof(stub) + siglen;
		new_phdr.p_memsz = sizeof(stub) + siglen;
		new_phdr.p_align = 0x1000;
		*new_phdr_slot = new_phdr;
		hdrs->ehdr.e_entry = new_vaddr;
		if (pwrite(fd, &hdrs->ehdr, sizeof(hdrs->ehdr), 0) != (ssize_t)sizeof(hdrs->ehdr))
			return 0;
		if (pwrite(fd, hdrs->phdr, hdrs->ehdr.e_phnum * sizeof(Elf64_Phdr), hdrs->ehdr.e_phoff) !=
			(ssize_t)(hdrs->ehdr.e_phnum * sizeof(Elf64_Phdr)))
			return 0;

		return 1;
		*/
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
	int fd = open(path, O_RDWR);
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
	if (!append_stub_and_set_entry(fd, "WoodyWoodpacker\n", hdrs))
		fprintf(stderr, "failed to append stub and patch entry\n");
	close(fd);

	// print_elf64_headers(hdrs);
	free_elf64_headers(hdrs);

	// TODO
	// encrypt text section
	// add signature + decryption code at the end of (i do not rememember where, looks to PT_LOAD) + encryption code
	// change entry point to the decryption code
	// flow of targetede file: print signature + decrypt text section + jump to original entry point and run normally + encrypted text section again
	return 0;
}
