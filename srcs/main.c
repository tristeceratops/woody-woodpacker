#include "woody_woodpacker.h"
#include "utils.h"

int main(void)
{
	const char *path = "example.txt";
	const char *message = "Hello from mmap!\nThis file was created and written using mmap.\n";
	const size_t len = strlen(message);
	int fd;
	void *map;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
	{
		perror("open");
		return (1);
	}
	if (ftruncate(fd, (off_t)len) == -1)
	{
		perror("ftruncate");
		close(fd);
		return (1);
	}
	map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
	{
		perror("mmap");
		close(fd);
		return (1);
	}
	ft_memcpy(map, message, len);
	if (msync(map, len, MS_SYNC) == -1)
		perror("msync");
	if (munmap(map, len) == -1)
		perror("munmap");
	if (close(fd) == -1)
		perror("close");
	printf("Wrote %zu bytes to %s using mmap.\n", len, path);
	return (0);
}
