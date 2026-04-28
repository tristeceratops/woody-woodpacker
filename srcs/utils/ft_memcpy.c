#include "utils.h"

void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	unsigned char		*p;
	const unsigned char	*s;

	p = dest;
	s = src;
	while (n--)
	{
		*p++ = *s++;
	}
	return (dest);
}