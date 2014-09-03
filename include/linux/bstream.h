#ifndef __BSTREAM_H
#define __BSTREAM_H

#include <linux/types.h>

struct bstream;

extern struct bstream *bstream_create(u32 num_pages, u32 page_size_order);
extern void bstream_free(struct bstream *bstream);

extern ssize_t bstream_read(struct bstream *bstream,
			    char __user *buf,
			    size_t size,
			    loff_t *ppos);
extern ssize_t bstream_write(struct bstream *bstream,
			     const char __user *buf,
			     size_t size,
			     loff_t *ppos);

extern ssize_t bstream_read_unlocked(struct bstream *bstream, long buf, bool is_user, size_t size, loff_t *ppos);
extern ssize_t bstream_write_unlocked(struct bstream *bstream, long buf, bool is_user, size_t size, loff_t *ppos);
extern bool bstream_on_last_write_page(struct bstream *bstream);
extern bool bstream_on_last_read_page(struct bstream *bstream);

static inline ssize_t bstream_kernel_write_unlocked(struct bstream *bstream,
						    const char *buf,
						    size_t size)
{
	return bstream_write_unlocked(bstream, (long)buf, false, size, NULL);
}

static inline ssize_t bstream_kernel_read_unlocked(struct bstream *bstream,
						   const char *buf,
						   size_t size)
{
	return bstream_read_unlocked(bstream, (long)buf, false, size, NULL);
}

#endif
