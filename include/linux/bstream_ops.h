#ifndef __BSTREAM_OPS_H
#define __BSTREAM_OPS_H

#include <linux/bstream.h>
#include <linux/types.h>

struct bstream_file_data {
	struct bstream *bstream;
	atomic_t bstream_use_count;
};

extern void register_bstream_file_ops(struct module *module);
extern int create_bstream_inode(const char *name, int permission,
				struct bstream_file_data *stream_data);

static inline
struct bstream_file_data *create_bstream_file_data(struct bstream *bstream)
{
	struct bstream_file_data *stream_data;

	stream_data = kzalloc(sizeof(*stream_data), GFP_KERNEL);
	if (stream_data != NULL) {
		stream_data->bstream = bstream;
		atomic_set(&stream_data->bstream_use_count, 1);
	}
	return stream_data;
}

static inline
void bstream_file_data_release(struct bstream_file_data *stream_data)
{
	if (atomic_dec_return(&stream_data->bstream_use_count) == 0) {
		if (stream_data->bstream)
			bstream_free(stream_data->bstream);
		kfree(stream_data);
	}
}

extern int create_bstream_file(const char *name, int permission,
			       u32 num_pages, u32 page_size_order,
			       atomic_long_t *back_pointer);
/*
 * Allocates an inode.
 */
extern int open_bstream_file(const char *name, int permission,
			     u32 num_pages, u32 page_size_order,
			     atomic_long_t *back_pointer);
extern void close_bstream_file(atomic_long_t *back_pointer);

static inline
struct bstream_file_data *get_bstream_file_data(atomic_long_t *back_pointer)
{
	return (struct bstream_file_data *)atomic_long_read(back_pointer);
}

#endif
