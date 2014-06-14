#include <linux/bstream_ops.h>
#include <linux/export.h>

static ssize_t bstream_file_read(struct file *filp, char __user *buf, size_t size, loff_t *ppos)
{
	struct bstream_file_data *stream_data = filp->private_data;
	struct bstream *bstream;

	bstream = stream_data->bstream;
	if (bstream != NULL)
		return bstream_read(bstream, buf, size, ppos);
	else
		return -EINVAL;
}

static ssize_t bstream_file_write(struct file *filp, const char __user *buf, size_t size, loff_t *ppos)
{
	struct bstream_file_data *stream_data = filp->private_data;
	struct bstream *bstream;

	bstream = stream_data->bstream;
	if (bstream != NULL)
		return bstream_write(bstream, buf, size, ppos);
	else
		return -EINVAL;
}

static int bstream_file_release(struct inode *inode, struct file *filp)
{
	struct bstream_file_data *stream_data = filp->private_data;
	bstream_file_data_release(stream_data);
	return 0;
}

static struct file_operations bstream_file_fops = {
	.read           = bstream_file_read,
	.write          = bstream_file_write,
	.release        = bstream_file_release,
	.llseek		= noop_llseek,
};

int create_bstream_inode(const char *name, int permission,
			 struct bstream_file_data *stream_data)
{
	atomic_inc(&stream_data->bstream_use_count);
	return anon_inode_getfd(name, &bstream_file_fops, stream_data, permission);
}
EXPORT_SYMBOL_GPL(create_bstream_inode);

void register_bstream_file_ops(struct module *module)
{
	bstream_file_fops.owner = module;
}
EXPORT_SYMBOL_GPL(register_bstream_file_ops);

int create_bstream_file(const char *name, int permission,
			u32 num_pages, u32 page_size_order,
			atomic_long_t *back_pointer)
{
	int r = 0;

	if (atomic_long_read(back_pointer) == 0) {
		struct bstream *bstream = bstream_create(num_pages, page_size_order);
		if (bstream != NULL) {
			struct bstream_file_data *stream_data =
				create_bstream_file_data(bstream);
			if (stream_data != NULL) {
				if (atomic_long_cmpxchg(back_pointer, 0, (long)stream_data) != 0) {
					bstream_file_data_release(stream_data);
				}
			} else {
				bstream_free(bstream);
				r = -ENOMEM;
			}
		} else {
			r = -ENOMEM;
		}
	}
	return r;
}
EXPORT_SYMBOL_GPL(create_bstream_file);

int open_bstream_file(const char *name, int permission,
		      u32 num_pages, u32 page_size_order,
		      atomic_long_t *back_pointer)
{
	/* TODO: Solve creation race. */
	int r = create_bstream_file(name, permission, num_pages, page_size_order, back_pointer);
	if (r >= 0) {
		struct bstream_file_data *stream_data =
			get_bstream_file_data(back_pointer);
		if (stream_data != NULL) {
			r = create_bstream_inode(name, permission, stream_data);
			if (r < 0)
				close_bstream_file(back_pointer);
		} else {
			r = -ENOMEM;
		}
	}
	return r;
}
EXPORT_SYMBOL_GPL(open_bstream_file);

void close_bstream_file(atomic_long_t *back_pointer)
{
	struct bstream_file_data *stream_data = (struct bstream_file_data *)
		atomic_long_xchg(back_pointer, 0);
	if (stream_data)
		bstream_file_data_release(stream_data);
}
EXPORT_SYMBOL_GPL(close_bstream_file);
