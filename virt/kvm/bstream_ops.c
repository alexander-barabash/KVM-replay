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
