#include <linux/bstream.h>
#include <linux/export.h>

#define BSTREAM_MIN_PAGES 2
struct bstream_page {
	u32 write_index;
	u32 read_index;
	unsigned long page;
};

struct bstream {
	u32 num_pages;
	u32 page_size_order;
	u32 write_page_index;
	u32 read_page_index;
	loff_t read_offset;
	loff_t write_offset;
	spinlock_t spinlock;
	struct mutex lock;
	struct bstream_page pages[BSTREAM_MIN_PAGES];
};
#ifdef spin_lock
#undef spin_lock
#endif
#ifdef spin_unlock
#undef spin_unlock
#endif
#define spin_lock(...)
#define spin_unlock(...)
static inline u32 bstream_page_size(struct bstream *bstream)
{
	return PAGE_SIZE << bstream->page_size_order;
}

static inline const void *bstream_page_read_position(struct bstream_page *page)
{
	if (unlikely(!page->page))
		return NULL;
	return (const void *)(page->page + page->read_index);
}

static inline void *bstream_page_write_position(struct bstream_page *page)
{
	if (unlikely(!page->page))
		return NULL;
	return (void *)(page->page + page->write_index);
}

static inline u32 bstream_page_unread(struct bstream_page *page)
{
	return page->write_index - page->read_index;
}

static inline u32 bstream_page_write_space(struct bstream *bstream, struct bstream_page *page)
{
	return bstream_page_size(bstream) - page->write_index;
}

static inline u32 bstream_next_page_index(struct bstream *bstream, u32 index)
{
	if (++index == bstream->num_pages)
		return 0;
	return index;
}

static inline struct bstream_page *bstream_read_page(struct bstream *bstream,
						     bool *exclusive_read,
						     u32 *unread_on_page)
{
	struct bstream_page *page;
	u32 read_page_index;
	spin_lock(&bstream->spinlock);
	read_page_index = bstream->read_page_index;
	page = &bstream->pages[read_page_index];
	*unread_on_page = bstream_page_unread(page);
	*exclusive_read = (read_page_index != bstream->write_page_index);
	spin_unlock(&bstream->spinlock);
	return page;
}

static inline struct bstream_page *bstream_goto_next_read_page(struct bstream *bstream,
							       bool *exclusive_read,
							       u32 *unread_on_page)
{
	struct bstream_page *page;
	u32 read_page_index;
	u32 write_page_index;
	spin_lock(&bstream->spinlock);
	read_page_index = bstream->read_page_index;
	write_page_index = bstream->write_page_index;
	if (read_page_index != write_page_index) {
		read_page_index = bstream_next_page_index(bstream, read_page_index);
		bstream->read_page_index = read_page_index;
		page = &bstream->pages[read_page_index];
		page->read_index = 0;
		*unread_on_page = page->write_index;
		*exclusive_read = (read_page_index != write_page_index);
	} else {
		page = NULL;
	}
	spin_unlock(&bstream->spinlock);
	return page;
}

static inline struct bstream_page *bstream_write_page(struct bstream *bstream,
						      u32 *left_on_page)
{
	struct bstream_page *page;
	u32 write_page_index;
	spin_lock(&bstream->spinlock);
	write_page_index = bstream->write_page_index;
	page = &bstream->pages[write_page_index];
	*left_on_page = bstream_page_write_space(bstream, page);
	spin_unlock(&bstream->spinlock);
	return page;
}

static inline struct bstream_page *bstream_goto_next_write_page(struct bstream *bstream)
{
	struct bstream_page *page;
	u32 write_page_index;
	spin_lock(&bstream->spinlock);
	write_page_index = bstream_next_page_index(bstream, bstream->write_page_index);
	if (write_page_index != bstream->read_page_index) {
		bstream->write_page_index = write_page_index;
		page = &bstream->pages[write_page_index];
		page->write_index = 0;
	} else {
		page = NULL;
	}
	spin_unlock(&bstream->spinlock);
	return page;
}

static inline void bstream_page_fwd_read_index(struct bstream *bstream,
					       struct bstream_page *page,
					       u32 value)
{
	spin_lock(&bstream->spinlock);
	page->read_index += value;
	spin_unlock(&bstream->spinlock);
}

static inline void bstream_page_fwd_write_index(struct bstream *bstream,
						struct bstream_page *page,
						u32 value)
{
	spin_lock(&bstream->spinlock);
	page->write_index += value;
	spin_unlock(&bstream->spinlock);
}

static inline bool bstream_page_alloc_page(struct bstream *bstream, struct bstream_page *page)
{
	if (page->page != 0)
		return true;
	page->page =
		__get_free_pages(GFP_KERNEL | __GFP_ZERO, bstream->page_size_order);
	return page->page != 0;
}

static inline bool bstream_alloc_page(struct bstream *bstream, u32 page_index)
{
	if (page_index < bstream->num_pages)
		return bstream_page_alloc_page(bstream, &bstream->pages[page_index]);
	else
		return false;
}

static inline void bstream_free_page(struct bstream *bstream, u32 page_index)
{
	if (page_index < bstream->num_pages) {
		struct bstream_page *bstream_page = &bstream->pages[page_index];
		if (bstream_page->page != 0) {
			free_pages(bstream_page->page, bstream->page_size_order);
			bstream_page->page = 0;
		}
	}
}

struct bstream *bstream_create(u32 num_pages, u32 page_size_order)
{
	struct bstream *bstream;
	int i;

	if ((((u64)PAGE_SIZE) << page_size_order) != (((u32)PAGE_SIZE) << page_size_order))
		return NULL;
	if (num_pages < BSTREAM_MIN_PAGES)
		num_pages = BSTREAM_MIN_PAGES;
	bstream = kzalloc(sizeof(struct bstream) +
			  (num_pages - BSTREAM_MIN_PAGES) * sizeof(struct bstream_page),
			  GFP_KERNEL);
	if (bstream == NULL)
		return NULL;
	spin_lock_init(&bstream->spinlock);
	mutex_init(&bstream->lock);
	bstream->num_pages = num_pages;
	bstream->page_size_order = page_size_order;
	for (i = 0; i < num_pages; ++i) {
		if (!bstream_alloc_page(bstream, i)) {
			bstream_free(bstream);
			return NULL;
		}
	}
	return bstream;
}
EXPORT_SYMBOL_GPL(bstream_create);

void bstream_free(struct bstream *bstream)
{
	u32 i;

	if (bstream != NULL) {
		for (i = 0; i < bstream->num_pages; ++i) {
			bstream_free_page(bstream, i);
		}
	}
	kfree(bstream);
}
EXPORT_SYMBOL_GPL(bstream_free);

ssize_t bstream_read_unlocked(struct bstream *bstream, long buf, bool is_user, size_t size, loff_t *ppos)
{
	ssize_t copied = 0;
	int err = 0;
	struct bstream_page *bstream_page = NULL;

	/* llseek is not supported. */
	if (ppos && unlikely(*ppos != bstream->read_offset))
		return -ESPIPE;

	while (size > 0) {
		bool exclusive_read;
		u32 unread_on_page;
		unsigned long to_copy, not_copied;
		const void *read_position;

		if (bstream_page == NULL)
			bstream_page = bstream_read_page(bstream, &exclusive_read, &unread_on_page);
		else
			bstream_page = bstream_goto_next_read_page(bstream, &exclusive_read, &unread_on_page);

		if (bstream_page == NULL)
			break;

		if (unread_on_page == 0) {
			if (!exclusive_read)
				break;
			else
				continue;
		}

		if (unread_on_page < size) {
			to_copy = unread_on_page;
			if (exclusive_read)
				size -= unread_on_page;
			else
				size = 0;
		} else {
			to_copy = size;
			size = 0;
		}
		
		read_position = bstream_page_read_position(bstream_page);
		if (read_position) {
			if (is_user) {
				not_copied = copy_to_user((char __user *)buf,
							  read_position,
							  to_copy);
			} else {
				memcpy((char *)buf,
				       read_position,
				       to_copy);
				not_copied = 0;
			}
		} else {
			not_copied = to_copy;
		}
		if (not_copied < to_copy) {
			to_copy -= not_copied;
			buf += to_copy;
			copied += to_copy;
			if (exclusive_read)
				bstream_page->read_index += to_copy;
			else
				bstream_page_fwd_read_index(bstream, bstream_page, to_copy);
		}
		if (not_copied > 0) {
			err = -EFAULT;
			size = 0;
		}
	}

	bstream->read_offset += copied;
	if (ppos)
		*ppos = bstream->read_offset;

	return copied ? copied : err;
}
EXPORT_SYMBOL_GPL(bstream_read_unlocked);

ssize_t bstream_read(struct bstream *bstream, char __user *buf, size_t size, loff_t *ppos)
{
	ssize_t copied;
	mutex_lock(&bstream->lock);
	copied = bstream_read_unlocked(bstream, (long)buf, true, size, ppos);
	mutex_unlock(&bstream->lock);
	return copied;
}
EXPORT_SYMBOL_GPL(bstream_read);

bool bstream_on_last_write_page(struct bstream *bstream)
{
	return (bstream_next_page_index(bstream, bstream->write_page_index) ==
		bstream->read_page_index);
}
EXPORT_SYMBOL_GPL(bstream_on_last_write_page);

bool bstream_on_last_read_page(struct bstream *bstream)
{
	return (bstream->read_page_index == bstream->write_page_index);
}
EXPORT_SYMBOL_GPL(bstream_on_last_read_page);

ssize_t bstream_write_unlocked(struct bstream *bstream,
			       long buf,
			       bool is_user,
			       size_t size,
			       loff_t *ppos)
{
	ssize_t copied = 0;
	int err = 0;
	struct bstream_page *bstream_page = NULL;
	
	/* llseek is not supported. */
	if (ppos && unlikely(*ppos != bstream->write_offset))
		return -ESPIPE;

	while (size > 0) {
		u32 left_on_page;
		unsigned long to_copy, not_copied;
		void *write_position;

		if (bstream_page == NULL) {
			bstream_page = bstream_write_page(bstream, &left_on_page);
		} else {
			bstream_page = bstream_goto_next_write_page(bstream);
			if (bstream_page == NULL) {
				break;
			}
			if (bstream_page->page == 0) {
				if (!is_user) {
					err = -ENOMEM;
					break;
				}
				/* TODO: reuse existing page if possible */
				break;
			}
			left_on_page = bstream_page_size(bstream);
		}

		if (left_on_page == 0)
			continue;

		if (left_on_page < size) {
			to_copy = left_on_page;
			size -= left_on_page;
		} else {
			to_copy = size;
			size = 0;
		}
		write_position = bstream_page_write_position(bstream_page);
		if (write_position) {
			if (is_user) {
				not_copied = copy_from_user(write_position,
							    (const char __user *)buf,
							    to_copy);
			} else {
				memcpy(write_position,
				       (const char *)buf,
				       to_copy);
				not_copied = 0;
			}
		} else {
			not_copied = to_copy;
		}
		if (not_copied < to_copy) {
			to_copy -= not_copied;
			buf += to_copy;
			copied += to_copy;
			bstream_page_fwd_write_index(bstream, bstream_page, to_copy);
		}
		if (not_copied > 0) {
			err = -EFAULT;
			size = 0;
		}
	}

	if (copied > 0) {
		if (((bstream->write_offset + copied) >> 20) !=
		    ((bstream->write_offset) >> 20)) {
			printk(KERN_WARNING "Wrote %lld MBytes to bstream\n",
			       ((bstream->write_offset + copied) >> 20));
		}
	}
	bstream->write_offset += copied;
	if (ppos)
		*ppos = bstream->write_offset;

	return copied ? copied : err;
}
EXPORT_SYMBOL_GPL(bstream_write_unlocked);

ssize_t bstream_write(struct bstream *bstream, const char __user *buf, size_t size, loff_t *ppos)
{
	ssize_t copied;
	mutex_lock(&bstream->lock);
	copied = bstream_write_unlocked(bstream, (long)buf, true, size, ppos);
	mutex_unlock(&bstream->lock);
	return copied;
}
EXPORT_SYMBOL_GPL(bstream_write);
