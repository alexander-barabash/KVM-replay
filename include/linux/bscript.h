#ifndef __BSCRIPT_H
#define __BSCRIPT_H

#ifndef COMPILE_USERSPACE
#include <linux/types.h>
#else
#include <stdint.h>
#include <stdbool.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;
#endif


#ifndef COMPILE_USERSPACE
#include <linux/bstream.h>
static inline bool bscript_write_raw_data(struct bstream *bstream, const void *data, u32 size)
{
	return bstream_kernel_write_unlocked(bstream, data, size) == size;
}
static inline bool bscript_read_raw_data(struct bstream *bstream, void *data, u32 size)
{
	return bstream_kernel_read_unlocked(bstream, data, size) == size;
}
#else
struct bstream;
extern bool bscript_write_raw_data(struct bstream *bstream, const void *data, u32 size);
extern bool bscript_read_raw_data(struct bstream *bstream, void *data, u32 size);
#endif

static inline bool bscript_write_u8(struct bstream *bstream, u8 c)
{
	return bscript_write_raw_data(bstream, &c, 1);
}
static inline bool bscript_read_u8(struct bstream *bstream, u8 *c)
{
	return bscript_read_raw_data(bstream, c, 1);
}

extern bool bscript_write_u16(struct bstream *bstream, u16 us);
extern bool bscript_read_u16(struct bstream *bstream, u16 *us);
extern bool bscript_write_u32(struct bstream *bstream, u32 u);
extern bool bscript_read_u32(struct bstream *bstream, u32 *u);
extern bool bscript_write_u64(struct bstream *bstream, u64 number);
extern bool bscript_read_u64(struct bstream *bstream, u64 *number);
extern bool bscript_write_symmetric_u32(struct bstream *bstream, u32 u);
extern bool bscript_read_symmetric_u32(struct bstream *bstream, u32 *u);
extern bool bscript_write_symmetric_u64(struct bstream *bstream, u64 ull);
extern bool bscript_read_symmetric_u64(struct bstream *bstream, u64 *ull);

static inline bool bscript_write_s8(struct bstream *bstream, s8 c)
{
	return bscript_write_u8(bstream, (u8)c);
}
static inline bool bscript_read_s8(struct bstream *bstream, s8 *c)
{
	return bscript_read_u8(bstream, (u8 *)c);
}

static inline bool bscript_write_s16(struct bstream *bstream, s16 number)
{
	if(number < 0)
		return bscript_write_u16(bstream, (u16)(((~number) << 1) | 1));
	else
		return bscript_write_u16(bstream, (u16)(number << 1));
}
static inline bool bscript_read_s16(struct bstream *bstream, s16 *number)
{
	u16 u;
	if (!bscript_read_u16(bstream, &u))
		return false;
	if(u & 1)
		*number = (s16)(~(u >> 1));
	else
		*number = (s16)(u >> 1);
	return true;
}

static inline bool bscript_write_s32(struct bstream *bstream, s32 number)
{
	if(number < 0)
		return bscript_write_u32(bstream, ((~number) << 1) | 1);
	else
		return bscript_write_u32(bstream, number << 1);
}
static inline bool bscript_read_s32(struct bstream *bstream, s32 *number)
{
	u32 u;
	if (!bscript_read_u32(bstream, &u))
		return false;
	if(u & 1)
		*number = ~(u >> 1);
	else
		*number = (u >> 1);
	return true;
}

static inline bool bscript_write_s64(struct bstream *bstream, s64 number)
{
	if(number < 0)
		return bscript_write_u64(bstream, ((~number) << 1) | 1);
	else
		return bscript_write_u64(bstream, number << 1);
}
static inline bool bscript_read_s64(struct bstream *bstream, s64 *number)
{
	u64 u;
	if (!bscript_read_u64(bstream, &u))
		return false;
	if(u & 1)
		*number = ~(u >> 1);
	else
		*number = (u >> 1);
	return true;
}

extern bool bscript_write_string(struct bstream *bstream, const u8 *s);
extern bool bscript_write_data(struct bstream *bstream, const void *data, u32 size);

#endif
