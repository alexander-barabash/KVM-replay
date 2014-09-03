#include <linux/bscript.h>
#ifndef COMPILE_USERSPACE
#include <linux/export.h>
#else
#include <string.h>
#define EXPORT_SYMBOL_GPL(...)
#endif

static u64 HIGHEST_BYTE_MASK_FOR_U64 = ((u64)0xFFU << (64 - 8));
static u8 NULL_MARKER = 0x80U;
static u8 SEVENBYTE_MASK = 0x7FU;
static u8 BYTE_MASK = 0xFFU;
static u8 HIGH_BIT_MASK = 0x80U;
static u8 SIXBYTE_MASK = 0x3FU;
static u8 FIRST_6BYTE_BIT_MASK = 0x80U;
static u8 LAST_6BYTE_BIT_MASK = 0x40U;

static inline u64 HIGHEST_BYTE_FOR_U64(u64 number)
{
	return number & HIGHEST_BYTE_MASK_FOR_U64;
}
static inline bool HAS_HIGHEST_BYTE_FOR_U64(u64 number)
{
	return HIGHEST_BYTE_FOR_U64(number) != 0;
}

static inline u8 LEAST_SIGNIFICANT_BYTE_AS_CHAR(u64 number)
{
	return (u8)(number & BYTE_MASK);
}
static inline u64 WITHOUT_LEAST_SIGNIFICANT_BYTE(u64 number)
{
	return number >> 8;
}
static inline u64 WITHOUT_LEAST_SIGNIFICANT_BIT(u64 number)
{
	return number >> 1;
}

/* N must be between 0 and 10 */
static inline u8 SIXBYTE(int N, u64 number)
{
	return (u8)((number >> (N * 6)) & SIXBYTE_MASK);
}
/* N must be between 0 and 8 */
static inline u8 SEVENBYTE(int N, u64 number)
{
	return (u8)((number >> (N * 7)) & SEVENBYTE_MASK);
}

static inline u8 HIGH_7BYTE(u8 byte)
{
	return (u8)(byte | HIGH_BIT_MASK);
}
static inline u8 LOW_7BYTE(u8 byte)
{
	return (u8)(byte & ~HIGH_BIT_MASK);
}
static inline bool IS_HIGH_7BYTE(u8 byte)
{
	return ((byte & HIGH_BIT_MASK) != 0);
}

static inline u8 FIRST_6BYTE(u8 byte)
{
	return (u8)(byte | FIRST_6BYTE_BIT_MASK);
}
static inline u8 LAST_6BYTE(u8 byte)
{
	return (u8)(byte | LAST_6BYTE_BIT_MASK);
}
static inline u8 ONLY_6BYTE(u8 byte)
{
	return (u8)(byte | (LAST_6BYTE_BIT_MASK | FIRST_6BYTE_BIT_MASK));
}
static inline u8 PURE_6BYTE(u8 byte)
{
	return (u8)(byte & SIXBYTE_MASK);
}

static inline bool IS_FIRST_6BYTE(u8 byte)
{
	return (byte & FIRST_6BYTE_BIT_MASK) != 0;
}
static inline bool IS_LAST_6BYTE(u8 byte)
{
	return (byte & LAST_6BYTE_BIT_MASK) != 0;
}

bool bscript_write_u16(struct bstream *bstream, u16 us)
{
	u8 bytes[] = {
		SEVENBYTE(0, us),
		SEVENBYTE(1, us),
		SEVENBYTE(2, us),
	};
	u8 buffer[sizeof(bytes)];
	u32 index = 0;
	if(bytes[2]) {
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
	} else if(bytes[1]) {
		buffer[index++] = HIGH_7BYTE(bytes[1]);
	}
	buffer[index++] = bytes[0];
	return bscript_write_raw_data(bstream, buffer, index);
}
EXPORT_SYMBOL_GPL(bscript_write_u16);

bool bscript_read_u16(struct bstream *bstream, u16 *us)
{
	u8 byte;
	u32 result;
	
	// 0
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*us = (u16)byte;
		return true;
	}
	result = LOW_7BYTE(byte);
	result <<= 7;
	
	// 1
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*us = (u16)(result | byte);
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 7;
	
	// 2
	if (!bscript_read_u8(bstream, &byte))
		return false;

	*us = (u16)(result | byte);
	return true;
}
EXPORT_SYMBOL_GPL(bscript_read_u16);

bool bscript_write_u32(struct bstream *bstream, u32 u)
{
	u8 bytes[] = {
		SEVENBYTE(0, u),
		SEVENBYTE(1, u),
		SEVENBYTE(2, u),
		SEVENBYTE(3, u),
		SEVENBYTE(4, u)
	};
	u8 buffer[sizeof(bytes)];
	u32 index = 0;
	if(bytes[4]) {
		buffer[index++] = HIGH_7BYTE(bytes[4]);
		buffer[index++] = HIGH_7BYTE(bytes[3]);
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
	} else if(bytes[3]) {
		buffer[index++] = HIGH_7BYTE(bytes[3]);
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
	} else if(bytes[2]) {
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
	} else if(bytes[1]) {
		buffer[index++] = HIGH_7BYTE(bytes[1]);
	}
	buffer[index++] = bytes[0];
	return bscript_write_raw_data(bstream, buffer, index);
}
EXPORT_SYMBOL_GPL(bscript_write_u32);

bool bscript_read_u32(struct bstream *bstream, u32 *u)
{
	u8 byte;
	u32 result;

	// 0
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*u = (u32)byte;
		return true;
	}
	result = LOW_7BYTE(byte);
	result <<= 7;

	// 1
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*u = result | byte;
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 7;
	
	// 2
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*u = result | byte;
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 7;

	// 3
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*u = result | byte;
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 7;

	// 4
	if (!bscript_read_u8(bstream, &byte))
		return false;
	*u = result | byte;
	return true;
}
EXPORT_SYMBOL_GPL(bscript_read_u32);

bool bscript_write_u64(struct bstream *bstream, u64 number)
{
	bool is_super_long_long;
	u8 tail;
	u8 bytes[9];
	u8 buffer[sizeof(bytes)];
	u32 index = 0;
	if (HAS_HIGHEST_BYTE_FOR_U64(number)) {
		/*
		 * If number does not fit into the 8 bytes of standard encoding
		 * (i.e. its most significant byte is non-zero),
		 * just chop off the least significant bit,
		 * and write the least significant byte afterwards.
		 */
		is_super_long_long = true;
		tail = LEAST_SIGNIFICANT_BYTE_AS_CHAR(number);
		number = WITHOUT_LEAST_SIGNIFICANT_BIT(number);
	} else {
		is_super_long_long = false;
		tail = 0;
	}
	bytes[0] = SEVENBYTE(0, number);
	bytes[1] = SEVENBYTE(1, number);
	bytes[2] = SEVENBYTE(2, number);
	bytes[3] = SEVENBYTE(3, number);
	bytes[4] = SEVENBYTE(4, number);
	bytes[5] = SEVENBYTE(5, number);
	bytes[6] = SEVENBYTE(6, number);
	bytes[7] = SEVENBYTE(7, number);
	bytes[8] = SEVENBYTE(8, number);
	if (is_super_long_long) {
		buffer[index++] = HIGH_7BYTE(bytes[8]);
		buffer[index++] = HIGH_7BYTE(bytes[7]);
		buffer[index++] = HIGH_7BYTE(bytes[6]);
		buffer[index++] = HIGH_7BYTE(bytes[5]);
		buffer[index++] = HIGH_7BYTE(bytes[4]);
		buffer[index++] = HIGH_7BYTE(bytes[3]);
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
		buffer[index++] = tail; /* This has 8 significant bits */
	} else if(bytes[7]) {
		buffer[index++] = HIGH_7BYTE(bytes[7]);
		buffer[index++] = HIGH_7BYTE(bytes[6]);
		buffer[index++] = HIGH_7BYTE(bytes[5]);
		buffer[index++] = HIGH_7BYTE(bytes[4]);
		buffer[index++] = HIGH_7BYTE(bytes[3]);
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
		buffer[index++] = bytes[0];
	} else if(bytes[6]) {
		buffer[index++] = HIGH_7BYTE(bytes[6]);
		buffer[index++] = HIGH_7BYTE(bytes[5]);
		buffer[index++] = HIGH_7BYTE(bytes[4]);
		buffer[index++] = HIGH_7BYTE(bytes[3]);
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
		buffer[index++] = bytes[0];
	} else if(bytes[5]) {
		buffer[index++] = HIGH_7BYTE(bytes[5]);
		buffer[index++] = HIGH_7BYTE(bytes[4]);
		buffer[index++] = HIGH_7BYTE(bytes[3]);
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
		buffer[index++] = bytes[0];
	} else if(bytes[4]) {
		buffer[index++] = HIGH_7BYTE(bytes[4]);
		buffer[index++] = HIGH_7BYTE(bytes[3]);
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
		buffer[index++] = bytes[0];
	} else if(bytes[3]) {
		buffer[index++] = HIGH_7BYTE(bytes[3]);
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
		buffer[index++] = bytes[0];
	} else if(bytes[2]) {
		buffer[index++] = HIGH_7BYTE(bytes[2]);
		buffer[index++] = HIGH_7BYTE(bytes[1]);
		buffer[index++] = bytes[0];
	} else if(bytes[1]) {
		buffer[index++] = HIGH_7BYTE(bytes[1]);
		buffer[index++] = bytes[0];
	} else {
		buffer[index++] = bytes[0];
	}
	return bscript_write_raw_data(bstream, buffer, index);
}
EXPORT_SYMBOL_GPL(bscript_write_u64);

bool bscript_read_u64(struct bstream *bstream, u64 *number)
{
	u8 byte;
	u64 result;

	// 0
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*number = (u64)byte;
		return true;
	}
	result = LOW_7BYTE(byte);
	result <<= 7;

	// 1
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*number = result | byte;
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 7;

	// 2
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*number = result | byte;
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 7;

	// 3
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*number = result | byte;
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 7;

	// 4
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*number = result | byte;
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 7;

	// 5
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*number = result | byte;
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 7;

	// 6
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*number = result | byte;
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 7;

	// 7
	if (!bscript_read_u8(bstream, &byte))
		return false;
	if(!IS_HIGH_7BYTE(byte)) {
		*number = result | byte;
		return true;
	}
	result |= LOW_7BYTE(byte);
	result <<= 8; // NB

	// 8
	if (!bscript_read_u8(bstream, &byte))
		return false;
	*number = result | byte;
	return true;
}
EXPORT_SYMBOL_GPL(bscript_read_u64);

bool bscript_write_symmetric_u32(struct bstream *bstream, u32 u)
{
	u8 bytes[] = {
		SIXBYTE(0, u),
		SIXBYTE(1, u),
		SIXBYTE(2, u),
		SIXBYTE(3, u),
		SIXBYTE(4, u),
		SIXBYTE(5, u),
	};
	u8 buffer[sizeof(bytes)];
	u32 index = 0;
	if(bytes[5]) {
		buffer[index++] = FIRST_6BYTE(bytes[5]);
		buffer[index++] = bytes[4];
		buffer[index++] = bytes[3];
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[4]) {
		buffer[index++] = FIRST_6BYTE(bytes[4]);
		buffer[index++] = bytes[3];
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[3]) {
		buffer[index++] = FIRST_6BYTE(bytes[3]);
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[2]) {
		buffer[index++] = FIRST_6BYTE(bytes[2]);
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[1]) {
		buffer[index++] = FIRST_6BYTE(bytes[1]);
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else {
		buffer[index++] = ONLY_6BYTE(bytes[0]);
	}
	return bscript_write_raw_data(bstream, buffer, index);
}
EXPORT_SYMBOL_GPL(bscript_write_symmetric_u32);

bool bscript_read_symmetric_u32(struct bstream *bstream, u32 *u)
{
	u8 byte;
	u32 result;

	// 0
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result = PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*u = result;
		return true;
	}
	result <<= 6;

	// 1
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*u = result;
		return true;
	}
	result <<= 6;

	// 2
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*u = result;
		return true;
	}
	result <<= 6;
  
	// 3
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*u = result;
		return true;
	}
	result <<= 6;
  
	// 4
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*u = result;
		return true;
	}
	result <<= 6;
  
	// 5
	if (!bscript_read_u8(bstream, &byte))
		return false;
	*u = result | PURE_6BYTE(byte);
	return true;
}
EXPORT_SYMBOL_GPL(bscript_read_symmetric_u32);

bool bscript_write_symmetric_u64(struct bstream *bstream, u64 ull)
{
	u8 bytes[] = {
		SIXBYTE(0, ull),
		SIXBYTE(1, ull),
		SIXBYTE(2, ull),
		SIXBYTE(3, ull),
		SIXBYTE(4, ull),
		SIXBYTE(5, ull),
		SIXBYTE(6, ull),
		SIXBYTE(7, ull),
		SIXBYTE(8, ull),
		SIXBYTE(9, ull),
		SIXBYTE(10, ull),
	};
	u8 buffer[sizeof(bytes)];
	u32 index = 0;
	if(bytes[10]) {
		buffer[index++] = FIRST_6BYTE(bytes[10]);
		buffer[index++] = bytes[9];
		buffer[index++] = bytes[8];
		buffer[index++] = bytes[7];
		buffer[index++] = bytes[6];
		buffer[index++] = bytes[5];
		buffer[index++] = bytes[4];
		buffer[index++] = bytes[3];
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[9]) {
		buffer[index++] = FIRST_6BYTE(bytes[9]);
		buffer[index++] = bytes[8];
		buffer[index++] = bytes[7];
		buffer[index++] = bytes[6];
		buffer[index++] = bytes[5];
		buffer[index++] = bytes[4];
		buffer[index++] = bytes[3];
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[8]) {
		buffer[index++] = FIRST_6BYTE(bytes[8]);
		buffer[index++] = bytes[7];
		buffer[index++] = bytes[6];
		buffer[index++] = bytes[5];
		buffer[index++] = bytes[4];
		buffer[index++] = bytes[3];
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[7]) {
		buffer[index++] = FIRST_6BYTE(bytes[7]);
		buffer[index++] = bytes[6];
		buffer[index++] = bytes[5];
		buffer[index++] = bytes[4];
		buffer[index++] = bytes[3];
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[6]) {
		buffer[index++] = FIRST_6BYTE(bytes[6]);
		buffer[index++] = bytes[5];
		buffer[index++] = bytes[4];
		buffer[index++] = bytes[3];
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[5]) {
		buffer[index++] = FIRST_6BYTE(bytes[5]);
		buffer[index++] = bytes[4];
		buffer[index++] = bytes[3];
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[4]) {
		buffer[index++] = FIRST_6BYTE(bytes[4]);
		buffer[index++] = bytes[3];
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[3]) {
		buffer[index++] = FIRST_6BYTE(bytes[3]);
		buffer[index++] = bytes[2];
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[2]) {
		buffer[index++] = FIRST_6BYTE(bytes[2]);
		buffer[index++] = bytes[1];
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else if(bytes[1]) {
		buffer[index++] = FIRST_6BYTE(bytes[1]);
		buffer[index++] = LAST_6BYTE(bytes[0]);
	} else {
		buffer[index++] = ONLY_6BYTE(bytes[0]);
	}
	return bscript_write_raw_data(bstream, buffer, index);
}
EXPORT_SYMBOL_GPL(bscript_write_symmetric_u64);

bool bscript_read_symmetric_u64(struct bstream *bstream, u64 *ull)
{
	u8 byte;
	u64 result;

	// 0
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result = PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*ull = result;
		return true;
	}
	result <<= 6;

	// 1
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*ull = result;
		return true;
	}
	result <<= 6;

	// 2
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*ull = result;
		return true;
	}
	result <<= 6;

	// 3
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*ull = result;
		return true;
	}
	result <<= 6;

	// 4
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*ull = result;
		return true;
	}
	result <<= 6;

	// 5
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*ull = result;
		return true;
	}
	result <<= 6;

	// 6
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*ull = result;
		return true;
	}
	result <<= 6;

	// 7
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*ull = result;
		return true;
	}
	result <<= 6;

	// 8
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*ull = result;
		return true;
	}
	result <<= 6;

	// 9
	if (!bscript_read_u8(bstream, &byte))
		return false;
	result |= PURE_6BYTE(byte);
	if(IS_LAST_6BYTE(byte)) {
		*ull = result;
		return true;
	}
	result <<= 6;

	// 10
	if (!bscript_read_u8(bstream, &byte))
		return false;
	*ull = result | PURE_6BYTE(byte);
	return true;
}
EXPORT_SYMBOL_GPL(bscript_read_symmetric_u64);

bool bscript_write_string(struct bstream *bstream, const u8 *s)
{
	u32 size;

	if (!s)
		return bscript_write_u8(bstream, NULL_MARKER);

	size = strlen(s);
	return
		bscript_write_u32(bstream, size) &&
		(!size ||
		 bscript_write_raw_data(bstream, s, size));
}
EXPORT_SYMBOL_GPL(bscript_write_string);

bool bscript_write_data(struct bstream *bstream, const void *data, u32 size)
{
	if(!data || !size)
		return bscript_write_u8(bstream, NULL_MARKER);
	
	return
		bscript_write_u32(bstream, size) &&
		bscript_write_raw_data(bstream, data, size);
}
EXPORT_SYMBOL_GPL(bscript_write_data);
