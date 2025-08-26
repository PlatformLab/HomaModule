/* SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+ */

/* This file contains a limited implementation of MurmurHash3; it is
 * used for rhashtables instead of the default jhash because it is
 * faster (25 ns. vs. 40 ns as of May 2025)
 */

/**
 * murmurhash3() - Hash function.
 * @data:    Pointer to key for which a hash is desired.
 * @len:     Length of the key; must be a multiple of 4.
 * @seed:    Seed for the hash.
 * Return:   A 32-bit hash value for the given key.
 */
static inline u32 murmurhash3(const void *data, u32 len, u32 seed)
{
	const u32 c1 = 0xcc9e2d51;
	const u32 c2 = 0x1b873593;
	const u32 *key = data;
	u32 h = seed;

	len = len >> 2;
	for (size_t i = 0; i < len; i++) {
		u32 k = key[i];

		k *= c1;
		k = (k << 15) | (k >> (32 - 15));
		k *= c2;

		h ^= k;
		h = (h << 13) | (h >> (32 - 13));
		h = h * 5 + 0xe6546b64;
	}

	/* Total number of input bytes */
	h ^= len * 4;

	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}
