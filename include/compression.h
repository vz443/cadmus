#ifndef CADMUS_COMPRESSION_H
#define CADMUS_COMPRESSION_H

/* Run-length encoding helpers for document payload compression. */

#include "types.h"

/* Compress a buffer with RLE. */
CadmusError compression_rle_compress(const cadmus_u8 *in,
                                     cadmus_u32 in_len,
                                     cadmus_u8 **out,
                                     cadmus_u32 *out_len);

/* Decompress an RLE buffer back to its expected size. */
CadmusError compression_rle_decompress(const cadmus_u8 *in,
                                       cadmus_u32 in_len,
                                       cadmus_u32 expected_len,
                                       cadmus_u8 **out,
                                       cadmus_u32 *out_len);

#endif /* CADMUS_COMPRESSION_H */
