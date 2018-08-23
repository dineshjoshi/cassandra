/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cassandra.transport.frame.checksum;

import java.io.IOException;
import java.util.EnumSet;

import com.google.common.collect.ImmutableTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.transport.Frame;
import org.apache.cassandra.transport.frame.FrameBodyTransformer;
import org.apache.cassandra.transport.frame.compress.Compressor;
import org.apache.cassandra.transport.frame.compress.LZ4Compressor;
import org.apache.cassandra.transport.frame.compress.SnappyCompressor;
import org.apache.cassandra.utils.ChecksumType;

/**
 * Provides a format that implements chunking and checksumming logic
 * that maybe used in conjunction with a frame Compressor if required
 * <p>
 * <strong>1.1. Checksummed/Compression Serialized Format</strong>
 * <p>
 * <pre>
 * {@code
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Number of Compressed Chunks  |     Compressed Length (e1)    /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /  Compressed Length cont. (e1) |    Uncompressed Length (e1)   /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Uncompressed Length cont. (e1)|    Checksum of Lengths (e1)   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Checksum of Lengths cont. (e1)|    Compressed Bytes (e1)    +//
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Checksum (e1)                        ||
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Compressed Length (e2)                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Uncompressed Length (e2)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Checksum of Lengths (e2)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Compressed Bytes (e2)                   +//
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Checksum (e2)                        ||
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Compressed Length (en)                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Uncompressed Length (en)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Checksum of Lengths (en)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Compressed Bytes (en)                  +//
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Checksum (en)                        ||
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * }
 * </pre>
 * <p>
 * <p>
 * <strong>1.2. Checksum Compression Description</strong>
 * <p>
 * The entire cpayload is broken into n chunks each with a pair of checksums:
 * <ul>
 * <li>[int]: compressed length of serialized bytes for this chunk (e.g. the length post compression)
 * <li>[int]: expected length of the decompressed bytes (e.g. the length after decompression)
 * <li>[int]: digest of decompressed and compressed length components above
 * <li>[k bytes]: compressed payload for this chunk
 * <li>[int]: digest of the decompressed result of the payload above for this chunk
 * </ul>
 * <p>
 */
public class ChecksummingTransformer implements FrameBodyTransformer
{
    private static final Logger logger = LoggerFactory.getLogger(ChecksummingTransformer.class);

    private static final EnumSet<Frame.Header.Flag> CHECKSUMS_ONLY = EnumSet.of(Frame.Header.Flag.CHECKSUMMED);
    private static final EnumSet<Frame.Header.Flag> CHECKSUMS_AND_COMPRESSION = EnumSet.of(Frame.Header.Flag.CHECKSUMMED, Frame.Header.Flag.COMPRESSED);

    private static final int CHUNK_HEADER_OVERHEAD = Integer.BYTES + Integer.BYTES + Integer.BYTES + Integer.BYTES;

    private static final ChecksummingTransformer CRC32_NO_COMPRESSION = new ChecksummingTransformer(ChecksumType.CRC32, null);
    private static final ChecksummingTransformer ADLER32_NO_COMPRESSION = new ChecksummingTransformer(ChecksumType.Adler32, null);
    private static final ImmutableTable<ChecksumType, Compressor, ChecksummingTransformer> transformers;
    static
    {
        ImmutableTable.Builder<ChecksumType, Compressor, ChecksummingTransformer> builder = ImmutableTable.builder();
        builder.put(ChecksumType.CRC32, LZ4Compressor.INSTANCE, new ChecksummingTransformer(ChecksumType.CRC32, LZ4Compressor.INSTANCE));
        builder.put(ChecksumType.CRC32, SnappyCompressor.INSTANCE, new ChecksummingTransformer(ChecksumType.CRC32, SnappyCompressor.INSTANCE));
        builder.put(ChecksumType.Adler32, LZ4Compressor.INSTANCE, new ChecksummingTransformer(ChecksumType.Adler32, LZ4Compressor.INSTANCE));
        builder.put(ChecksumType.Adler32, SnappyCompressor.INSTANCE, new ChecksummingTransformer(ChecksumType.Adler32, SnappyCompressor.INSTANCE));
        transformers = builder.build();
    }

    private final int blockSize;
    private final Compressor compressor;
    private final ChecksumType checksum;

    public static ChecksummingTransformer getTransformer(ChecksumType checksumType, Compressor compressor)
    {
        ChecksummingTransformer transformer = compressor == null
                                              ? checksumType == ChecksumType.CRC32 ? CRC32_NO_COMPRESSION : ADLER32_NO_COMPRESSION
                                              : transformers.get(checksumType, compressor);

        if (transformer == null)
        {
            logger.warn("Invalid compression/checksum options supplied. %s / %s", checksumType, compressor.getClass().getName());
            throw new RuntimeException("Invalid compression / checksum options supplied");
        }

        return transformer;
    }

    ChecksummingTransformer(ChecksumType checksumType, Compressor compressor)
    {
        this(checksumType, DatabaseDescriptor.getNativeTransportFrameBlockSize(), compressor);
    }

    ChecksummingTransformer(ChecksumType checksumType, int blockSize, Compressor compressor)
    {
        this.checksum = checksumType;
        this.blockSize = blockSize;
        this.compressor = compressor;
    }

    public EnumSet<Frame.Header.Flag> getOutboundHeaderFlags()
    {
        return null == compressor ? CHECKSUMS_ONLY : CHECKSUMS_AND_COMPRESSION;
    }

    public ByteBuf transformOutbound(ByteBuf inputBuf) throws IOException
    {
        // be pessimistic about life and assume the compressed output will be the same size as the input bytes
        int maxTotalCompressedLength = maxCompressedLength(inputBuf.readableBytes());
        int expectedChunks = (int) Math.ceil((double) maxTotalCompressedLength / blockSize);
        int expectedMaxSerializedLength = Short.BYTES + (expectedChunks * CHUNK_HEADER_OVERHEAD) + maxTotalCompressedLength;
        byte[] retBuf = new byte[expectedMaxSerializedLength];
        ByteBuf ret = Unpooled.wrappedBuffer(retBuf);
        ret.writerIndex(0);
        ret.readerIndex(0);

        // write out bogus short to start with to pre-allocate space as we'll encode one at the end when we finalize
        // for the number of compressed chunks to expect
        ret.writeShort((short) 0);

        byte[] inBuf = new byte[blockSize];
        byte[] outBuf = new byte[maxCompressedLength(blockSize)];
        byte[] chunkLengths = new byte[2];

        int numCompressedChunks = 0;
        int readableBytes;
        while ((readableBytes = inputBuf.readableBytes()) > 0)
        {
            int lengthToRead = Math.min(blockSize, readableBytes);
            inputBuf.readBytes(inBuf, 0, lengthToRead);
            int written = maybeCompress(inBuf, lengthToRead, outBuf);
            int uncompressedChunkChecksum = (int) checksum.of(inBuf, 0, lengthToRead);

            if (ret.writableBytes() < (CHUNK_HEADER_OVERHEAD + written))
            {
                // this really shouldn't ever happen -- it means we either mis-calculated the number of chunks we
                // expected to create, we gave some input to the compressor that caused the output to be much
                // larger than the input.. or some other edge condition. Regardless -- resize if necessary.
                byte[] resizedRetBuf = new byte[(retBuf.length + (CHUNK_HEADER_OVERHEAD + written)) * 3 / 2];
                System.arraycopy(retBuf, 0, resizedRetBuf, 0, retBuf.length);
                retBuf = resizedRetBuf;
                ByteBuf resizedRetByteBuf = Unpooled.wrappedBuffer(retBuf);
                resizedRetByteBuf.writerIndex(ret.writerIndex());
                ret = resizedRetByteBuf;
            }

            ret.writeInt(written); // compressed length of chunk
            ret.writeInt(lengthToRead); // uncompressed length of chunk

            // calculate the checksum of the compressed and decompressed lengths
            // protect us against a bogus length causing potential havoc on deserialization
            chunkLengths[0] = (byte) written;
            chunkLengths[1] = (byte) lengthToRead;
            int lengthsChecksum = (int) checksum.of(chunkLengths, 0, 2);
            ret.writeInt(lengthsChecksum);

            ret.writeBytes(outBuf, 0, written); // the actual content bytes, possibly compressed
            ret.writeInt(uncompressedChunkChecksum); // crc32 checksum calculated for source bytes

            numCompressedChunks++;
        }
        ret.setShort(0, (short) numCompressedChunks);

        return ret;
    }

    public ByteBuf transformInbound(ByteBuf inputBuf, EnumSet<Frame.Header.Flag> flags) throws IOException
    {
        int numChunks = readUnsignedShort(inputBuf);

        int currentPosition = 0;

        byte[] buf = null;
        byte[] retBuf = new byte[inputBuf.readableBytes()];
        byte[] chunkLengths = new byte[2];
        for (int i = 0; i < numChunks; i++)
        {
            int compressedLength = inputBuf.readInt();
            int decompressedLength = inputBuf.readInt();
            int lengthsChecksum = inputBuf.readInt();
            chunkLengths[0] = (byte) compressedLength;
            chunkLengths[1] = (byte) decompressedLength;

            // calculate checksum on lengths (decompressed and compressed) and make sure it matches
            int calculatedLengthsChecksum = (int) checksum.of(chunkLengths, 0, 2);
            // make sure checksum on lengths match
            if (lengthsChecksum != calculatedLengthsChecksum)
            {
                throw new IOException(String.format("Checksum invalid on chunk bytes lengths. Deserialized compressed " +
                                                    "length: %d decompressed length: %d. %d != %d", compressedLength,
                                                    decompressedLength, lengthsChecksum, calculatedLengthsChecksum));
            }

            if (currentPosition + decompressedLength > retBuf.length)
            {
                byte[] resizedBuf = new byte[retBuf.length + decompressedLength * 3 / 2];
                System.arraycopy(retBuf, 0, resizedBuf, 0, retBuf.length);
                retBuf = resizedBuf;
            }

            if (buf == null || buf.length < compressedLength)
            {
                buf = new byte[compressedLength];
            }

            // get the compressed bytes for this chunk
            inputBuf.readBytes(buf, 0, compressedLength);
            // decompress it
            byte[] decompressedChunk = maybeDecompress(buf, compressedLength, decompressedLength, flags);
            // add the decompressed bytes into the ret buf
            System.arraycopy(decompressedChunk, 0, retBuf, currentPosition, decompressedLength);
            currentPosition += decompressedLength;

            // get the checksum of the decompressed bytes as calculated when serialized
            int expectedDecompressedChecksum = inputBuf.readInt();
            // calculate a crc32 checksum of the decompressed bytes we got
            int calculatedDecompressedChecksum = (int) checksum.of(decompressedChunk, 0, decompressedLength);
            // make sure they match
            if (expectedDecompressedChecksum != calculatedDecompressedChecksum)
            {
                throw new IOException("Decompressed checksum for chunk does not match expected checksum");
            }
        }

        ByteBuf ret = Unpooled.wrappedBuffer(retBuf, 0, currentPosition);
        ret.writerIndex(currentPosition);
        return ret;
    }

    private int maxCompressedLength(int uncompressedLength)
    {
        return null == compressor ? uncompressedLength : compressor.maxCompressedLength(uncompressedLength);

    }

    private int maybeCompress(byte[] input, int length, byte[] output) throws IOException
    {
        if (null == compressor)
        {
            System.arraycopy(input, 0, output, 0, length);
            return length;
        }

        return compressor.compress(input, 0, length, output, 0);
    }

    private byte[] maybeDecompress(byte[] input, int length, int expectedLength, EnumSet<Frame.Header.Flag> flags) throws IOException
    {
        if (null == compressor || !flags.contains(Frame.Header.Flag.COMPRESSED))
            return input;

        return compressor.decompress(input, 0, length, expectedLength);
    }

    private static int readUnsignedShort(ByteBuf buf) throws IOException
    {
        int ch1 = buf.readByte() & 0xFF;
        int ch2 = buf.readByte() & 0xFF;
        if ((ch1 | ch2) < 0)
            throw new IOException("Failed to read unsigned short as deserialized value is bogus/negative");
        return (ch1 << 8) + (ch2);
    }
}
