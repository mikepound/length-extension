package uk.ac.nottingham.cryptography.hashing;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.Queue;


public class PaddedInputStream extends InputStream {
    static final int BLOCK_LENGTH = 64;
    byte[] buffer;
    InputStream source;
    int totalSize = 0;
    boolean streamExhausted;
    Queue<byte[]> paddingBytes;

    public PaddedInputStream(InputStream source) {
        this.buffer = new byte[BLOCK_LENGTH];
        this.source = source;

        try {
            if (this.source.available() > 0) {
                this.streamExhausted = false;
            }
        } catch (IOException ex) {
            this.streamExhausted = true;
        }
        this.paddingBytes = new LinkedList<byte[]>();
    }

    public PaddedInputStream(InputStream source, int initialSize) {
        this(source);
        this.totalSize = initialSize;
    }

    @Override
    public int read() throws IOException {
        throw new IOException("Output via read() not supported");
    }

    @Override
    public int read(byte[] buffer) throws IOException {

        // If stream is already finished, serve any remaining padding blocks
        if (this.streamExhausted) {
            if (this.paddingBytes.size() > 0) {
                byte[] paddingBlock = this.paddingBytes.poll();
                System.arraycopy(paddingBlock,0,buffer,0,BLOCK_LENGTH);
                return BLOCK_LENGTH;
            } else {
                return -1;
            }
        }

        // Read from stream
        int bytesRead = this.source.read(this.buffer, 0, BLOCK_LENGTH);

        if (bytesRead == BLOCK_LENGTH) {
            // Stream has enough data
            System.arraycopy(this.buffer, 0, buffer, 0, BLOCK_LENGTH);
            totalSize += bytesRead;
            return bytesRead;
        } else if (bytesRead > 0) {
            // Stream has returned a partial block
            totalSize += bytesRead;

            this.paddingBytes = padMessage(this.buffer, bytesRead, totalSize);
            // Add padding and create final i+1 block if needed

            if (this.paddingBytes.size() > 0) {
                byte[] paddingBlock = this.paddingBytes.poll();
                System.arraycopy(paddingBlock,0,buffer,0,BLOCK_LENGTH);
                this.streamExhausted = true;
                return BLOCK_LENGTH;
            }

            return -1;
        } else {
            // Only occurs when data is exact multiple of block size
            this.paddingBytes = padMessage(this.buffer, 0, totalSize);

            if (this.paddingBytes.size() > 0) {
                byte[] paddingBlock = this.paddingBytes.poll();
                System.arraycopy(paddingBlock,0,buffer,0,BLOCK_LENGTH);
                this.streamExhausted = true;
                return BLOCK_LENGTH;
            }

            return -1;
        }
    }

    @Override
    public byte[] readAllBytes() throws IOException {
        throw new IOException("Output via readAllBytes() not supported");
    }

    private Queue<byte[]> padMessage(byte[] block, int blockLength, int messageLength) throws IOException {
        // Calculates appropriate padding and adds blocks into a queue
        Queue<byte[]> paddingBlocks = new LinkedList<>();

        int blockBitLength = blockLength * 8;
        int messageBitLength = messageLength * 8;

        int padBitLength = Math.floorMod(512 - 1 - 64 - blockBitLength, 512);

        int totalBitLength = blockBitLength + padBitLength + 1 + 64;
        // There should be either one or two blocks of padding
        if (totalBitLength != 512 && totalBitLength != 1024) {
            throw new IOException("Error calculating padding size");
        }

        if (totalBitLength == 512) {
            byte[] paddingBlock = new byte[BLOCK_LENGTH];
            System.arraycopy(block, 0, paddingBlock, 0, blockLength);
            paddingBlock[blockLength] = (byte)0b10000000;
            byte[] lenBytes = ByteBuffer.allocate(8).putLong(messageBitLength).array();

            System.arraycopy(lenBytes, 0, paddingBlock, block.length - 8, 8);
            paddingBlocks.add(paddingBlock);

            return paddingBlocks;
        } else {
            byte[] paddingBlock1 = new byte[BLOCK_LENGTH];

            System.arraycopy(block, 0, paddingBlock1, 0, blockLength);
            paddingBlock1[blockLength] = (byte)0b10000000;

            byte[] paddingBlock2 = new byte[BLOCK_LENGTH];
            byte[] lenBytes = ByteBuffer.allocate(8).putLong(messageBitLength).array();
            System.arraycopy(lenBytes, 0, paddingBlock2, block.length - 8, 8);

            paddingBlocks.add(paddingBlock1);
            paddingBlocks.add(paddingBlock2);

            return paddingBlocks;
        }
    }

    @Override
    public void close() throws IOException {
        this.source.close();
    }
}
