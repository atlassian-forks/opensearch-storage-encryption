/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import java.io.IOException;
import java.util.Objects;

import org.apache.lucene.store.FilterIndexInput;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.RandomAccessInput;

/** Checks index key access before returning bytes from a buffered index input. */
final class KeyAccessIndexInput extends FilterIndexInput {
    private final Runnable accessCheck;

    KeyAccessIndexInput(IndexInput input, Runnable accessCheck) {
        super("key-access(" + input + ")", input);
        this.accessCheck = Objects.requireNonNull(accessCheck);
    }

    @Override
    public byte readByte() throws IOException {
        accessCheck.run();
        return in.readByte();
    }

    @Override
    public void readBytes(byte[] b, int offset, int len) throws IOException {
        accessCheck.run();
        in.readBytes(b, offset, len);
    }

    @Override
    public short readShort() throws IOException {
        accessCheck.run();
        return in.readShort();
    }

    @Override
    public int readInt() throws IOException {
        accessCheck.run();
        return in.readInt();
    }

    @Override
    public long readLong() throws IOException {
        accessCheck.run();
        return in.readLong();
    }

    @Override
    public int readVInt() throws IOException {
        accessCheck.run();
        return in.readVInt();
    }

    @Override
    public long readVLong() throws IOException {
        accessCheck.run();
        return in.readVLong();
    }

    @Override
    public int readZInt() throws IOException {
        accessCheck.run();
        return in.readZInt();
    }

    @Override
    public long readZLong() throws IOException {
        accessCheck.run();
        return in.readZLong();
    }

    @Override
    public String readString() throws IOException {
        accessCheck.run();
        return in.readString();
    }

    @Override
    public void readInts(int[] values, int offset, int length) throws IOException {
        accessCheck.run();
        in.readInts(values, offset, length);
    }

    @Override
    public void readLongs(long[] values, int offset, int length) throws IOException {
        accessCheck.run();
        in.readLongs(values, offset, length);
    }

    @Override
    public void readFloats(float[] values, int offset, int length) throws IOException {
        accessCheck.run();
        in.readFloats(values, offset, length);
    }

    @Override
    public void readGroupVInt(int[] values, int offset) throws IOException {
        accessCheck.run();
        in.readGroupVInt(values, offset);
    }

    @Override
    public void readBytes(byte[] values, int offset, int length, boolean useBuffer) throws IOException {
        accessCheck.run();
        in.readBytes(values, offset, length, useBuffer);
    }

    @Override
    public KeyAccessIndexInput clone() {
        return new KeyAccessIndexInput(in.clone(), accessCheck);
    }

    @Override
    public IndexInput slice(String description, long offset, long length) throws IOException {
        return new KeyAccessIndexInput(in.slice(description, offset, length), accessCheck);
    }

    @Override
    public RandomAccessInput randomAccessSlice(long offset, long length) throws IOException {
        RandomAccessInput random = in.randomAccessSlice(offset, length);
        return new RandomAccessInput() {
            @Override
            public long length() {
                return random.length();
            }

            @Override
            public byte readByte(long pos) throws IOException {
                accessCheck.run();
                return random.readByte(pos);
            }

            @Override
            public short readShort(long pos) throws IOException {
                accessCheck.run();
                return random.readShort(pos);
            }

            @Override
            public int readInt(long pos) throws IOException {
                accessCheck.run();
                return random.readInt(pos);
            }

            @Override
            public long readLong(long pos) throws IOException {
                accessCheck.run();
                return random.readLong(pos);
            }

            @Override
            public void readBytes(long pos, byte[] b, int off, int len) throws IOException {
                accessCheck.run();
                random.readBytes(pos, b, off, len);
            }
        };
    }
}
