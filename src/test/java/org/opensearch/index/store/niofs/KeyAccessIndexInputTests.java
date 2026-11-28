/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.lucene.store.ByteBuffersDirectory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.opensearch.test.OpenSearchTestCase;

public class KeyAccessIndexInputTests extends OpenSearchTestCase {
    public void testPrimitiveAndBulkReadsCheckAccessOnce() throws Exception {
        AtomicInteger checks = new AtomicInteger();
        AtomicBoolean allowed = new AtomicBoolean(true);
        try (var dir = new ByteBuffersDirectory()) {
            try (var output = dir.createOutput("file", IOContext.DEFAULT)) {
                output.writeLong(0x0123456789ABCDEFL);
                output.writeVInt(300);
                output.writeInt(42);
                output.writeInt(73);
            }
            try (IndexInput input = new KeyAccessIndexInput(dir.openInput("file", IOContext.DEFAULT), () -> {
                checks.incrementAndGet();
                if (!allowed.get()) {
                    throw new SecurityException("revoked");
                }
            })) {
                assertEquals(0x0123456789ABCDEFL, input.readLong());
                assertEquals(1, checks.get());
                assertEquals(300, input.readVInt());
                assertEquals(2, checks.get());

                int[] values = new int[2];
                long position = input.getFilePointer();
                allowed.set(false);
                expectThrows(SecurityException.class, () -> input.readInts(values, 0, values.length));
                assertEquals(position, input.getFilePointer());
                assertArrayEquals(new int[2], values);
                assertEquals(3, checks.get());

                allowed.set(true);
                input.readInts(values, 0, values.length);
                assertArrayEquals(new int[] { 42, 73 }, values);
                assertEquals(4, checks.get());
            }
        }
    }

    public void testRevocationCoversExistingInputCloneSliceAndRandomReads() throws Exception {
        var allowed = new AtomicBoolean(true);
        Runnable check = () -> {
            if (!allowed.get())
                throw new SecurityException("revoked");
        };
        try (var dir = new ByteBuffersDirectory()) {
            try (var output = dir.createOutput("file", IOContext.DEFAULT)) {
                output.writeBytes(new byte[] { 1, 2, 3, 4 }, 4);
            }
            try (
                IndexInput input = new KeyAccessIndexInput(dir.openInput("file", IOContext.DEFAULT), check);
                IndexInput clone = input.clone();
                IndexInput slice = input.slice("slice", 0, 4)
            ) {
                var random = input.randomAccessSlice(0, 4);
                assertEquals((byte) 1, input.readByte());
                allowed.set(false);
                expectThrows(SecurityException.class, () -> input.readByte());
                expectThrows(SecurityException.class, () -> clone.readByte());
                expectThrows(SecurityException.class, () -> slice.readByte());
                expectThrows(SecurityException.class, () -> random.readByte(0));
                allowed.set(true);
                assertEquals((byte) 2, input.readByte());
            }
        }
    }
}
