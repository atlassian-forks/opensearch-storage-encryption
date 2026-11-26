/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;
import java.util.Objects;

import org.apache.lucene.store.AlreadyClosedException;
import org.apache.lucene.store.IndexOutput;

/** Guards calls to an existing encrypted output, including Lucene's buffered writes. */
public final class KeyAccessIndexOutput extends IndexOutput {
    @FunctionalInterface
    public interface Abort {
        void abort() throws IOException;
    }

    private final IndexOutput delegate;
    private final Runnable accessCheck;
    private final Abort abort;
    private boolean closed;

    public KeyAccessIndexOutput(IndexOutput delegate, Runnable accessCheck, Abort abort) {
        super("key-access(" + delegate + ")", delegate.getName());
        this.delegate = Objects.requireNonNull(delegate);
        this.accessCheck = Objects.requireNonNull(accessCheck);
        this.abort = Objects.requireNonNull(abort);
    }

    private void ensureOpen() {
        if (closed) {
            throw new AlreadyClosedException("Encrypted output is closed");
        }
    }

    @Override
    public void writeByte(byte value) throws IOException {
        ensureOpen();
        accessCheck.run();
        delegate.writeByte(value);
    }

    @Override
    public void writeBytes(byte[] bytes, int offset, int length) throws IOException {
        ensureOpen();
        accessCheck.run();
        delegate.writeBytes(bytes, offset, length);
    }

    @Override
    public long getFilePointer() {
        return delegate.getFilePointer();
    }

    @Override
    public long getChecksum() throws IOException {
        ensureOpen();
        accessCheck.run();
        return delegate.getChecksum();
    }

    @Override
    public void close() throws IOException {
        if (closed)
            return;
        closed = true;
        try {
            accessCheck.run();
        } catch (RuntimeException denied) {
            try {
                abort.abort();
            } catch (IOException | RuntimeException failure) {
                denied.addSuppressed(failure);
            }
            throw denied;
        }
        delegate.close();
    }
}
