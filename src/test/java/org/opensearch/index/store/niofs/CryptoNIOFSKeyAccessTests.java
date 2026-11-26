/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import static org.mockito.Mockito.mock;

import java.nio.file.Files;
import java.security.Key;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.store.AlreadyClosedException;
import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IOContext;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.test.OpenSearchTestCase;

public class CryptoNIOFSKeyAccessTests extends OpenSearchTestCase {
    public void testKeyLoadFailureDoesNotLeaveAnOutputFile() throws Exception {
        var allowed = new AtomicBoolean(false);
        var key = new SecretKeySpec(randomByteArrayOfLength(32), "AES");
        KeyResolver resolver = new KeyResolver() {
            @Override
            public void checkAccess() {
                // Admission passed before access changed.
            }

            @Override
            public Key getDataKey() {
                if (!allowed.get()) {
                    throw new SecurityException("revoked");
                }
                return key;
            }
        };
        CryptoMetricsService.initialize(mock(MetricsRegistry.class));
        try (
            var directory = new CryptoNIOFSDirectory(
                FSLockFactory.getDefault(),
                createTempDir(),
                Security.getProvider("SunJCE"),
                resolver,
                new EncryptionMetadataCache()
            )
        ) {
            String[] initialFiles = directory.listAll();
            expectThrows(SecurityException.class, () -> directory.createOutput("retry.fdt", IOContext.DEFAULT));
            expectThrows(SecurityException.class, () -> directory.createTempOutput("retry", "fdt", IOContext.DEFAULT));
            assertArrayEquals(initialFiles, directory.listAll());

            allowed.set(true);
            try (var output = directory.createOutput("retry.fdt", IOContext.DEFAULT)) {
                output.writeByte((byte) 42);
            }
            try (var input = directory.openInput("retry.fdt", IOContext.DEFAULT)) {
                assertEquals((byte) 42, input.readByte());
            }
        }
    }

    public void testExistingOutputsAndReadersHonorTenantKeyAccess() throws Exception {
        AtomicBoolean allowed = new AtomicBoolean(true);
        var key = new SecretKeySpec(randomByteArrayOfLength(32), "AES");
        KeyResolver resolver = () -> {
            if (!allowed.get())
                throw new SecurityException("revoked");
            return key;
        };
        KeyResolver otherResolver = () -> key;
        CryptoMetricsService.initialize(mock(MetricsRegistry.class));
        try (
            var a = new CryptoNIOFSDirectory(
                FSLockFactory.getDefault(),
                createTempDir(),
                Security.getProvider("SunJCE"),
                resolver,
                new EncryptionMetadataCache()
            );
            var b = new CryptoNIOFSDirectory(
                FSLockFactory.getDefault(),
                createTempDir(),
                Security.getProvider("SunJCE"),
                otherResolver,
                new EncryptionMetadataCache()
            )
        ) {
            var out = a.createOutput("resume.fdt", IOContext.DEFAULT);
            var other = b.createOutput("other.fdt", IOContext.DEFAULT);
            out.writeByte((byte) 11);
            allowed.set(false);
            expectThrows(SecurityException.class, () -> out.writeByte((byte) 12));
            expectThrows(SecurityException.class, () -> out.writeBytes(new byte[] { 12 }, 1));
            expectThrows(SecurityException.class, out::getChecksum);
            other.writeByte((byte) 42);
            other.close();
            allowed.set(true);
            out.writeByte((byte) 13);
            out.close();
            try (var in = a.openInput("resume.fdt", IOContext.DEFAULT); var bin = b.openInput("other.fdt", IOContext.DEFAULT)) {
                assertEquals((byte) 11, in.readByte());
                allowed.set(false);
                expectThrows(SecurityException.class, in::readByte);
                assertEquals((byte) 42, bin.readByte());
                allowed.set(true);
                assertEquals((byte) 13, in.readByte());
            }
            var aborted = a.createTempOutput("aborted", "fdt", IOContext.DEFAULT);
            aborted.writeBytes(new byte[100_000], 100_000);
            aborted.writeByte((byte) 99);
            var path = a.getDirectory().resolve(aborted.getName());
            long size = Files.size(path);
            allowed.set(false);
            expectThrows(SecurityException.class, aborted::close);
            assertEquals(size, Files.size(path));
            allowed.set(true);
            expectThrows(AlreadyClosedException.class, () -> aborted.writeByte((byte) 100));
            a.deleteFile(aborted.getName());
        }
    }
}
