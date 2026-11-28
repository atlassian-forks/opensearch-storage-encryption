/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.security.Security;

import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.test.OpenSearchTestCase;

public class EncryptionMetadataCacheRegistryTests extends OpenSearchTestCase {
    public void testInvalidateIndexClearsOnlyThatIndexAcrossShards() {
        var a0 = EncryptionMetadataCacheRegistry.getOrCreateCache("tenant-a", 0, "a");
        var a1 = EncryptionMetadataCacheRegistry.getOrCreateCache("tenant-a", 1, "a");
        var b0 = EncryptionMetadataCacheRegistry.getOrCreateCache("tenant-b", 0, "b");
        byte[] iv = new byte[] { 1 };
        a0.putFrameIv("file", 0, iv);
        a1.putFrameIv("file", 0, iv);
        b0.putFrameIv("file", 0, iv);
        var footer = new EncryptionFooter(new byte[16], 8192, (short) 1);
        var provider = Security.getProvider("SunJCE");
        a0.getOrLoadMetadata("file", footer, new byte[32], provider);
        b0.getOrLoadMetadata("file", footer, new byte[32], provider);
        assertNotNull(a0.getFileKey("file"));
        assertNotNull(b0.getFileKey("file"));
        try {
            EncryptionMetadataCacheRegistry.invalidateIndex("tenant-a");
            assertNull(a0.getFrameIv("file", 0));
            assertNull(a1.getFrameIv("file", 0));
            assertNull(a0.getFileKey("file"));
            assertNotNull(b0.getFileKey("file"));
            assertArrayEquals(iv, b0.getFrameIv("file", 0));
            assertSame(a0, EncryptionMetadataCacheRegistry.getOrCreateCache("tenant-a", 0, "a"));
        } finally {
            EncryptionMetadataCacheRegistry.removeCache("tenant-a", 0, "a");
            EncryptionMetadataCacheRegistry.removeCache("tenant-a", 1, "a");
            EncryptionMetadataCacheRegistry.removeCache("tenant-b", 0, "b");
        }
    }
}
