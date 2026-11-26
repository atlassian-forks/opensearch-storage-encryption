/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import java.security.Key;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.index.store.key.KeyResolver;

public class TestKeyResolver implements KeyResolver {
    @Override
    public Key getDataKey() {
        // Deterministic weak key for benchmarks only — not for production use
        byte[] masterKey = new byte[32];
        for (int i = 0; i < 32; i++) {
            masterKey[i] = (byte) (i % 2);
        }
        return new SecretKeySpec(masterKey, "AES");
    }
}
