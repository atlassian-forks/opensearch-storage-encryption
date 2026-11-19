/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.security.Provider;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import org.opensearch.index.store.key.KeyResolver;

/**
 * Creates local {@link CryptoTranslog} instances that share the index {@link KeyResolver}.
 *
 * OpenSearch 2.19 {@link TranslogFactory} is a functional interface with only the 7-arg
 * {@link #newTranslog} method. Remote-store translogs are rejected: 2.19 has no
 * {@code ChannelFactory} constructor injection, and decrypt-on-upload would write
 * plaintext temp files.
 */
public class CryptoTranslogFactory implements TranslogFactory {

    private final KeyResolver keyResolver;
    private final Provider provider;

    /**
     * @param keyResolver the unified key resolver (same as used by index files)
     * @param provider the JCE provider for translog cipher and digest
     */
    public CryptoTranslogFactory(KeyResolver keyResolver, Provider provider) {
        this.keyResolver = keyResolver;
        this.provider = Objects.requireNonNull(provider, "provider");
    }

    @Override
    public Translog newTranslog(
        TranslogConfig config,
        String translogUUID,
        TranslogDeletionPolicy deletionPolicy,
        LongSupplier globalCheckpointSupplier,
        LongSupplier primaryTermSupplier,
        LongConsumer persistedSequenceNumberConsumer,
        BooleanSupplier startedPrimarySupplier
    ) throws IOException {

        if (config.getIndexSettings().isRemoteTranslogStoreEnabled()) {
            throw new IllegalArgumentException(
                "index.store.type cryptofs does not support remote store on OpenSearch 2.19; "
                    + "use a local translog or a non-cryptofs store"
            );
        }

        return new CryptoTranslog(
            config,
            translogUUID,
            deletionPolicy,
            globalCheckpointSupplier,
            primaryTermSupplier,
            persistedSequenceNumberConsumer,
            keyResolver,
            provider
        );
    }
}
