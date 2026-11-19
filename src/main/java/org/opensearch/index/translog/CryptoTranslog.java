/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.index.store.key.KeyResolver;

/**
 * A Translog implementation that provides AES-GCM encryption capabilities.
 *
 * This class extends LocalTranslog and overrides {@link #getChannelFactory()} so that
 * translog file operations go through encrypted channels. OpenSearch 2.19 constructors
 * do not accept a ChannelFactory; LocalTranslog calls {@code getChannelFactory()} while
 * creating the writer (including during {@code super()}), so the factory is bound on a
 * ThreadLocal for the duration of construction.
 *
 * Translog files (.tlog) are encrypted using AES-GCM with 8KB authenticated chunks.
 * Each chunk includes a 16-byte authentication tag for data integrity verification.
 * Checkpoint files (.ckp) remain unencrypted for performance and compatibility.
 *
 * Uses unified KeyResolver (same as index files) for consistent
 * key management across all encrypted components.
 *
 * @opensearch.internal
 */
public class CryptoTranslog extends LocalTranslog {

    private static final Logger logger = LogManager.getLogger(CryptoTranslog.class);

    /**
     * Holds the factory while {@code LocalTranslog}'s constructor calls
     * {@link #getChannelFactory()} before subclass fields are assigned.
     */
    private static final ThreadLocal<CryptoChannelFactory> FACTORY_DURING_SUPER = new ThreadLocal<>();

    private final CryptoChannelFactory channelFactory;

    /**
     * Creates a new CryptoTranslog with AES-GCM encryption.
     *
     * @param config the translog configuration
     * @param translogUUID the translog UUID
     * @param deletionPolicy the deletion policy
     * @param globalCheckpointSupplier the global checkpoint supplier
     * @param primaryTermSupplier the primary term supplier
     * @param persistedSequenceNumberConsumer the persisted sequence number consumer
     * @param keyResolver the key resolver for encryption (unified with index files)
     * @param provider the JCE provider for translog cipher and digest
     * @throws IOException if translog creation fails
     */
    public CryptoTranslog(
        TranslogConfig config,
        String translogUUID,
        TranslogDeletionPolicy deletionPolicy,
        LongSupplier globalCheckpointSupplier,
        LongSupplier primaryTermSupplier,
        LongConsumer persistedSequenceNumberConsumer,
        KeyResolver keyResolver,
        Provider provider
    )
        throws IOException {
        this(
            config,
            translogUUID,
            deletionPolicy,
            globalCheckpointSupplier,
            primaryTermSupplier,
            persistedSequenceNumberConsumer,
            keyResolver,
            bindFactory(keyResolver, translogUUID, provider)
        );
    }

    private CryptoTranslog(
        TranslogConfig config,
        String translogUUID,
        TranslogDeletionPolicy deletionPolicy,
        LongSupplier globalCheckpointSupplier,
        LongSupplier primaryTermSupplier,
        LongConsumer persistedSequenceNumberConsumer,
        KeyResolver keyResolver,
        CryptoChannelFactory factory
    )
        throws IOException {
        super(config, translogUUID, deletionPolicy, globalCheckpointSupplier, primaryTermSupplier, persistedSequenceNumberConsumer);
        try {
            if (keyResolver == null || translogUUID == null) {
                throw new IllegalArgumentException(
                    "Cannot create CryptoTranslog without keyResolver and translogUUID. "
                        + "Required for translog encryption. keyResolver="
                        + keyResolver
                        + ", translogUUID="
                        + translogUUID
                );
            }
            this.channelFactory = factory;
            logger.debug("CryptoTranslog initialized for translog: {}", translogUUID);
        } finally {
            FACTORY_DURING_SUPER.remove();
        }
    }

    /**
     * Bind the crypto factory on this thread before {@code super()} so
     * {@link #getChannelFactory()} can return it while the parent opens files.
     */
    private static CryptoChannelFactory bindFactory(KeyResolver keyResolver, String translogUUID, Provider provider) throws IOException {
        FACTORY_DURING_SUPER.remove();
        CryptoChannelFactory factory = createCryptoChannelFactory(keyResolver, translogUUID, provider);
        FACTORY_DURING_SUPER.set(factory);
        return factory;
    }

    /**
     * Helper method to create CryptoChannelFactory for constructor use.
     */
    private static CryptoChannelFactory createCryptoChannelFactory(KeyResolver keyResolver, String translogUUID, Provider provider)
        throws IOException {
        try {
            return new CryptoChannelFactory(keyResolver, translogUUID, provider);
        } catch (Exception e) {
            throw new IOException(
                "Failed to initialize crypto channel factory for translog encryption. " + "Cannot proceed without encryption!",
                e
            );
        }
    }

    @Override
    ChannelFactory getChannelFactory() {
        CryptoChannelFactory factory = this.channelFactory;
        if (factory == null) {
            factory = FACTORY_DURING_SUPER.get();
        }
        if (factory == null) {
            throw new IllegalStateException("CryptoChannelFactory is not initialized");
        }
        return factory;
    }

    /**
     * OpenSearch 2.19 {@link Translog#openReader} uses {@code FileChannel.open} directly.
     * Route recovery reads through the crypto factory so existing encrypted generations
     * can be decrypted.
     */
    @Override
    TranslogReader openReader(Path path, Checkpoint checkpoint) throws IOException {
        FileChannel channel = getChannelFactory().open(path, StandardOpenOption.READ);
        try {
            assert Translog.parseIdFromFileName(path) == checkpoint.generation : "expected generation: "
                + Translog.parseIdFromFileName(path)
                + " but got: "
                + checkpoint.generation;
            TranslogReader reader = TranslogReader.open(channel, path, checkpoint, translogUUID);
            channel = null;
            return reader;
        } finally {
            IOUtils.close(channel);
        }
    }
}
