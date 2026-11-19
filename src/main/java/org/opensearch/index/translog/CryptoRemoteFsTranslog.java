/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.opensearch.index.remote.RemoteStoreEnums.DataCategory.TRANSLOG;
import static org.opensearch.index.remote.RemoteStoreEnums.DataType.DATA;
import static org.opensearch.index.remote.RemoteStoreEnums.DataType.METADATA;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.blobstore.BlobPath;
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.remote.RemoteStorePathStrategy;
import org.opensearch.index.remote.RemoteTranslogTransferTracker;
import org.opensearch.index.store.PrivilegedAccess;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.translog.transfer.BlobStoreTransferService;
import org.opensearch.index.translog.transfer.FileTransferTracker;
import org.opensearch.index.translog.transfer.TranslogTransferManager;
import org.opensearch.indices.RemoteStoreSettings;
import org.opensearch.repositories.blobstore.BlobStoreRepository;
import org.opensearch.threadpool.ThreadPool;

/**
 * A RemoteFsTranslog implementation that provides AES-GCM encryption capabilities
 * with decrypt-before-upload for remote store.
 *
 * OpenSearch 2.19 {@link RemoteFsTranslog} takes 11 constructor arguments and has no
 * ChannelFactory parameter. Encryption is injected by overriding
 * {@link #getChannelFactory()}.
 *
 * @opensearch.internal
 */
public class CryptoRemoteFsTranslog extends RemoteFsTranslog {

    private static final Logger logger = LogManager.getLogger(CryptoRemoteFsTranslog.class);

    /**
     * Holds the factory while {@code RemoteFsTranslog}'s constructor calls
     * {@link #getChannelFactory()} before subclass fields are assigned.
     */
    private static final ThreadLocal<CryptoChannelFactory> FACTORY_DURING_SUPER = new ThreadLocal<>();

    private final CryptoChannelFactory cryptoFactory;

    public CryptoRemoteFsTranslog(
        TranslogConfig config,
        String translogUUID,
        TranslogDeletionPolicy deletionPolicy,
        LongSupplier globalCheckpointSupplier,
        LongSupplier primaryTermSupplier,
        LongConsumer persistedSequenceNumberConsumer,
        BlobStoreRepository blobStoreRepository,
        ThreadPool threadPool,
        BooleanSupplier startedPrimarySupplier,
        RemoteTranslogTransferTracker remoteTranslogTransferTracker,
        RemoteStoreSettings remoteStoreSettings,
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
            blobStoreRepository,
            threadPool,
            startedPrimarySupplier,
            remoteTranslogTransferTracker,
            remoteStoreSettings,
            keyResolver,
            bindFactory(keyResolver, translogUUID, provider)
        );
    }

    private CryptoRemoteFsTranslog(
        TranslogConfig config,
        String translogUUID,
        TranslogDeletionPolicy deletionPolicy,
        LongSupplier globalCheckpointSupplier,
        LongSupplier primaryTermSupplier,
        LongConsumer persistedSequenceNumberConsumer,
        BlobStoreRepository blobStoreRepository,
        ThreadPool threadPool,
        BooleanSupplier startedPrimarySupplier,
        RemoteTranslogTransferTracker remoteTranslogTransferTracker,
        RemoteStoreSettings remoteStoreSettings,
        KeyResolver keyResolver,
        CryptoChannelFactory factory
    )
        throws IOException {
        super(
            config,
            translogUUID,
            deletionPolicy,
            globalCheckpointSupplier,
            primaryTermSupplier,
            persistedSequenceNumberConsumer,
            blobStoreRepository,
            threadPool,
            startedPrimarySupplier,
            remoteTranslogTransferTracker,
            remoteStoreSettings
        );
        try {
            this.cryptoFactory = factory;

            TranslogTransferManager decryptingManager = createDecryptingTranslogTransferManager(
                blobStoreRepository,
                threadPool,
                config.getShardId(),
                fileTransferTracker,
                remoteTranslogTransferTracker,
                config.getIndexSettings().getRemoteStorePathStrategy(),
                remoteStoreSettings,
                config.getIndexSettings().isTranslogMetadataEnabled(),
                keyResolver,
                translogUUID,
                cryptoFactory
            );

            PrivilegedAccess.doPrivileged(() -> {
                try {
                    Field transferManagerField = RemoteFsTranslog.class.getDeclaredField("translogTransferManager");
                    transferManagerField.setAccessible(true);
                    transferManagerField.set(this, decryptingManager);
                    return null;
                } catch (ReflectiveOperationException e) {
                    throw new IllegalStateException("Failed to replace TranslogTransferManager", e);
                }
            });
        } catch (Exception e) {
            logger.error("Failed to replace TranslogTransferManager with decrypting version", e);
            throw new IOException("Failed to initialize decrypt-before-upload capability", e);
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

    @Override
    ChannelFactory getChannelFactory() {
        CryptoChannelFactory factory = this.cryptoFactory;
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

    /**
     * Creates a DecryptingTranslogTransferManager to replace parent's manager.
     */
    private static TranslogTransferManager createDecryptingTranslogTransferManager(
        BlobStoreRepository blobStoreRepository,
        ThreadPool threadPool,
        ShardId shardId,
        FileTransferTracker fileTransferTracker,
        RemoteTranslogTransferTracker tracker,
        RemoteStorePathStrategy pathStrategy,
        RemoteStoreSettings remoteStoreSettings,
        boolean isTranslogMetadataEnabled,
        KeyResolver keyResolver,
        String translogUUID,
        CryptoChannelFactory cryptoFactory
    ) {
        String indexUUID = shardId.getIndex().getUUID();
        String shardIdStr = String.valueOf(shardId.id());

        RemoteStorePathStrategy.PathInput dataPathInput = RemoteStorePathStrategy.PathInput
            .builder()
            .basePath(blobStoreRepository.basePath())
            .indexUUID(indexUUID)
            .shardId(shardIdStr)
            .dataCategory(TRANSLOG)
            .dataType(DATA)
            .fixedPrefix(remoteStoreSettings.getTranslogPathFixedPrefix())
            .build();
        BlobPath dataPath = pathStrategy.generatePath(dataPathInput);

        RemoteStorePathStrategy.PathInput mdPathInput = RemoteStorePathStrategy.PathInput
            .builder()
            .basePath(blobStoreRepository.basePath())
            .indexUUID(indexUUID)
            .shardId(shardIdStr)
            .dataCategory(TRANSLOG)
            .dataType(METADATA)
            .fixedPrefix(remoteStoreSettings.getTranslogPathFixedPrefix())
            .build();
        BlobPath mdPath = pathStrategy.generatePath(mdPathInput);

        BlobStoreTransferService transferService = new BlobStoreTransferService(blobStoreRepository.blobStore(), threadPool);

        return new DecryptingTranslogTransferManager(
            shardId,
            transferService,
            dataPath,
            mdPath,
            fileTransferTracker,
            tracker,
            remoteStoreSettings,
            isTranslogMetadataEnabled,
            keyResolver,
            translogUUID,
            cryptoFactory
        );
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
                "Failed to initialize crypto channel factory for translog encryption. Cannot proceed without encryption!",
                e
            );
        }
    }
}
