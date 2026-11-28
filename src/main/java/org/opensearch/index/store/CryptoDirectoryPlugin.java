/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchTransportService;
import org.opensearch.action.search.TransportCreatePitAction.CreateReaderContextRequest;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.lifecycle.LifecycleComponent;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.index.Index;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.index.IndexModule;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.shard.IndexEventListener;
import org.opensearch.index.shard.SearchOperationListener;
import org.opensearch.index.store.action.GetIndexCountForKeyAction;
import org.opensearch.index.store.action.TransportGetIndexCountForKeyAction;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_loader.FileChannelCache;
import org.opensearch.index.store.cipher.EncryptionMetadataCacheRegistry;
import org.opensearch.index.store.key.MasterKeyHealthMonitor;
import org.opensearch.index.store.key.NodeLevelKeyCache;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.pool.PoolSizeCalculator;
import org.opensearch.index.store.rest.RestGetIndexCountForKeyAction;
import org.opensearch.index.store.rest.RestRegisterCryptoAction;
import org.opensearch.index.store.rest.RestUnregisterCryptoAction;
import org.opensearch.indices.RemoteStoreSettings;
import org.opensearch.indices.cluster.IndicesClusterStateService.AllocatedIndices.IndexRemovalReason;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.EnginePlugin;
import org.opensearch.plugins.IndexStorePlugin;
import org.opensearch.plugins.NetworkPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.TelemetryAwarePlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.search.internal.ReaderContext;
import org.opensearch.search.internal.ShardSearchRequest;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.telemetry.tracing.Tracer;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportInterceptor;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

/**
 * A plugin that enables index level encryption and decryption.
 */
public class CryptoDirectoryPlugin extends Plugin
    implements
        IndexStorePlugin,
        EnginePlugin,
        TelemetryAwarePlugin,
        ActionPlugin,
        NetworkPlugin {
    private static final Logger log = LogManager.getLogger(CryptoDirectoryPlugin.class);

    /**
     * Setting key for enabling the crypto plugin.
     */
    public static final String CRYPTO_PLUGIN_ENABLED = "plugins.crypto.enabled";

    /**
     * Setting for controlling whether the crypto plugin is enabled.
     */
    public static final Setting<Boolean> CRYPTO_PLUGIN_ENABLED_SETTING = Setting
        .boolSetting(CRYPTO_PLUGIN_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final);

    private NodeEnvironment nodeEnvironment;
    private final boolean enabled;
    private final RevokedIndexContexts revokedContexts = new RevokedIndexContexts();

    // Static storage for remote store parameters (accessible by CryptoEngineFactory)
    private static Supplier<RepositoriesService> repositoriesServiceSupplier;
    private static RemoteStoreSettings remoteStoreSettings;

    /**
     * Constructor with settings.
     * @param settings OpenSearch node settings
     */
    public CryptoDirectoryPlugin(Settings settings) {
        super();
        this.enabled = settings.getAsBoolean(CRYPTO_PLUGIN_ENABLED, false);

        if (enabled) {
            log.info("OpenSearch Crypto Directory Plugin is enabled and ready for encryption operations");
        } else {
            log
                .warn(
                    "OpenSearch Crypto Directory Plugin installed but disabled. "
                        + "No encryption/decryption will be performed. "
                        + "To enable encryption, set '{}' to true in opensearch.yml",
                    CRYPTO_PLUGIN_ENABLED
                );
        }
    }

    /**
     * Check if the plugin is disabled.
     * @return true if the plugin is disabled, false otherwise
     */
    public boolean isDisabled() {
        return !enabled;
    }

    /**
     * Get the RepositoriesService supplier for remote store operations.
     * @return the repositories service supplier, or null if not initialized
     */
    public static Supplier<RepositoriesService> getRepositoriesServiceSupplier() {
        return repositoriesServiceSupplier;
    }

    /**
     * Get the RemoteStoreSettings for remote store operations.
     * @return the remote store settings, or null if not initialized
     */
    public static RemoteStoreSettings getRemoteStoreSettings() {
        return remoteStoreSettings;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = Arrays
            .asList(
                CRYPTO_PLUGIN_ENABLED_SETTING,
                CryptoDirectoryFactory.INDEX_CRYPTO_PROVIDER_SETTING,
                CryptoDirectoryFactory.INDEX_KEY_ACCESS_SETTING,
                CryptoDirectoryFactory.INDEX_KEY_PROVIDER_SETTING,
                CryptoDirectoryFactory.INDEX_KMS_ARN_SETTING,
                CryptoDirectoryFactory.INDEX_KMS_ENC_CTX_SETTING,
                CryptoDirectoryFactory.NODE_KEY_REFRESH_INTERVAL_SETTING,
                CryptoDirectoryFactory.NODE_KEY_EXPIRY_INTERVAL_SETTING,
                CryptoDirectoryFactory.WRITE_CACHE_ENABLED_SETTING,
                PoolSizeCalculator.NODE_POOL_SIZE_PERCENTAGE_SETTING,
                PoolSizeCalculator.NODE_CACHE_TO_POOL_RATIO_SETTING,
                PoolSizeCalculator.NODE_WARMUP_PERCENTAGE_SETTING,
                PoolSizeCalculator.NODE_MAX_FILE_CHANNELS_SETTING,
                PoolSizeCalculator.NODE_FD_CACHE_EXPIRE_SECONDS_SETTING
            );
        return settings;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, DirectoryFactory> getDirectoryFactories() {
        if (isDisabled()) {
            log.debug("Crypto Directory Plugin is disabled. No directory factories will be registered.");
            return Collections.emptyMap();
        }
        log.debug("Crypto Directory Plugin is enabled. Registering cryptofs directory factory.");
        return Collections.singletonMap(CryptoDirectoryFactory.STORE_TYPE, new CryptoDirectoryFactory());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<EngineFactory> getEngineFactory(IndexSettings indexSettings) {
        if (isDisabled()) {
            return Optional.empty();
        }

        // Only provide our custom engine factory for cryptofs indices
        if (CryptoDirectoryFactory.STORE_TYPE.equals(indexSettings.getValue(IndexModule.INDEX_STORE_TYPE_SETTING))) {
            return Optional.of(new CryptoEngineFactory());
        }
        return Optional.empty();
    }

    @Override
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {
        return isDisabled() ? List.of() : List.of(RevokedIndexContexts.Wiring.class);
    }

    @Override
    public Collection<Object> createComponents(
        Client client,
        ClusterService clusterService,
        ThreadPool threadPool,
        ResourceWatcherService resourceWatcherService,
        ScriptService scriptService,
        NamedXContentRegistry xContentRegistry,
        Environment environment,
        NodeEnvironment nodeEnvironment,
        NamedWriteableRegistry namedWriteableRegistry,
        IndexNameExpressionResolver expressionResolver,
        Supplier<RepositoriesService> repositoriesServiceSupplier,
        Tracer tracer,
        MetricsRegistry metricsRegistry
    ) {
        if (isDisabled()) {
            log.debug("Crypto Directory Plugin is disabled. Skipping component initialization.");
            return Collections.emptyList();
        }

        this.nodeEnvironment = nodeEnvironment;

        // Store remote store parameters for CryptoEngineFactory to access
        CryptoDirectoryPlugin.repositoriesServiceSupplier = repositoriesServiceSupplier;
        // Create RemoteStoreSettings with node settings and cluster settings
        CryptoDirectoryPlugin.remoteStoreSettings = new RemoteStoreSettings(environment.settings(), clusterService.getClusterSettings());

        // Set cluster service for accessing cluster metadata (e.g., repository settings)
        CryptoDirectoryFactory.setClusterService(clusterService);

        // Initialize health monitor first (creates monitor)
        MasterKeyHealthMonitor.initialize(environment.settings(), client, clusterService);

        // Initialize cache second (depends on health monitor reference)
        NodeLevelKeyCache.initialize(environment.settings(), MasterKeyHealthMonitor.getInstance());

        // Apply published index metadata before the ordinary shard applier opens directories.
        clusterService.addHighPriorityApplier(event -> applyKeyAccess(event, threadPool));
        // Run after the shard applier and also retire gates on nodes that never hosted the index.
        clusterService.addListener(event -> {
            for (Index deleted : event.indicesDeleted()) {
                NodeLevelKeyCache.getInstance().removeIndex(deleted.getUUID());
            }
        });

        // Start health monitoring now that everything is initialized
        MasterKeyHealthMonitor.start();

        // Pool resources are lazily initialized on first cryptofs shard creation
        // This prevents allocation on dedicated master nodes which never create shards
        CryptoDirectoryFactory.setNodeSettings(environment.settings());
        CryptoMetricsService.initialize(metricsRegistry);

        return List.of(revokedContexts);
    }

    @Override
    public void close() {
        if (isDisabled()) {
            log.debug("Crypto Directory Plugin is disabled. No cleanup needed.");
            return;
        }

        MasterKeyHealthMonitor.shutdown();
        // Close shared pool resources if they were initialized
        // the shared pool is initialized only when at least one index
        // level enc enabled index is created.
        CryptoDirectoryFactory.closeSharedPool();
    }

    @Override
    public List<ActionHandler<?, ?>> getActions() {
        return Arrays.asList(new ActionHandler<>(GetIndexCountForKeyAction.INSTANCE, TransportGetIndexCountForKeyAction.class));
    }

    @Override
    public List<RestHandler> getRestHandlers(
        Settings settings,
        RestController restController,
        ClusterSettings clusterSettings,
        IndexScopedSettings indexScopedSettings,
        SettingsFilter settingsFilter,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<DiscoveryNodes> nodesInCluster
    ) {
        return Arrays.asList(new RestRegisterCryptoAction(), new RestUnregisterCryptoAction(), new RestGetIndexCountForKeyAction());
    }

    @Override
    public List<TransportInterceptor> getTransportInterceptors(NamedWriteableRegistry registry, ThreadContext threadContext) {
        if (isDisabled()) {
            return List.of();
        }
        return List.of(new TransportInterceptor() {
            @Override
            public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(
                String action,
                String executor,
                boolean forceExecution,
                TransportRequestHandler<T> actualHandler
            ) {
                if (!action.startsWith("indices:data/read/search[")) {
                    return actualHandler;
                }
                return (request, channel, task) -> {
                    // The shard UUID has already been resolved. The query can be answered without reading any files.
                    if (request instanceof ShardSearchRequest shardRequest) {
                        Index index = shardRequest.shardId().getIndex();
                        requireShardReadAccess(index);
                        if (shardRequest.scroll() != null
                            && shardRequest.readerId() == null
                            && (SearchTransportService.QUERY_ACTION_NAME.equals(action)
                                || SearchTransportService.DFS_ACTION_NAME.equals(action))) {
                            channel = revokedContexts.guardCreation(index.getUUID(), channel);
                        }
                    }
                    if (SearchTransportService.CREATE_READER_CONTEXT_ACTION_NAME.equals(action)
                        && request instanceof CreateReaderContextRequest createPit) {
                        Index index = createPit.getShardId().getIndex();
                        requireShardReadAccess(index);
                        channel = revokedContexts.guardCreation(index.getUUID(), channel);
                    }
                    actualHandler.messageReceived(request, channel, task);
                };
            }
        });
    }

    static void requireShardReadAccess(Index index) {
        if (NodeLevelKeyCache.getInstance().isIndexRevoked(index.getUUID())) {
            throw new OpenSearchStatusException("Index key access is revoked", RestStatus.FORBIDDEN);
        }
    }

    private void applyKeyAccess(ClusterChangedEvent event, ThreadPool threadPool) {
        if (!event.metadataChanged()) {
            return;
        }
        NodeLevelKeyCache keyCache = NodeLevelKeyCache.getInstance();
        List<Index> revoked = new ArrayList<>();
        for (IndexMetadata current : event.state().metadata().indices().values()) {
            Settings settings = current.getSettings();
            if (!CryptoDirectoryFactory.STORE_TYPE.equals(settings.get(IndexModule.INDEX_STORE_TYPE_SETTING.getKey()))) {
                continue;
            }
            IndexMetadata previous = event.previousState().metadata().index(current.getIndex().getName());
            String access = CryptoDirectoryFactory.INDEX_KEY_ACCESS_SETTING.get(settings);
            if (previous != null
                && previous.getIndex().equals(current.getIndex())
                && access.equals(CryptoDirectoryFactory.INDEX_KEY_ACCESS_SETTING.get(previous.getSettings()))) {
                continue;
            }
            Index index = current.getIndex();
            String indexUuid = index.getUUID();
            if ("allowed".equals(access)) {
                keyCache.restoreIndex(indexUuid);
            } else {
                keyCache.revokeIndex(indexUuid);
                revokedContexts.clear(indexUuid);
                EncryptionMetadataCacheRegistry.invalidateIndex(indexUuid);
                revoked.add(index);
            }
        }
        if (!revoked.isEmpty()) {
            BlockCache<?> cache = CryptoDirectoryFactory.getSharedBlockCache();
            if (cache != null && nodeEnvironment != null) {
                // The deny gates are already active. Sweep the shared cache off the cluster-state thread.
                threadPool.generic().execute(() -> {
                    for (Index index : revoked) {
                        if (keyCache.isIndexRevoked(index.getUUID())) {
                            for (Path indexPath : nodeEnvironment.indexPaths(index)) {
                                cache.invalidateByPathPrefix(indexPath);
                            }
                        }
                    }
                });
            }
        }
    }

    @Override
    public void onIndexModule(IndexModule indexModule) {
        if (isDisabled()) {
            log
                .debug(
                    "Crypto Directory Plugin is disabled. Skipping index module initialization for index: {}",
                    indexModule.getIndex().getName()
                );
            return;
        }

        Settings indexSettings = indexModule.getSettings();
        String storeType = indexSettings.get(IndexModule.INDEX_STORE_TYPE_SETTING.getKey());

        if (CryptoDirectoryFactory.STORE_TYPE.equals(storeType)) {
            // Validate crypto settings early at index creation time
            CryptoIndexSettingsValidator.validate(indexSettings);
            indexModule.addSearchOperationListener(new SearchOperationListener() {
                @Override
                public void onNewScrollContext(ReaderContext readerContext) {
                    revokedContexts.track(readerContext);
                }

                @Override
                public void onNewPitContext(ReaderContext readerContext) {
                    revokedContexts.track(readerContext);
                }

                @Override
                public void validateReaderContext(ReaderContext readerContext, TransportRequest request) {
                    revokedContexts.validate(readerContext);
                }
            });
            indexModule.addIndexEventListener(new IndexEventListener() {
                /*
                 * Cache invalidation for closed shards is handled automatically
                 * by CryptoDirectIODirectory.close() when the directory is closed.
                 */
                @Override
                public void afterIndexRemoved(Index index, IndexSettings idxSettings, IndexRemovalReason reason) {
                    if (reason != IndexRemovalReason.DELETED) {
                        return;
                    }

                    BlockCache<?> cache = CryptoDirectoryFactory.getSharedBlockCache();
                    if (cache != null && nodeEnvironment != null) {
                        for (Path indexPath : nodeEnvironment.indexPaths(index)) {
                            cache.invalidateByPathPrefix(indexPath);
                        }
                    }

                    // Invalidate FD cache entries for all files in the deleted index
                    FileChannelCache fdCache = CryptoDirectoryFactory.getSharedFileChannelCache();
                    if (fdCache != null && nodeEnvironment != null) {
                        for (Path indexPath : nodeEnvironment.indexPaths(index)) {
                            fdCache.invalidateByPathPrefix(indexPath);
                        }
                    }

                    /*
                    * The resolvers should be removed only when the index is actually deleted (DELETED reason).
                    * We should NOT remove resolvers when shards are relocated (NO_LONGER_ASSIGNED) or during
                    * node restarts, as other nodes may still need the resolver for their shards.
                    * 
                    * This prevents race conditions during:
                    * - Shard relocation between nodes
                    * - Node restarts with replica recovery
                    * - Cluster topology changes
                    * */
                    int nShards = idxSettings.getNumberOfShards();
                    for (int i = 0; i < nShards; i++) {
                        ShardKeyResolverRegistry.removeResolver(index.getUUID(), i, index.getName());
                        NodeLevelKeyCache.getInstance().evict(index.getUUID(), i, index.getName());
                    }
                }
            });
        }
    }
}
