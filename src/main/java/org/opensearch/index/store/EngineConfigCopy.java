/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.lang.reflect.Field;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.codec.CodecService;
import org.opensearch.index.engine.EngineConfig;
import org.opensearch.index.translog.TranslogFactory;

/**
 * Copies an {@link EngineConfig} on OpenSearch 2.19, which has a {@link EngineConfig.Builder}
 * but no {@code toBuilder()} and no public {@code getCodecService()}.
 *
 * @opensearch.internal
 */
final class EngineConfigCopy {

    private EngineConfigCopy() {
        throw new AssertionError("Utility class should not be instantiated");
    }

    /**
     * Rebuild {@code config} with every 2.19 builder field copied, replacing only the translog factory.
     */
    static EngineConfig withTranslogFactory(EngineConfig config, TranslogFactory translogFactory) {
        return new EngineConfig.Builder()
            .shardId(config.getShardId())
            .threadPool(config.getThreadPool())
            .indexSettings(config.getIndexSettings())
            .warmer(config.getWarmer())
            .store(config.getStore())
            .mergePolicy(config.getMergePolicy())
            .analyzer(config.getAnalyzer())
            .similarity(config.getSimilarity())
            .codecService(codecService(config))
            .eventListener(config.getEventListener())
            .queryCache(config.getQueryCache())
            .queryCachingPolicy(config.getQueryCachingPolicy())
            .translogConfig(config.getTranslogConfig())
            .translogDeletionPolicyFactory(config.getCustomTranslogDeletionPolicyFactory())
            .flushMergesAfter(config.getFlushMergesAfter())
            .externalRefreshListener(config.getExternalRefreshListener())
            .internalRefreshListener(config.getInternalRefreshListener())
            .indexSort(config.getIndexSort())
            .circuitBreakerService(config.getCircuitBreakerService())
            .globalCheckpointSupplier(config.getGlobalCheckpointSupplier())
            .retentionLeasesSupplier(config.retentionLeasesSupplier())
            .primaryTermSupplier(config.getPrimaryTermSupplier())
            .tombstoneDocSupplier(config.getTombstoneDocSupplier())
            .readOnlyReplica(config.isReadOnlyReplica())
            .startedPrimarySupplier(config.getStartedPrimarySupplier())
            .translogFactory(translogFactory)
            .leafSorter(config.getLeafSorter())
            .build();
    }

    /**
     * OpenSearch 2.19 stores {@code codecService} privately with no getter. Core's 3.x
     * {@code toBuilder()} copies the field directly; this is the 2.19 equivalent.
     */
    @SuppressForbidden(reason = "OpenSearch 2.19 EngineConfig has no getCodecService(); copy private field")
    private static CodecService codecService(EngineConfig config) {
        return PrivilegedAccess.doPrivileged(() -> {
            try {
                Field field = EngineConfig.class.getDeclaredField("codecService");
                field.setAccessible(true);
                return (CodecService) field.get(config);
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("Unable to copy EngineConfig.codecService", e);
            }
        });
    }
}
