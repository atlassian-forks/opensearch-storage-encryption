/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.Version;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.transport.TransportResponse;
import org.opensearch.index.store.key.NodeLevelKeyCache;
import org.opensearch.index.store.key.NodeLevelKeyCache.IndexReadAccess;
import org.opensearch.search.SearchPhaseResult;
import org.opensearch.search.SearchService;
import org.opensearch.search.internal.ReaderContext;
import org.opensearch.search.internal.ShardSearchContextId;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportChannel;

/** Releases node-local scroll and PIT contexts for a revoked physical index. */
final class RevokedIndexContexts {
    private static final Logger logger = LogManager.getLogger(RevokedIndexContexts.class);
    private final ConcurrentMap<String, ConcurrentMap<ShardSearchContextId, IndexReadAccess>> contexts = new ConcurrentHashMap<>();
    private SearchService searchService;
    private ThreadPool threadPool;

    // The node constructs plugin lifecycle services after SearchService has been bound.
    public static final class Wiring extends AbstractLifecycleComponent {
        @Inject
        public Wiring(RevokedIndexContexts contexts, SearchService searchService, ThreadPool threadPool) {
            contexts.searchService = searchService;
            contexts.threadPool = threadPool;
        }

        @Override
        protected void doStart() {}

        @Override
        protected void doStop() {}

        @Override
        protected void doClose() {}
    }

    TransportChannel guardCreation(String indexUuid, TransportChannel delegate) {
        IndexReadAccess access = NodeLevelKeyCache.getInstance().captureIndexReadAccess(indexUuid);
        if (access == null) {
            return delegate;
        }
        checkAccess(access);
        return new TransportChannel() {
            @Override
            public void sendResponse(TransportResponse response) throws IOException {
                checkResponse(response);
                delegate.sendResponse(response);
            }

            @Override
            public void sendResponseBatch(TransportResponse response) {
                checkResponse(response);
                delegate.sendResponseBatch(response);
            }

            @Override
            public void completeStream() {
                delegate.completeStream();
            }

            private void checkResponse(TransportResponse response) {
                if (response instanceof SearchPhaseResult created && !access.isCurrent()) {
                    // Core has registered the context. The revoke snapshot may have run before it was visible.
                    if (created.getContextId() != null) {
                        release(indexUuid, Set.of(created.getContextId()));
                    }
                    throw invalidatedContext();
                }
            }

            @Override
            public void sendResponse(Exception exception) throws IOException {
                delegate.sendResponse(exception);
            }

            @Override
            public String getProfileName() {
                return delegate.getProfileName();
            }

            @Override
            public String getChannelType() {
                return delegate.getChannelType();
            }

            @Override
            public Version getVersion() {
                return delegate.getVersion();
            }

            @Override
            public <T> Optional<T> get(String name, Class<T> clazz) {
                return delegate.get(name, clazz);
            }
        };
    }

    void track(ReaderContext context) {
        String indexUuid = context.indexShard().shardId().getIndex().getUUID();
        IndexReadAccess access = NodeLevelKeyCache.getInstance().captureIndexReadAccess(indexUuid);
        if (access != null) {
            ShardSearchContextId id = context.id();
            context.addOnClose(() -> untrack(indexUuid, id));
            contexts.compute(indexUuid, (uuid, readers) -> {
                ConcurrentMap<ShardSearchContextId, IndexReadAccess> current = readers == null ? new ConcurrentHashMap<>() : readers;
                current.put(id, access);
                return current;
            });
        }
    }

    void validate(ReaderContext context) {
        var index = context.indexShard().shardId().getIndex();
        CryptoDirectoryPlugin.requireShardReadAccess(index);
        var readers = contexts.get(index.getUUID());
        if (readers != null) {
            checkAccess(readers.get(context.id()));
        }
    }

    private static void checkAccess(IndexReadAccess access) {
        if (access != null && !access.isCurrent()) {
            throw invalidatedContext();
        }
    }

    private static OpenSearchStatusException invalidatedContext() {
        return new OpenSearchStatusException("Reader context was invalidated by index key revocation", RestStatus.FORBIDDEN);
    }

    private void untrack(String indexUuid, ShardSearchContextId id) {
        contexts.computeIfPresent(indexUuid, (uuid, readers) -> {
            readers.remove(id);
            return readers.isEmpty() ? null : readers;
        });
    }

    void clear(String indexUuid) {
        var readers = contexts.get(indexUuid);
        if (readers != null) {
            // Keep revisions until Core closes each reader. Restore can run before the cleanup worker.
            release(indexUuid, Set.copyOf(readers.keySet()));
        }
    }

    private void release(String indexUuid, Set<ShardSearchContextId> ids) {
        // Release only the captured contexts, off the cluster-state thread.
        threadPool.generic().execute(() -> {
            for (ShardSearchContextId id : ids) {
                try {
                    searchService.freeReaderContext(id);
                } catch (RuntimeException e) {
                    logger.warn("Failed to release reader context for revoked index UUID {}", indexUuid, e);
                }
            }
        });
    }
}
