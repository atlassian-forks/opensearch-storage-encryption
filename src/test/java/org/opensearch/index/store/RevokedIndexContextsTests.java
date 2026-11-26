/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.ExecutorService;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.TransportCreatePitAction.CreateReaderContextResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.shard.IndexShard;
import org.opensearch.index.store.key.MasterKeyHealthMonitor;
import org.opensearch.index.store.key.NodeLevelKeyCache;
import org.opensearch.search.SearchPhaseResult;
import org.opensearch.search.SearchService;
import org.opensearch.search.dfs.DfsSearchResult;
import org.opensearch.search.internal.ReaderContext;
import org.opensearch.search.internal.ShardSearchContextId;
import org.opensearch.search.query.QuerySearchResult;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportChannel;
import org.opensearch.transport.client.Client;

public class RevokedIndexContextsTests extends OpenSearchTestCase {
    private static final String TENANT_A = "tenant-a";
    private static final String TENANT_B = "tenant-b";
    private final Queue<Runnable> cleanup = new ArrayDeque<>();
    private final RevokedIndexContexts contexts = new RevokedIndexContexts();
    private NodeLevelKeyCache keys;
    private SearchService searchService;
    private ThreadPool threadPool;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        MasterKeyHealthMonitor.initialize(Settings.EMPTY, mock(Client.class), mock(ClusterService.class));
        NodeLevelKeyCache.initialize(Settings.EMPTY, MasterKeyHealthMonitor.getInstance());
        keys = NodeLevelKeyCache.getInstance();
        for (String tenant : new String[] { TENANT_A, TENANT_B }) {
            keys.revokeIndex(tenant);
            keys.restoreIndex(tenant);
        }
        searchService = mock(SearchService.class);
        threadPool = mock(ThreadPool.class);
        var executor = mock(ExecutorService.class);
        when(threadPool.generic()).thenReturn(executor);
        doAnswer(invocation -> {
            cleanup.add(invocation.getArgument(0));
            return null;
        }).when(executor).execute(any(Runnable.class));
        new RevokedIndexContexts.Wiring(contexts, searchService, threadPool);
    }

    @Override
    public void tearDown() throws Exception {
        try {
            NodeLevelKeyCache.reset();
            MasterKeyHealthMonitor.reset();
        } finally {
            super.tearDown();
        }
    }

    public void testPitCreationSpanningRevokeAndRestoreIsRejected() throws Exception {
        assertLateCreateRejected(new CreateReaderContextResponse(new ShardSearchContextId("session", 1)));
    }

    public void testInitialScrollQuerySpanningRevokeAndRestoreIsRejected() throws Exception {
        assertLateCreateRejected(new QuerySearchResult(new ShardSearchContextId("session", 1), null, null));
    }

    public void testInitialScrollDfsSpanningRevokeAndRestoreIsRejected() throws Exception {
        assertLateCreateRejected(new DfsSearchResult(new ShardSearchContextId("session", 1), null, null));
    }

    public void testStreamedScrollUsesTheSameCreationCheck() {
        var delegate = mock(TransportChannel.class);
        var admitted = contexts.guardCreation(TENANT_A, delegate);
        var first = new QuerySearchResult(new ShardSearchContextId("session", 1), null, null);
        admitted.sendResponseBatch(first);
        admitted.completeStream();
        verify(delegate).sendResponseBatch(first);
        verify(delegate).completeStream();

        var stale = contexts.guardCreation(TENANT_A, delegate);
        keys.revokeIndex(TENANT_A);
        keys.restoreIndex(TENANT_A);
        var second = new QuerySearchResult(new ShardSearchContextId("session", 2), null, null);
        expectThrows(OpenSearchStatusException.class, () -> stale.sendResponseBatch(second));
        verifyNoMoreInteractions(delegate);
        cleanup.remove().run();
        verify(searchService).freeReaderContext(second.getContextId());
    }

    private void assertLateCreateRejected(SearchPhaseResult result) throws Exception {
        var delegate = mock(TransportChannel.class);
        var admitted = contexts.guardCreation(TENANT_A, delegate);
        keys.revokeIndex(TENANT_A);
        contexts.clear(TENANT_A);
        keys.restoreIndex(TENANT_A);
        // The request passed admission before revoke, but Core only registered its reader after restore.
        try (var lateReader = reader(TENANT_A, result.getContextId().getId())) {
            contexts.track(lateReader);
            var exception = expectThrows(OpenSearchStatusException.class, () -> admitted.sendResponse(result));
            assertEquals(RestStatus.FORBIDDEN, exception.status());
            verifyNoInteractions(delegate, searchService);
            cleanup.remove().run();
            assertTrue(cleanup.isEmpty());
            verify(searchService).freeReaderContext(result.getContextId());
        }
    }

    public void testLateRegistrationIsReleasedWhenCleanupRanBeforeCorePublishedIt() {
        var admitted = contexts.guardCreation(TENANT_A, mock(TransportChannel.class));
        try (var reader = reader(TENANT_A, 1)) {
            contexts.track(reader);
            when(searchService.freeReaderContext(reader.id())).thenReturn(false, true);
            keys.revokeIndex(TENANT_A);
            contexts.clear(TENANT_A);
            cleanup.remove().run();
            verify(searchService).freeReaderContext(reader.id());
            keys.restoreIndex(TENANT_A);

            var result = new CreateReaderContextResponse(reader.id());
            expectThrows(OpenSearchStatusException.class, () -> admitted.sendResponse(result));
            cleanup.remove().run();
            verify(searchService, times(2)).freeReaderContext(reader.id());
        }
    }

    public void testCleanupAfterRestoreCannotFreeFreshOrOtherTenantReaders() throws Exception {
        try (var old = reader(TENANT_A, 1); var fresh = reader(TENANT_A, 2); var otherTenant = reader(TENANT_B, 3)) {
            contexts.track(old);
            contexts.track(otherTenant);
            keys.revokeIndex(TENANT_A);
            contexts.clear(TENANT_A);
            keys.restoreIndex(TENANT_A);

            var delegate = mock(TransportChannel.class);
            var admitted = contexts.guardCreation(TENANT_A, delegate);
            contexts.track(fresh);
            var result = new CreateReaderContextResponse(fresh.id());
            admitted.sendResponse(result);
            verify(delegate).sendResponse(result);

            // The worker has not released the old context yet. Restore must still leave it unusable.
            expectThrows(OpenSearchStatusException.class, () -> contexts.validate(old));
            contexts.validate(fresh);
            contexts.validate(otherTenant);
            cleanup.remove().run();
            verify(searchService).freeReaderContext(old.id());
            verifyNoMoreInteractions(searchService);
            contexts.validate(fresh);
            contexts.validate(otherTenant);
        }
        contexts.clear(TENANT_A);
        contexts.clear(TENANT_B);
        assertTrue(cleanup.isEmpty());
    }

    private ReaderContext reader(String indexUuid, long id) {
        var shard = mock(IndexShard.class);
        when(shard.shardId()).thenReturn(new ShardId(indexUuid, indexUuid, 0));
        when(shard.getThreadPool()).thenReturn(threadPool);
        return new ReaderContext(new ShardSearchContextId("session", id), null, shard, null, 60_000, false);
    }
}
