/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.mockito.Mockito.mock;

import java.util.Collections;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.index.Index;
import org.opensearch.index.IndexModule;
import org.opensearch.index.engine.EngineConfigFactory;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.store.key.MasterKeyHealthMonitor;
import org.opensearch.index.store.key.NodeLevelKeyCache;
import org.opensearch.test.IndexSettingsModule;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;

public class CryptoDirectoryPluginKeyAccessTests extends OpenSearchTestCase {
    public void testRejectedIndexModuleValidationDoesNotRestoreRevokedKeyAccess() throws Exception {
        MasterKeyHealthMonitor.initialize(Settings.EMPTY, mock(Client.class), mock(ClusterService.class));
        NodeLevelKeyCache.initialize(Settings.EMPTY, MasterKeyHealthMonitor.getInstance());
        try {
            NodeLevelKeyCache cache = NodeLevelKeyCache.getInstance();
            cache.revokeIndex("uuid-a");
            Index index = new Index("tenant-a", "uuid-a");
            // An invalid provider makes OpenSearch reject this candidate metadata.
            var indexSettings = IndexSettingsModule
                .newIndexSettings(
                    index,
                    Settings.builder().put("index.uuid", "uuid-a").put("index.store.type", "cryptofs").build(),
                    CryptoDirectoryFactory.INDEX_KEY_ACCESS_SETTING
                );
            IndexModule module = new IndexModule(
                indexSettings,
                null,
                mock(EngineFactory.class),
                mock(EngineConfigFactory.class),
                Collections.emptyMap(),
                () -> true,
                null,
                Collections.emptyMap()
            );
            CryptoDirectoryPlugin plugin = new CryptoDirectoryPlugin(Settings.builder().put("plugins.crypto.enabled", true).build());
            expectThrows(IllegalArgumentException.class, () -> plugin.onIndexModule(module));
            expectThrows(SecurityException.class, () -> cache.get("uuid-a", 0, "tenant-a"));
        } finally {
            NodeLevelKeyCache.reset();
            MasterKeyHealthMonitor.reset();
        }
    }
}
