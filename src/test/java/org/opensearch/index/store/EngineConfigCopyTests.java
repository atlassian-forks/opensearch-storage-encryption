/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.lang.reflect.Field;

import org.opensearch.index.codec.CodecService;
import org.opensearch.index.engine.EngineConfig;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Guards the reflective {@link EngineConfigCopy} copy of {@code EngineConfig.codecService}.
 * OpenSearch 2.19 has no getter; a 2.19.x field rename would otherwise fail only at runtime.
 */
public class EngineConfigCopyTests extends OpenSearchTestCase {

    public void testCodecServiceFieldExistsWithExpectedType() {
        final Field field;
        try {
            field = EngineConfig.class.getDeclaredField("codecService");
        } catch (NoSuchFieldException e) {
            throw new AssertionError(
                "EngineConfig.codecService is missing; EngineConfigCopy.withTranslogFactory "
                    + "will fail at runtime on this OpenSearch version",
                e
            );
        }
        assertEquals("EngineConfig.codecService type changed; EngineConfigCopy must be updated", CodecService.class, field.getType());
    }
}
