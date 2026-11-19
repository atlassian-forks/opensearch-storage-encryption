/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.opensearch.SpecialPermission;
import org.opensearch.common.SuppressForbidden;

/**
 * OpenSearch 2.19 privileged-action helper (same shape as repository-s3 {@code SocketAccess}).
 * Plugin-security.policy grants only apply inside these blocks.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "java.security.AccessController is the 2.19 privileged-action API")
@SuppressWarnings("removal")
public final class PrivilegedAccess {

    private PrivilegedAccess() {}

    public static <T> T doPrivileged(PrivilegedAction<T> operation) {
        checkSpecialPermission();
        return AccessController.doPrivileged(operation);
    }

    public static <T> T doPrivilegedIOException(PrivilegedExceptionAction<T> operation) throws IOException {
        checkSpecialPermission();
        try {
            return AccessController.doPrivileged(operation);
        } catch (PrivilegedActionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException ioe) {
                throw ioe;
            }
            throw new IOException(e);
        }
    }

    private static void checkSpecialPermission() {
        try {
            SpecialPermission.check();
        } catch (NoClassDefFoundError e) {
            // jcstress forks do not ship OpenSearch core
        }
    }
}
