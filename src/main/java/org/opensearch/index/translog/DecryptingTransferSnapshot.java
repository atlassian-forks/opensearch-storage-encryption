/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.PrivilegedAccess;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.translog.transfer.FileSnapshot.TransferFileSnapshot;
import org.opensearch.index.translog.transfer.FileSnapshot.TranslogFileSnapshot;
import org.opensearch.index.translog.transfer.TransferSnapshot;
import org.opensearch.index.translog.transfer.TranslogTransferMetadata;

/**
 * Wrapper for TransferSnapshot that provides decrypted file streams during upload.
 *
 * @opensearch.internal
 */
public class DecryptingTransferSnapshot implements TransferSnapshot {

    private static final Logger logger = LogManager.getLogger(DecryptingTransferSnapshot.class);

    private final TransferSnapshot delegate;
    private final KeyResolver keyResolver;
    private final String translogUUID;
    private final CryptoChannelFactory cryptoFactory;

    /**
     * Creates a new DecryptingTransferSnapshot wrapping the provided snapshot.
     *
     * @param delegate the original TransferSnapshot to wrap
     * @param keyResolver the key resolver for decryption
     * @param translogUUID the translog UUID for encryption context
     * @param cryptoFactory the crypto channel factory for finalizing ciphers
     */
    public DecryptingTransferSnapshot(
        TransferSnapshot delegate,
        KeyResolver keyResolver,
        String translogUUID,
        CryptoChannelFactory cryptoFactory
    ) {
        this.delegate = delegate;
        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
        this.cryptoFactory = cryptoFactory;
    }

    /**
     * Each TranslogFileSnapshot is wrapped with DecryptingFileSnapshot which
     * provides a decrypting input stream when read.
     */
    @Override
    public Set<TransferFileSnapshot> getTranslogFileSnapshots() {
        try {
            Set<TransferFileSnapshot> originals = delegate.getTranslogFileSnapshots();
            return wrapTranslogSnapshots(originals);
        } catch (Exception e) {
            logger.error("Failed to wrap translog snapshots", e);
            throw new RuntimeException("Failed to wrap translog snapshots", e);
        }
    }

    @Override
    public Set<TransferFileSnapshot> getTranslogFileSnapshotWithMetadata() throws IOException {
        try {
            Set<TransferFileSnapshot> originals = delegate.getTranslogFileSnapshotWithMetadata();
            return wrapTranslogSnapshots(originals);
        } catch (IOException e) {
            logger.error("IOException wrapping translog snapshots with metadata", e);
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error wrapping translog snapshots with metadata", e);
            throw new IOException("Failed to wrap translog snapshots", e);
        }
    }

    @Override
    public Set<TransferFileSnapshot> getCheckpointFileSnapshots() {
        // Checkpoint files are not encrypted, return as it is
        return delegate.getCheckpointFileSnapshots();
    }

    @Override
    public TranslogTransferMetadata getTranslogTransferMetadata() {
        return delegate.getTranslogTransferMetadata();
    }

    private Set<TransferFileSnapshot> wrapTranslogSnapshots(Set<TransferFileSnapshot> originals) throws IOException {
        Set<TransferFileSnapshot> wrapped = new HashSet<>();

        for (TransferFileSnapshot snapshot : originals) {
            if (snapshot instanceof TranslogFileSnapshot) {
                TranslogFileSnapshot translogSnapshot = (TranslogFileSnapshot) snapshot;
                Path path = translogSnapshot.getPath();

                // This writes authentication tags so the file can be decrypted during upload
                cryptoFactory.finalizeForPath(path);

                if (path != null && path.getFileName().toString().endsWith(".tlog")) {
                    // 2.19 TranslogFileSnapshot is final, and TranslogTransferManager.prepareMetadata
                    // checkcasts TransferFileSnapshot to TranslogFileSnapshot. Materialize decrypted
                    // bytes as a real TranslogFileSnapshot with the original filename.
                    wrapped.add(materializeDecryptedTranslogSnapshot(translogSnapshot));
                } else {
                    wrapped.add(snapshot);
                }
            } else {
                wrapped.add(snapshot);
            }
        }

        return wrapped;
    }

    /**
     * Decrypt {@code translogSnapshot} into a temp file named like the original, then wrap that
     * path in a 2.19 {@link TranslogFileSnapshot} so upload and metadata mapping still type-check.
     */
    private TranslogFileSnapshot materializeDecryptedTranslogSnapshot(TranslogFileSnapshot translogSnapshot) throws IOException {
        DecryptingFileSnapshot decrypting = new DecryptingFileSnapshot(
            translogSnapshot,
            keyResolver,
            translogUUID,
            cryptoFactory.getProvider()
        );
        Path originalPath = translogSnapshot.getPath();
        Path decryptedDir = PrivilegedAccess.doPrivilegedIOException(() -> Files.createTempDirectory("cryptofs-tlog-decrypt-"));
        Path decryptedPath = decryptedDir.resolve(originalPath.getFileName());
        try (
            InputStream in = decrypting.inputStream();
            OutputStream out = PrivilegedAccess.doPrivilegedIOException(() -> Files.newOutputStream(decryptedPath))
        ) {
            in.transferTo(out);
        } finally {
            decrypting.close();
        }
        decryptedPath.toFile().deleteOnExit();
        decryptedDir.toFile().deleteOnExit();
        TranslogFileSnapshot materialized = new TranslogFileSnapshot(
            translogSnapshot.getPrimaryTerm(),
            translogSnapshot.getGeneration(),
            decryptedPath,
            null
        );
        if (translogSnapshot.getMetadataFileInputStream() != null) {
            materialized.setMetadataFileInputStream(translogSnapshot.getMetadataFileInputStream());
        }
        return materialized;
    }
}
