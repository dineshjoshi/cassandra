/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cassandra.db.streaming;

import java.io.File;
import java.io.IOException;
import java.util.Set;

import com.google.common.base.Throwables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.cassandra.db.ColumnFamilyStore;
import org.apache.cassandra.db.Directories;
import org.apache.cassandra.db.lifecycle.LifecycleTransaction;
import org.apache.cassandra.io.sstable.Component;
import org.apache.cassandra.io.sstable.Descriptor;
import org.apache.cassandra.io.sstable.SSTableMultiWriter;
import org.apache.cassandra.io.sstable.format.big.BigTableBlockWriter;
import org.apache.cassandra.io.util.DataInputPlus;
import org.apache.cassandra.schema.TableId;
import org.apache.cassandra.streaming.ProgressInfo;
import org.apache.cassandra.streaming.StreamReceiver;
import org.apache.cassandra.streaming.StreamSession;
import org.apache.cassandra.streaming.messages.StreamMessageHeader;

import static java.lang.String.format;

import static org.apache.cassandra.utils.FBUtilities.prettyPrintMemory;

/**
 * CassandraBlockStreamReader reads SSTable off the wire and writes it to disk.
 */
public class CassandraBlockStreamReader implements IStreamReader
{
    private static final Logger logger = LoggerFactory.getLogger(CassandraBlockStreamReader.class);

    private final TableId tableId;
    private final StreamSession session;
    private final CassandraStreamHeader header;
    private final int fileSequenceNumber;

    public CassandraBlockStreamReader(StreamMessageHeader messageHeader, CassandraStreamHeader streamHeader, StreamSession session)
    {
        if (session.getPendingRepair() != null)
        {
            // we should only ever be streaming pending repair sstables if the session has a pending repair id
            if (!session.getPendingRepair().equals(messageHeader.pendingRepair))
                throw new IllegalStateException(format("Stream Session & SSTable (%s) pendingRepair UUID mismatch.", messageHeader.tableId));
        }

        this.header = streamHeader;
        this.session = session;
        this.tableId = messageHeader.tableId;
        this.fileSequenceNumber = messageHeader.sequenceNumber;
    }

    /**
     * @param inputPlus where this reads data from
     * @return SSTable transferred
     * @throws IOException if reading the remote sstable fails. Will throw an RTE if local write fails.
     */
    @SuppressWarnings("resource") // input needs to remain open, streams on top of it can't be closed
    @Override
    public SSTableMultiWriter read(DataInputPlus inputPlus) throws IOException
    {
        ColumnFamilyStore cfs = ColumnFamilyStore.getIfExists(tableId);
        if (cfs == null)
        {
            // schema was dropped during streaming
            throw new IOException("Table " + tableId + " was dropped during streaming");
        }

        ComponentManifest manifest = header.componentManifest;
        long totalSize = manifest.getTotalSize();

        logger.debug("[Stream #{}] Started receiving sstable #{} from {}, size = {}, table = {}",
                     session.planId(),
                     fileSequenceNumber,
                     session.peer,
                     prettyPrintMemory(totalSize),
                     cfs.metadata());

        BigTableBlockWriter writer = null;

        try
        {
            writer = createWriter(cfs, totalSize, manifest.getComponents());
            long bytesRead = 0;
            for (Component component : manifest.getComponents())
            {
                long length = manifest.getSizeForType(component.type);

                logger.debug("[Stream #{}] Started receiving {} component from {}, componentSize = {}, readBytes = {}, totalSize = {}",
                             session.planId(),
                             component,
                             session.peer,
                             prettyPrintMemory(length),
                             prettyPrintMemory(bytesRead),
                             prettyPrintMemory(totalSize));

                writer.writeComponent(component.type, inputPlus, length);
                session.progress(writer.descriptor.filenameFor(component), ProgressInfo.Direction.IN, length, length);
                bytesRead += length;

                logger.debug("[Stream #{}] Finished receiving {} component from {}, componentSize = {}, readBytes = {}, totalSize = {}",
                             session.planId(),
                             component,
                             session.peer,
                             prettyPrintMemory(length),
                             prettyPrintMemory(bytesRead),
                             prettyPrintMemory(totalSize));
            }

            writer.descriptor.getMetadataSerializer().mutateLevel(writer.descriptor, header.sstableLevel);
            return writer;
        }
        catch (Throwable e)
        {
            logger.error("[Stream {}] Error while reading sstable from stream for table = {}", session.planId(), cfs.metadata(), e);
            if (writer != null)
                e = writer.abort(e);
            Throwables.throwIfUnchecked(e);
            throw new RuntimeException(e);
        }
    }

    private File getDataDir(ColumnFamilyStore cfs, long totalSize) throws IOException
    {
        Directories.DataDirectory localDir = cfs.getDirectories().getWriteableLocation(totalSize);
        if (localDir == null)
            throw new IOException(format("Insufficient disk space to store %s", prettyPrintMemory(totalSize)));

        File dir = cfs.getDirectories().getLocationForDisk(cfs.getDiskBoundaries().getCorrectDiskForKey(header.firstKey));

        if (dir == null)
            return cfs.getDirectories().getDirectoryForNewSSTables();

        return dir;
    }

    @SuppressWarnings("resource")
    protected BigTableBlockWriter createWriter(ColumnFamilyStore cfs, long totalSize, Set<Component> components) throws IOException
    {
        File dataDir = getDataDir(cfs, totalSize);

        StreamReceiver streamReceiver = session.getAggregator(tableId);
        assert streamReceiver instanceof CassandraStreamReceiver;

        LifecycleTransaction txn = CassandraStreamReceiver.fromReceiver(session.getAggregator(tableId)).getTransaction();

        Descriptor desc = cfs.newSSTableDescriptor(dataDir, header.version, header.format);

        logger.debug("[Table #{}] {} Components to write: {}", cfs.metadata(), desc.filenameFor(Component.DATA), components);

        return new BigTableBlockWriter(desc, cfs.metadata, txn, components);
    }
}
