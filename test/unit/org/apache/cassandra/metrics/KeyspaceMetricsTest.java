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

package org.apache.cassandra.metrics;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.function.LongSupplier;

import org.apache.cassandra.OrderedJUnit4ClassRunner;
import org.apache.cassandra.SchemaLoader;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.schema.Schema;
import org.apache.cassandra.service.EmbeddedCassandraService;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.Session;


@RunWith(OrderedJUnit4ClassRunner.class)
public class KeyspaceMetricsTest extends SchemaLoader
{

    private static Session session;

    @BeforeClass()
    public static void setup() throws ConfigurationException, IOException
    {
        Schema.instance.clear();

        EmbeddedCassandraService cassandra = new EmbeddedCassandraService();
        cassandra.start();

        Cluster cluster = Cluster.builder().addContactPoint("127.0.0.1").withPort(DatabaseDescriptor.getNativeTransportPort()).build();
        session = cluster.connect();
    }

    @Test
    public void registerUnregister()
    {
        String keyspaceN = "junit" + System.nanoTime();
        CassandraMetricsRegistry registry = CassandraMetricsRegistry.Metrics;
        LongSupplier count = () -> registry.getNames().stream().filter((n) -> n.contains(keyspaceN)).count();

        // no metrics before create
        assertEquals(0, count.getAsLong());

        session.execute(String.format(
                "CREATE KEYSPACE %s WITH replication = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };",
                keyspaceN));
        // some metrics
        assertTrue(count.getAsLong() > 0);

        session.execute(String.format("DROP KEYSPACE %s;", keyspaceN));
        // no metrics after drop
        assertEquals(0, count.getAsLong());
    }
}