/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.auditlog.sink;

import org.apache.kafka.clients.producer.MockProducer;
import org.apache.kafka.common.serialization.LongSerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.helper.LoggingSink;
import org.opensearch.security.auditlog.helper.MockAuditMessageFactory;
import org.opensearch.security.auditlog.impl.AuditCategory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class KafkaSinkTest {

    @Test
    public void testKafkaSinkWithMockProducer() {
        MockProducer<Long, String> mock = new MockProducer<>(true, new LongSerializer(), new StringSerializer());

        LoggingSink fallback = new LoggingSink("test", Settings.EMPTY, null, null);
        KafkaSink sink = new KafkaSink("kafka", Settings.EMPTY, "opensearch.audit.config", fallback, () -> mock, "compliance");

        sink.store(MockAuditMessageFactory.validAuditMessage(AuditCategory.MISSING_PRIVILEGES));
        assertEquals(1, mock.history().size());
        assertEquals("compliance", mock.history().get(0).topic());
        assertTrue(mock.history().get(0).value().contains("MISSING_PRIVILEGES"));
    }
}
