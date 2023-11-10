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

import java.lang.Thread.UncaughtExceptionHandler;
import java.time.Duration;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.yaml.YamlXContent;
import org.opensearch.security.auditlog.AbstractAuditlogiUnitTest;
import org.opensearch.security.auditlog.helper.MockAuditMessageFactory;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.test.helper.file.FileHelper;

import org.springframework.kafka.test.rule.EmbeddedKafkaRule;

public class KafkaSinkTest extends AbstractAuditlogiUnitTest {

    @ClassRule
    public static EmbeddedKafkaRule embeddedKafka = new EmbeddedKafkaRule(1, true, 1, "compliance") {
        // Prevents test exceptions from randomized runner, see https://bit.ly/3y17IkI
        private UncaughtExceptionHandler currentHandler;

        @Override
        public void before() {
            currentHandler = Thread.getDefaultUncaughtExceptionHandler();
            super.before();
        }

        @Override
        public void after() {
            super.after();
            Thread.setDefaultUncaughtExceptionHandler(currentHandler);
        }
    };

    @Test
    public void testKafka() throws Exception {
        String configYml = FileHelper.loadFile("auditlog/endpoints/sink/configuration_kafka.yml");
        configYml = configYml.replace("_RPLC_BOOTSTRAP_SERVERS_", embeddedKafka.getEmbeddedKafka().getBrokersAsString());
        Settings.Builder settingsBuilder = Settings.builder().loadFromSource(configYml, YamlXContent.yamlXContent.mediaType());
        try (KafkaConsumer<Long, String> consumer = createConsumer()) {
            consumer.subscribe(Arrays.asList("compliance"));

            Settings settings = settingsBuilder.put("path.home", ".").build();
            SinkProvider provider = new SinkProvider(settings, null, null, null);
            AuditLogSink sink = provider.getDefaultSink();
            try {
                Assert.assertEquals(KafkaSink.class, sink.getClass());
                boolean success = sink.doStore(MockAuditMessageFactory.validAuditMessage(AuditCategory.MISSING_PRIVILEGES));
                Assert.assertTrue(success);
                ConsumerRecords<Long, String> records = consumer.poll(Duration.ofSeconds(10));
                Assert.assertEquals(1, records.count());
            } finally {
                sink.close();
            }
        }

    }

    private KafkaConsumer<Long, String> createConsumer() {
        Properties props = new Properties();
        props.put("bootstrap.servers", embeddedKafka.getEmbeddedKafka().getBrokersAsString());
        props.put("auto.offset.reset", "earliest");
        props.put("group.id", "mygroup" + System.currentTimeMillis() + "_" + new Random().nextDouble());
        props.put("key.deserializer", "org.apache.kafka.common.serialization.LongDeserializer");
        props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        return new KafkaConsumer<>(props);
    }
}
