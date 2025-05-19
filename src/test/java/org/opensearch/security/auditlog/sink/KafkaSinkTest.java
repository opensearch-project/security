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
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.yaml.YamlXContent;
import org.opensearch.security.auditlog.AbstractAuditlogUnitTest;
import org.opensearch.security.auditlog.helper.MockAuditMessageFactory;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.test.helper.file.FileHelper;

import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.kafka.test.EmbeddedKafkaKraftBroker;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class KafkaSinkTest extends AbstractAuditlogUnitTest {

    private static EmbeddedKafkaBroker embeddedKafka;
    private static UncaughtExceptionHandler origHandler;

    @BeforeClass
    public static void startKafka() throws Exception {
        // Preserve the runner’s default handler (see https://bit.ly/3y17IkI)
        origHandler = Thread.getDefaultUncaughtExceptionHandler();

        // 1 broker, 1 partition per topic, create topic “compliance”
        embeddedKafka = new EmbeddedKafkaKraftBroker(1, 1, "compliance");
        embeddedKafka.afterPropertiesSet();   // <— starts the broker
    }

    @AfterClass
    public static void stopKafka() {
        if (embeddedKafka != null) {
            embeddedKafka.destroy();
        }
        Thread.setDefaultUncaughtExceptionHandler(origHandler);
    }

    @Test
    public void testKafka() throws Exception {
        String configYml = FileHelper.loadFile("auditlog/endpoints/sink/configuration_kafka.yml")
            .replace("_RPLC_BOOTSTRAP_SERVERS_", embeddedKafka.getBrokersAsString());

        Settings.Builder settingsBuilder = Settings.builder().loadFromSource(configYml, YamlXContent.yamlXContent.mediaType());

        try (KafkaConsumer<Long, String> consumer = createConsumer()) {
            consumer.subscribe(Arrays.asList("compliance"));

            Settings settings = settingsBuilder.put("path.home", ".").build();
            SinkProvider provider = new SinkProvider(settings, null, null, null, null);
            AuditLogSink sink = provider.getDefaultSink();

            try {
                assertThat(sink.getClass(), is(KafkaSink.class));
                boolean success = sink.doStore(MockAuditMessageFactory.validAuditMessage(AuditCategory.MISSING_PRIVILEGES));
                Assert.assertTrue(success);

                ConsumerRecords<Long, String> records = consumer.poll(Duration.ofSeconds(10));
                assertThat(records.count(), is(1));
            } finally {
                sink.close();
            }
        }
    }

    private KafkaConsumer<Long, String> createConsumer() {
        Properties props = new Properties();
        props.put("bootstrap.servers", embeddedKafka.getBrokersAsString());
        props.put("auto.offset.reset", "earliest");
        props.put("group.id", "mygroup" + System.currentTimeMillis() + "_" + new Random().nextDouble());
        props.put("key.deserializer", "org.apache.kafka.common.serialization.LongDeserializer");
        props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        return new KafkaConsumer<>(props);
    }
}
