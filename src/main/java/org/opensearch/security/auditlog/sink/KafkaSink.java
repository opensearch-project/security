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

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Properties;

import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.serialization.LongSerializer;
import org.apache.kafka.common.serialization.StringSerializer;

import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;

public class KafkaSink extends AuditLogSink {

    private final String[] mandatoryProperties = new String[] { "bootstrap_servers", "topic_name" };
    private boolean valid = true;
    private Producer<Long, String> producer;
    private String topicName;

    // allows MockProducer in tests.
    @FunctionalInterface
    public interface ProducerFactory {
        Producer<Long, String> create() throws Exception;
    }

    @SuppressWarnings("removal")
    public KafkaSink(final String name, final Settings settings, final String settingsPrefix, AuditLogSink fallbackSink) {
        super(name, settings, settingsPrefix, fallbackSink);

        Settings sinkSettings = settings.getAsSettings(settingsPrefix);
        checkMandatorySinkSettings(sinkSettings);

        if (!valid) {
            log.error("Failed to configure Kafka producer, please check the logfile.");
            return;
        }

        final Properties producerProps = new Properties();
        for (String key : sinkSettings.names()) {
            if (!key.equals("topic_name")) {
                producerProps.put(key.replace('_', '.'), sinkSettings.get(key));
            }
        }

        producerProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, LongSerializer.class.getName());
        producerProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        this.topicName = sinkSettings.get("topic_name");
        this.producer = createProducerPrivileged(() -> new KafkaProducer<>(producerProps));
    }

    /**
     * Useful in tests to pass a MockProducer without needing a broker or Docker.
     */
    @SuppressWarnings("removal")
    public KafkaSink(
        final String name,
        final Settings settings,
        final String settingsPrefix,
        final AuditLogSink fallbackSink,
        final ProducerFactory producerFactory,
        final String topicName
    ) {
        super(name, settings, settingsPrefix, fallbackSink);
        if (topicName == null || topicName.isEmpty()) {
            log.error("No value for topic_name provided in injected constructor, this endpoint will not work.");
            this.valid = false;
            return;
        }
        this.topicName = topicName;
        this.producer = createProducerPrivileged(producerFactory);
        // valid already false if producer creation failed
    }

    @SuppressWarnings("removal")
    private Producer<Long, String> createProducerPrivileged(ProducerFactory factory) {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Producer<Long, String>>() {
                @Override
                public Producer<Long, String> run() throws Exception {
                    return factory.create();
                }
            });
        } catch (PrivilegedActionException e) {
            log.error("Failed to configure Kafka producer due to ", e);
            this.valid = false;
            return null;
        }
    }

    @Override
    protected boolean doStore(AuditMessage msg) {
        if (!valid || producer == null) {
            return false;
        }
        ProducerRecord<Long, String> data = new ProducerRecord<>(topicName, msg.toJson());
        producer.send(data, new Callback() {
            @Override
            public void onCompletion(RecordMetadata metadata, Exception exception) {
                if (exception != null) {
                    log.error("Could not store message on Kafka topic {}", topicName, exception);
                    fallbackSink.store(msg);
                }
            }
        });
        return true;
    }

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }

    private void checkMandatorySinkSettings(Settings sinkSettings) {
        for (String mandatory : mandatoryProperties) {
            String value = sinkSettings.get(mandatory);
            if (value == null || value.length() == 0) {
                log.error("No value for {} provided in configuration, this endpoint will not work.", value);
                this.valid = false;
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (producer != null) {
            valid = false;
            producer.close();
        }
    }
}
