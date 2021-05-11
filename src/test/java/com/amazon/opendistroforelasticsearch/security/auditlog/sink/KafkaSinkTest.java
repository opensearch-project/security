/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auditlog.sink;

import java.time.Duration;
import java.util.Arrays;
import java.util.Properties;

import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.yaml.YamlXContent;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.springframework.kafka.test.rule.EmbeddedKafkaRule;

import scala.util.Random;

import com.amazon.opendistroforelasticsearch.security.auditlog.AbstractAuditlogiUnitTest;
import com.amazon.opendistroforelasticsearch.security.auditlog.helper.MockAuditMessageFactory;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;

public class KafkaSinkTest extends AbstractAuditlogiUnitTest {

	@ClassRule
	public static EmbeddedKafkaRule embeddedKafka = new EmbeddedKafkaRule(1, true, 1, "compliance");

	@Test
	public void testKafka() throws Exception {
	    String configYml = FileHelper.loadFile("auditlog/endpoints/sink/configuration_kafka.yml");
		configYml = configYml.replace("_RPLC_BOOTSTRAP_SERVERS_",embeddedKafka.getEmbeddedKafka().getBrokersAsString());
		Settings.Builder settingsBuilder = Settings.builder().loadFromSource(configYml, YamlXContent.yamlXContent.type());
		try(KafkaConsumer<Long, String> consumer = createConsumer()) {
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
		props.put("group.id", "mygroup"+System.currentTimeMillis()+"_"+new Random().nextDouble());
		props.put("key.deserializer", "org.apache.kafka.common.serialization.LongDeserializer");
		props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
		return new KafkaConsumer<>(props);
	}
}
