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

package org.opensearch.security.auditlog.sink;

import org.apache.logging.log4j.Level;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.file.FileHelper;

public class SinkProviderTest {

	@Test
	public void testConfiguration() throws Exception {

		Settings settings = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/sink/configuration_all_variants.yml")).build();
		SinkProvider provider = new SinkProvider(settings, null, null, null);

		// make sure we have a debug sink as fallback
		Assert.assertEquals(DebugSink.class, provider.fallbackSink.getClass() );

		AuditLogSink sink = provider.getSink("DefaULT");
		Assert.assertEquals(sink.getClass(), DebugSink.class);

		sink = provider.getSink("endpoint1");
		Assert.assertEquals(InternalOpenSearchSink.class, sink.getClass());

		sink = provider.getSink("endpoint2");
		Assert.assertEquals(ExternalOpenSearchSink.class, sink.getClass());
		// todo: sink does not work

		sink = provider.getSink("endpoinT3");
		Assert.assertEquals(DebugSink.class, sink.getClass());

		// no valid type
		sink = provider.getSink("endpoint4");
		Assert.assertEquals(null, sink);

		sink = provider.getSink("endpoint2");
		Assert.assertEquals(ExternalOpenSearchSink.class, sink.getClass());
		// todo: sink does not work, no valid config

		// no valid type
		sink = provider.getSink("endpoint6");
		Assert.assertEquals(null, sink);

		// no valid type
		sink = provider.getSink("endpoint7");
		Assert.assertEquals(null, sink);

		sink = provider.getSink("endpoint8");
		Assert.assertEquals(DebugSink.class, sink.getClass());

		// wrong type in config
		sink = provider.getSink("endpoint9");
		Assert.assertEquals(ExternalOpenSearchSink.class, sink.getClass());

		// log4j, valid configuration
		sink = provider.getSink("endpoint10");
		Assert.assertEquals(Log4JSink.class, sink.getClass());
		Log4JSink lsink = (Log4JSink)sink;
		Assert.assertEquals("loggername", lsink.loggerName);
		Assert.assertEquals(Level.WARN, lsink.logLevel);

		// log4j, no level, fallback to default
		sink = provider.getSink("endpoint11");
		Assert.assertEquals(Log4JSink.class, sink.getClass());
		lsink = (Log4JSink)sink;
		Assert.assertEquals("loggername", lsink.loggerName);
		Assert.assertEquals(Level.INFO, lsink.logLevel);

		// log4j, wrong level, fallback to log4j default
		sink = provider.getSink("endpoint12");
		Assert.assertEquals(Log4JSink.class, sink.getClass());
		lsink = (Log4JSink)sink;
		Assert.assertEquals("loggername", lsink.loggerName);
		Assert.assertEquals(Level.DEBUG, lsink.logLevel);

	}

	@Test
	public void testNoMultipleEndpointsConfiguration() throws Exception {
		Settings settings = Settings.builder().loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/sink/configuration_no_multiple_endpoints.yml")).build();
		SinkProvider provider = new SinkProvider(settings, null, null, null);
		InternalOpenSearchSink sink = (InternalOpenSearchSink)provider.defaultSink;
		Assert.assertEquals("myownindex", sink.index);
		Assert.assertEquals("auditevents", sink.type);
	}


}
