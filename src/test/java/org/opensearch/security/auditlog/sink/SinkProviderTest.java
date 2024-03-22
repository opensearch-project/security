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

import org.apache.logging.log4j.Level;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.helper.file.FileHelper;

public class SinkProviderTest {

    @Test
    public void testConfiguration() throws Exception {

        Settings settings = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/sink/configuration_all_variants.yml"))
            .build();
        SinkProvider provider = new SinkProvider(settings, null, null, null);

        // make sure we have a debug sink as fallback
        Assert.assertEquals(DebugSink.class, provider.fallbackSink.getClass());

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
        Log4JSink lsink = (Log4JSink) sink;
        Assert.assertEquals("loggername", lsink.loggerName);
        Assert.assertEquals(Level.WARN, lsink.logLevel);

        // log4j, no level, fallback to default
        sink = provider.getSink("endpoint11");
        Assert.assertEquals(Log4JSink.class, sink.getClass());
        lsink = (Log4JSink) sink;
        Assert.assertEquals("loggername", lsink.loggerName);
        Assert.assertEquals(Level.INFO, lsink.logLevel);

        // log4j, wrong level, fallback to log4j default
        sink = provider.getSink("endpoint12");
        Assert.assertEquals(Log4JSink.class, sink.getClass());
        lsink = (Log4JSink) sink;
        Assert.assertEquals("loggername", lsink.loggerName);
        Assert.assertEquals(Level.DEBUG, lsink.logLevel);

        sink = provider.getSink("endpoint13");
        Assert.assertEquals(Log4JSink.class, sink.getClass());
        lsink = (Log4JSink) sink;
        Assert.assertEquals("audit", lsink.loggerName);
        Assert.assertEquals(Level.INFO, lsink.logLevel);

    }

    @Test
    public void testNoMultipleEndpointsConfiguration() throws Exception {
        Settings settings = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/sink/configuration_no_multiple_endpoints.yml"))
            .build();
        SinkProvider provider = new SinkProvider(settings, null, null, null);
        InternalOpenSearchSink sink = (InternalOpenSearchSink) provider.defaultSink;
        Assert.assertEquals("myownindex", sink.index);
        Assert.assertEquals("auditevents", sink.type);
    }

}
