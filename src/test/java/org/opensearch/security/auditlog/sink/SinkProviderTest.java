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
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.helper.file.FileHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class SinkProviderTest {

    @Test
    public void testConfiguration() throws Exception {

        Settings settings = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/sink/configuration_all_variants.yml"))
            .build();
        SinkProvider provider = new SinkProvider(settings, null, null, null);

        // make sure we have a debug sink as fallback
        assertThat(provider.fallbackSink.getClass(), is(DebugSink.class));

        AuditLogSink sink = provider.getSink("DefaULT");
        assertThat(DebugSink.class, is(sink.getClass()));

        sink = provider.getSink("endpoint1");
        assertThat(sink.getClass(), is(InternalOpenSearchSink.class));

        sink = provider.getSink("endpoint2");
        assertThat(sink.getClass(), is(ExternalOpenSearchSink.class));
        // todo: sink does not work

        sink = provider.getSink("endpoinT3");
        assertThat(sink.getClass(), is(DebugSink.class));

        // no valid type
        sink = provider.getSink("endpoint4");
        assertThat(sink, is(nullValue()));

        sink = provider.getSink("endpoint2");
        assertThat(sink.getClass(), is(ExternalOpenSearchSink.class));
        // todo: sink does not work, no valid config

        // no valid type
        sink = provider.getSink("endpoint6");
        assertThat(sink, is(nullValue()));

        // no valid type
        sink = provider.getSink("endpoint7");
        assertThat(sink, is(nullValue()));

        sink = provider.getSink("endpoint8");
        assertThat(sink.getClass(), is(DebugSink.class));

        // wrong type in config
        sink = provider.getSink("endpoint9");
        assertThat(sink.getClass(), is(ExternalOpenSearchSink.class));

        // log4j, valid configuration
        sink = provider.getSink("endpoint10");
        assertThat(sink.getClass(), is(Log4JSink.class));
        Log4JSink lsink = (Log4JSink) sink;
        assertThat(lsink.loggerName, is("loggername"));
        assertThat(lsink.logLevel, is(Level.WARN));

        // log4j, no level, fallback to default
        sink = provider.getSink("endpoint11");
        assertThat(sink.getClass(), is(Log4JSink.class));
        lsink = (Log4JSink) sink;
        assertThat(lsink.loggerName, is("loggername"));
        assertThat(lsink.logLevel, is(Level.INFO));

        // log4j, wrong level, fallback to log4j default
        sink = provider.getSink("endpoint12");
        assertThat(sink.getClass(), is(Log4JSink.class));
        lsink = (Log4JSink) sink;
        assertThat(lsink.loggerName, is("loggername"));
        assertThat(lsink.logLevel, is(Level.DEBUG));

        sink = provider.getSink("endpoint13");
        assertThat(sink.getClass(), is(Log4JSink.class));
        lsink = (Log4JSink) sink;
        assertThat(lsink.loggerName, is("audit"));
        assertThat(lsink.logLevel, is(Level.INFO));

    }

    @Test
    public void testNoMultipleEndpointsConfiguration() throws Exception {
        Settings settings = Settings.builder()
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/sink/configuration_no_multiple_endpoints.yml"))
            .build();
        SinkProvider provider = new SinkProvider(settings, null, null, null);
        InternalOpenSearchSink sink = (InternalOpenSearchSink) provider.defaultSink;
        assertThat(sink.index, is("myownindex"));
        assertThat(sink.type, is("auditevents"));
    }

}
