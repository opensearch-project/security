/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.configuration;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.index.Index;
import org.opensearch.index.IndexService;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SystemIndexSearcherWrapperTest {
    @Test
    public void identifiesDefaultSecurityIndex() {
        assertTrue(isSecurityIndex(Settings.EMPTY, ".opendistro_security"));
        assertFalse(isSecurityIndex(Settings.EMPTY, ".opensearch_security"));
    }

    @Test
    public void identifiesOnlyConfiguredSecurityIndex() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ".custom-security").build();
        assertTrue(isSecurityIndex(settings, ".custom-security"));
        assertFalse(isSecurityIndex(settings, ".opendistro_security"));
        assertFalse(isSecurityIndex(settings, ".custom-security-backup"));
    }

    private boolean isSecurityIndex(Settings settings, String indexName) {
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(settings));
        IndexService indexService = mock(IndexService.class);
        when(indexService.index()).thenReturn(new Index(indexName, "test-uuid"));
        when(indexService.getThreadPool()).thenReturn(threadPool);
        return new SystemIndexSearcherWrapper(indexService, settings, null, null, null).isSecurityIndexRequest();
    }
}
