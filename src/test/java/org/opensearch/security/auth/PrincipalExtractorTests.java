package org.opensearch.security.auth;

import java.util.List;
import java.util.stream.StreamSupport;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.commons.ConfigConstants;
import org.opensearch.node.Node;
import org.opensearch.rule.SecurityAttribute;
import org.opensearch.rule.attribute_extractor.AttributeExtractor;
import org.opensearch.rule.autotagging.Attribute;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PrincipalExtractorTests {

    private ThreadPool threadPool;

    @Before
    public void setup() {
        threadPool = new ThreadPool(Settings.builder().put(Node.NODE_NAME_SETTING.getKey(), "name").build());
    }

    @Test
    public void testGetAttribute() {
        PrincipalExtractor extractor = new PrincipalExtractor(threadPool);
        Attribute attribute = extractor.getAttribute();
        assertEquals(SecurityAttribute.PRINCIPAL, attribute);
        threadPool.shutdown();
    }

    @Test
    public void testExtractWithNoUser() {
        PrincipalExtractor extractor = new PrincipalExtractor(threadPool);
        assertFalse(extractor.extract().iterator().hasNext());
    }

    @Test
    public void testExtractWithUser() {
        ThreadContext threadContext = threadPool.getThreadContext();
        threadContext.putTransient(ConfigConstants.OPENSEARCH_SECURITY_USER_INFO_THREAD_CONTEXT, "alice||all_access|");
        PrincipalExtractor extractor = new PrincipalExtractor(threadPool);
        Iterable<String> principalIter = extractor.extract();
        List<String> principals = StreamSupport.stream(principalIter.spliterator(), false).toList();

        assertTrue(principals.contains("username_alice"));
        assertTrue(principals.contains("role_all_access"));
        assertEquals(2, principals.size());
    }

    @Test
    public void testCombinationStyle() {
        PrincipalExtractor extractor = new PrincipalExtractor(threadPool);
        assertEquals(AttributeExtractor.CombinationStyle.OR, extractor.getCombinationStyle());
    }
}
