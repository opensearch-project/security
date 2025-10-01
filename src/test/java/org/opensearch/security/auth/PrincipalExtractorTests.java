/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.auth;

import java.util.List;
import java.util.stream.StreamSupport;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.node.Node;
import org.opensearch.rule.attribute_extractor.AttributeExtractor;
import org.opensearch.rule.autotagging.Attribute;
import org.opensearch.security.support.ConfigConstants;
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
        assertEquals(PrincipalAttribute.PRINCIPAL, attribute);
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
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT, "alice||all_access|");
        PrincipalExtractor extractor = new PrincipalExtractor(threadPool);
        Iterable<String> principalIter = extractor.extract();
        List<String> principals = StreamSupport.stream(principalIter.spliterator(), false).toList();
        assertTrue(principals.contains("username|alice"));
        assertTrue(principals.contains("role|all_access"));
        assertEquals(2, principals.size());
    }

    @Test
    public void testCombinationStyle() {
        PrincipalExtractor extractor = new PrincipalExtractor(threadPool);
        assertEquals(AttributeExtractor.LogicalOperator.OR, extractor.getLogicalOperator());
    }
}
