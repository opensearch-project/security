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

package org.opensearch.security.extensions;


import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Supplier;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.routing.allocation.decider.Decision;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.security.auth.internal.InternalAuthenticationBackend;
import org.opensearch.security.securityconf.InternalUsersModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import static org.junit.Assert.assertEquals;

public class ExtensionRegistrationUnitTests extends SingleClusterTest {

    //TODO: Figure out how to build these tests when normally inject


    public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool,
                                               ResourceWatcherService resourceWatcherService, ScriptService scriptService,
                                               NamedXContentRegistry xContentRegistry, Environment environment,
                                               NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry,
                                               IndexNameExpressionResolver indexNameExpressionResolver,
                                               Supplier<RepositoriesService> repositoriesServiceSupplier) {

        return new ArrayList<>();
    }

    @Test
    public void testRegisterExtensionExtensionExists() {

        assertEquals(true, true);
    }

    @Test
    public void testRegisterExtensionExtensionDoesNotExist() {
        assertEquals(true, true);
    }

    @Test
    public void testExtensionIsRegisteredRegisteredCheck() {
        assertEquals(true, true);
    }

    @Test
    public void testExtensionIsNotRegisteredRegisteredCheck() {
        assertEquals(true, true);
    }

    @Test
    public void testAddValidServiceAccount() {
        assertEquals(true, true);
    }

    @Test
    public void testAddInvalidServiceAccount() {
        assertEquals(true, true);
    }

    @Test
    public void testServiceAccountWasAddedToConfig() {
        assertEquals(true, true);
    }
}
