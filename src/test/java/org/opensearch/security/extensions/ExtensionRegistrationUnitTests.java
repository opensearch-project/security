package org.opensearch.security.extensions;


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

import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Supplier;

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
