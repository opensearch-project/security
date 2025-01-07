/// *
// * SPDX-License-Identifier: Apache-2.0
// *
// * The OpenSearch Contributors require contributions made to
// * this file be licensed under the Apache-2.0 license or a
// * compatible open source license.
// */
//
// package tests.java.opensearch.security.spi.resources;
//
// import org.hamcrest.MatcherAssert;
// import org.mockito.Mock;
// import org.mockito.MockitoAnnotations;
// import org.opensearch.OpenSearchException;
// import org.opensearch.accesscontrol.resources.fallback.DefaultResourceAccessControlExtension;
// import org.opensearch.client.Client;
// import org.opensearch.plugins.ResourceAccessControlPlugin;
// import org.opensearch.plugins.ResourceSharingExtension;
// import org.opensearch.test.OpenSearchTestCase;
// import org.opensearch.threadpool.ThreadPool;
//
// import java.util.ArrayList;
// import java.util.Arrays;
// import java.util.Collections;
// import java.util.List;
//
// import static org.hamcrest.Matchers.*;
// import static org.mockito.Mockito.mock;
//
// public class ResourceServiceTests extends OpenSearchTestCase {
//
// @Mock
// private Client client;
//
// @Mock
// private ThreadPool threadPool;
//
// public void setup() {
// MockitoAnnotations.openMocks(this);
// }
//
// public void testGetResourceAccessControlPluginReturnsInitializedPlugin() {
// setup();
// Client mockClient = mock(Client.class);
// ThreadPool mockThreadPool = mock(ThreadPool.class);
//
// ResourceAccessControlPlugin mockPlugin = mock(ResourceAccessControlPlugin.class);
// List<ResourceAccessControlPlugin> plugins = new ArrayList<>();
// plugins.add(mockPlugin);
//
// List<ResourceSharingExtension> resourcePlugins = new ArrayList<>();
//
// ResourceService resourceService = new ResourceService(plugins, resourcePlugins, mockClient, mockThreadPool);
//
// ResourceAccessControlPlugin result = resourceService.getResourceAccessControlPlugin();
//
// MatcherAssert.assertThat(mockPlugin, equalTo(result));
// }
//
// public void testGetResourceAccessControlPlugin_NoPlugins() {
// setup();
// List<ResourceAccessControlPlugin> emptyPlugins = new ArrayList<>();
// List<ResourceSharingExtension> resourcePlugins = new ArrayList<>();
//
// ResourceService resourceService = new ResourceService(emptyPlugins, resourcePlugins, client, threadPool);
//
// ResourceAccessControlPlugin result = resourceService.getResourceAccessControlPlugin();
//
// assertNotNull(result);
// MatcherAssert.assertThat(result, instanceOf(DefaultResourceAccessControlExtension.class));
// }
//
// public void testGetResourceAccessControlPlugin_SinglePlugin() {
// setup();
// ResourceAccessControlPlugin mockPlugin = mock(ResourceAccessControlPlugin.class);
// List<ResourceAccessControlPlugin> singlePlugin = Arrays.asList(mockPlugin);
// List<ResourceSharingExtension> resourcePlugins = new ArrayList<>();
//
// ResourceService resourceService = new ResourceService(singlePlugin, resourcePlugins, client, threadPool);
//
// ResourceAccessControlPlugin result = resourceService.getResourceAccessControlPlugin();
//
// assertNotNull(result);
// assertSame(mockPlugin, result);
// }
//
// public void testListResourcePluginsReturnsPluginList() {
// setup();
// List<ResourceAccessControlPlugin> resourceACPlugins = new ArrayList<>();
// List<ResourceSharingExtension> expectedResourcePlugins = new ArrayList<>();
// expectedResourcePlugins.add(mock(ResourceSharingExtension.class));
// expectedResourcePlugins.add(mock(ResourceSharingExtension.class));
//
// ResourceService resourceService = new ResourceService(resourceACPlugins, expectedResourcePlugins, client, threadPool);
//
// List<ResourceSharingExtension> actualResourcePlugins = resourceService.listResourcePlugins();
//
// MatcherAssert.assertThat(expectedResourcePlugins, equalTo(actualResourcePlugins));
// }
//
// public void testListResourcePlugins_concurrentModification() {
// setup();
// List<ResourceAccessControlPlugin> emptyACPlugins = Collections.emptyList();
// List<ResourceSharingExtension> resourcePlugins = new ArrayList<>();
// resourcePlugins.add(mock(ResourceSharingExtension.class));
//
// ResourceService resourceService = new ResourceService(emptyACPlugins, resourcePlugins, client, threadPool);
//
// Thread modifierThread = new Thread(() -> { resourcePlugins.add(mock(ResourceSharingExtension.class)); });
//
// modifierThread.start();
//
// List<ResourceSharingExtension> result = resourceService.listResourcePlugins();
//
// assertNotNull(result);
// // The size could be either 1 or 2 depending on the timing of the concurrent modification
// assertTrue(result.size() == 1 || result.size() == 2);
// }
//
// public void testListResourcePlugins_emptyList() {
// setup();
// List<ResourceAccessControlPlugin> emptyACPlugins = Collections.emptyList();
// List<ResourceSharingExtension> emptyResourcePlugins = Collections.emptyList();
//
// ResourceService resourceService = new ResourceService(emptyACPlugins, emptyResourcePlugins, client, threadPool);
//
// List<ResourceSharingExtension> result = resourceService.listResourcePlugins();
//
// assertNotNull(result);
// MatcherAssert.assertThat(result, is(empty()));
// }
//
// public void testListResourcePlugins_immutability() {
// setup();
// List<ResourceAccessControlPlugin> emptyACPlugins = Collections.emptyList();
// List<ResourceSharingExtension> resourcePlugins = new ArrayList<>();
// resourcePlugins.add(mock(ResourceSharingExtension.class));
//
// ResourceService resourceService = new ResourceService(emptyACPlugins, resourcePlugins, client, threadPool);
//
// List<ResourceSharingExtension> result = resourceService.listResourcePlugins();
//
// assertThrows(UnsupportedOperationException.class, () -> { result.add(mock(ResourceSharingExtension.class)); });
// }
//
// public void testResourceServiceConstructorWithMultiplePlugins() {
// setup();
// ResourceAccessControlPlugin plugin1 = mock(ResourceAccessControlPlugin.class);
// ResourceAccessControlPlugin plugin2 = mock(ResourceAccessControlPlugin.class);
// List<ResourceAccessControlPlugin> resourceACPlugins = Arrays.asList(plugin1, plugin2);
// List<ResourceSharingExtension> resourcePlugins = Arrays.asList(mock(ResourceSharingExtension.class));
//
// assertThrows(OpenSearchException.class, () -> { new ResourceService(resourceACPlugins, resourcePlugins, client, threadPool); });
// }
//
// public void testResourceServiceConstructor_MultiplePlugins() {
// setup();
// ResourceAccessControlPlugin mockPlugin1 = mock(ResourceAccessControlPlugin.class);
// ResourceAccessControlPlugin mockPlugin2 = mock(ResourceAccessControlPlugin.class);
// List<ResourceAccessControlPlugin> multiplePlugins = Arrays.asList(mockPlugin1, mockPlugin2);
// List<ResourceSharingExtension> resourcePlugins = new ArrayList<>();
//
// assertThrows(
// org.opensearch.OpenSearchException.class,
// () -> { new ResourceService(multiplePlugins, resourcePlugins, client, threadPool); }
// );
// }
//
// public void testResourceServiceWithMultipleResourceACPlugins() {
// setup();
// List<ResourceAccessControlPlugin> multipleResourceACPlugins = Arrays.asList(
// mock(ResourceAccessControlPlugin.class),
// mock(ResourceAccessControlPlugin.class)
// );
// List<ResourceSharingExtension> resourcePlugins = new ArrayList<>();
//
// assertThrows(
// OpenSearchException.class,
// () -> { new ResourceService(multipleResourceACPlugins, resourcePlugins, client, threadPool); }
// );
// }
//
// public void testResourceServiceWithNoAccessControlPlugin() {
// setup();
// List<ResourceAccessControlPlugin> resourceACPlugins = new ArrayList<>();
// List<ResourceSharingExtension> resourcePlugins = new ArrayList<>();
// Client client = mock(Client.class);
// ThreadPool threadPool = mock(ThreadPool.class);
//
// ResourceService resourceService = new ResourceService(resourceACPlugins, resourcePlugins, client, threadPool);
//
// MatcherAssert.assertThat(resourceService.getResourceAccessControlPlugin(), instanceOf(DefaultResourceAccessControlExtension.class));
// MatcherAssert.assertThat(resourcePlugins, equalTo(resourceService.listResourcePlugins()));
// }
//
// public void testResourceServiceWithNoResourceACPlugins() {
// setup();
// List<ResourceAccessControlPlugin> emptyResourceACPlugins = new ArrayList<>();
// List<ResourceSharingExtension> resourcePlugins = new ArrayList<>();
//
// ResourceService resourceService = new ResourceService(emptyResourceACPlugins, resourcePlugins, client, threadPool);
//
// assertNotNull(resourceService.getResourceAccessControlPlugin());
// }
//
// public void testResourceServiceWithSingleResourceAccessControlPlugin() {
// setup();
// List<ResourceAccessControlPlugin> resourceACPlugins = new ArrayList<>();
// ResourceAccessControlPlugin mockPlugin = mock(ResourceAccessControlPlugin.class);
// resourceACPlugins.add(mockPlugin);
//
// List<ResourceSharingExtension> resourcePlugins = new ArrayList<>();
//
// ResourceService resourceService = new ResourceService(resourceACPlugins, resourcePlugins, client, threadPool);
//
// assertNotNull(resourceService);
// MatcherAssert.assertThat(mockPlugin, equalTo(resourceService.getResourceAccessControlPlugin()));
// MatcherAssert.assertThat(resourcePlugins, equalTo(resourceService.listResourcePlugins()));
// }
// }
