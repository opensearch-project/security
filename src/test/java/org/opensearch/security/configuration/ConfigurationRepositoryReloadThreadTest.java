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

package org.opensearch.security.configuration;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.node.Node;
import org.opensearch.security.securityconf.impl.CType;

import static org.awaitility.Awaitility.await;
import static org.junit.Assert.assertEquals;

public class ConfigurationRepositoryReloadThreadTest {

    static final Settings settings = Settings.builder().put(Node.NODE_NAME_SETTING.getKey(), "test_node").build();

    @Test
    public void singleRequest() {
        Set<CType<?>> requestedConfigTypes = Set.of(CType.INTERNALUSERS, CType.ROLES);
        AtomicInteger reloadCounter = new AtomicInteger(0);
        Set<CType<?>> reloadedConfigTypes = Collections.synchronizedSet(new HashSet<>());
        ConfigurationRepository.ReloadThread subject = new ConfigurationRepository.ReloadThread(settings, (configTypes) -> {
            reloadCounter.incrementAndGet();
            reloadedConfigTypes.addAll(configTypes);
        });
        subject.start();
        subject.requestReload(requestedConfigTypes, null);

        await().until(subject::isIdle);
        assertEquals("Exactly one reload should have been performed after the reload request", 1, reloadCounter.get());
        assertEquals("The reloaded config types match the requested config types", requestedConfigTypes, reloadedConfigTypes);
    }

    @Test
    public void twoRequestsBeforeStart() {
        AtomicInteger reloadCounter = new AtomicInteger(0);
        Set<CType<?>> reloadedConfigTypes = Collections.synchronizedSet(new HashSet<>());
        ConfigurationRepository.ReloadThread subject = new ConfigurationRepository.ReloadThread(settings, (configTypes) -> {
            reloadCounter.incrementAndGet();
            reloadedConfigTypes.addAll(configTypes);
        });
        subject.requestReload(Set.of(CType.INTERNALUSERS), null);
        subject.requestReload(Set.of(CType.ROLES), null);
        subject.start();

        await().until(subject::isIdle);
        assertEquals("Exactly one reload should have been performed after the reload request", 1, reloadCounter.get());
        assertEquals(
            "The reloaded config types match the requested config types",
            Set.of(CType.INTERNALUSERS, CType.ROLES),
            reloadedConfigTypes
        );
    }

    @Test
    public void oneQueuedRequest() {
        AtomicInteger reloadCounter = new AtomicInteger(0);
        // The following boolean allows us to synchronize between the reload code and the assertion for testing purposes. This helps to
        // avoid using Thread.sleep() calls.
        AtomicBoolean reloadContinueCondition = new AtomicBoolean(false);
        Set<CType<?>> reloadedConfigTypes = Collections.synchronizedSet(new HashSet<>());
        ConfigurationRepository.ReloadThread subject = new ConfigurationRepository.ReloadThread(settings, (configTypes) -> {
            reloadCounter.incrementAndGet();
            reloadedConfigTypes.addAll(configTypes);
            await().until(reloadContinueCondition::get);
        });
        subject.start();
        subject.requestReload(Set.of(CType.INTERNALUSERS), null);
        await().until(subject::queueIsEmpty);

        subject.requestReload(Set.of(CType.ROLES), null);

        // Signal the reload function to finish
        reloadContinueCondition.set(true);

        await().until(subject::isIdle);
        assertEquals("Two reload requests have been performed now", 2, reloadCounter.get());
        assertEquals(
            "The reloaded config types match the requested config types",
            Set.of(CType.INTERNALUSERS, CType.ROLES),
            reloadedConfigTypes
        );
    }

    @Test
    public void twoQueuedRequests() {
        AtomicInteger reloadCounter = new AtomicInteger(0);
        // The following boolean allows us to synchronize between the reload code and the assertion for testing purposes. This helps to
        // avoid using Thread.sleep() calls.
        AtomicBoolean reloadContinueCondition = new AtomicBoolean(false);
        Set<CType<?>> reloadedConfigTypes = Collections.synchronizedSet(new HashSet<>());
        ConfigurationRepository.ReloadThread subject = new ConfigurationRepository.ReloadThread(settings, (configTypes) -> {
            reloadCounter.incrementAndGet();
            reloadedConfigTypes.addAll(configTypes);
            await().until(reloadContinueCondition::get);
        });
        subject.start();
        subject.requestReload(Set.of(CType.INTERNALUSERS), null);
        await().until(subject::queueIsEmpty);

        subject.requestReload(Set.of(CType.ROLES), null);
        subject.requestReload(Set.of(CType.ROLESMAPPING), null);

        // Signal the reload function to finish
        reloadContinueCondition.set(true);

        await().until(subject::isIdle);
        assertEquals("Two reload requests have been performed now", 2, reloadCounter.get());
        assertEquals(
            "The reloaded config types match the requested config types",
            Set.of(CType.INTERNALUSERS, CType.ROLES, CType.ROLESMAPPING),
            reloadedConfigTypes
        );
    }

    @Test
    public void twoQueuedRequestsWithoutTypeChange() {
        AtomicInteger reloadCounter = new AtomicInteger(0);
        // The following boolean allows us to synchronize between the reload code and the assertion for testing purposes. This helps to
        // avoid using Thread.sleep() calls.
        AtomicBoolean reloadContinueCondition = new AtomicBoolean(false);
        Set<CType<?>> reloadedConfigTypes = Collections.synchronizedSet(new HashSet<>());
        ConfigurationRepository.ReloadThread subject = new ConfigurationRepository.ReloadThread(settings, (configTypes) -> {
            reloadCounter.incrementAndGet();
            reloadedConfigTypes.addAll(configTypes);
            await().until(reloadContinueCondition::get);
        });
        subject.start();
        subject.requestReload(Set.of(CType.INTERNALUSERS), null);
        await().until(subject::queueIsEmpty);

        subject.requestReload(Set.of(CType.ROLES, CType.ROLESMAPPING), null);
        subject.requestReload(Set.of(CType.ROLESMAPPING), null);

        // Signal the reload function to finish
        reloadContinueCondition.set(true);

        await().until(subject::isIdle);
        assertEquals("Two reload requests have been performed now", 2, reloadCounter.get());
        assertEquals(
            "The reloaded config types match the requested config types",
            Set.of(CType.INTERNALUSERS, CType.ROLES, CType.ROLESMAPPING),
            reloadedConfigTypes
        );
    }

    @Test
    public void threadContinuesDespiteException() {
        AtomicInteger reloadCounter = new AtomicInteger(0);
        Set<CType<?>> reloadedConfigTypes = Collections.synchronizedSet(new HashSet<>());
        ConfigurationRepository.ReloadThread subject = new ConfigurationRepository.ReloadThread(settings, (configTypes) -> {
            reloadCounter.incrementAndGet();
            reloadedConfigTypes.addAll(configTypes);
            if (configTypes.contains(CType.AUDIT)) {
                // We use the config type AUDIT to request an exception for testing
                throw new RuntimeException("Throwing exception, as requested");
            }
        });
        subject.start();
        subject.requestReload(Set.of(CType.AUDIT), null);
        await().until(subject::queueIsEmpty);

        subject.requestReload(Set.of(CType.ROLES), null);

        await().until(subject::isIdle);
        assertEquals("Two reload requests have been performed now", 2, reloadCounter.get());
        assertEquals("The reloaded config types match the requested config types", Set.of(CType.AUDIT, CType.ROLES), reloadedConfigTypes);
    }

}
