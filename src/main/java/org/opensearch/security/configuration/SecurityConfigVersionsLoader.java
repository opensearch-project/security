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

package org.opensearch.security.configuration;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.transport.client.Client;

public class SecurityConfigVersionsLoader {
    private static final Logger log = LogManager.getLogger(SecurityConfigVersionsLoader.class);

    private final Client client;
    private final String opendistroSecurityConfigVersionsIndex;

    public SecurityConfigVersionsLoader(Client client, Settings settings) {
        this.client = client;
        this.opendistroSecurityConfigVersionsIndex = settings.get(
            ConfigConstants.SECURITY_CONFIG_VERSIONS_INDEX_NAME,
            ConfigConstants.OPENDISTRO_SECURITY_CONFIG_VERSIONS_INDEX
        );
    }

    private void getSecurityConfigVersionDocAsync(ActionListener<SecurityConfigVersionDocument> listener) {
        GetRequest getRequest = new GetRequest(opendistroSecurityConfigVersionsIndex, "opendistro_security_config_versions");

        client.get(getRequest, new ActionListener<>() {
            @Override
            public void onResponse(GetResponse getResponse) {
                try {
                    if (!getResponse.isExists()) {
                        log.warn("Config versions document not found in {}", opendistroSecurityConfigVersionsIndex);
                        listener.onResponse(new SecurityConfigVersionDocument()); // return empty doc
                        return;
                    }

                    SecurityConfigVersionDocument doc = DefaultObjectMapper.readValue(
                        getResponse.getSourceAsString(),
                        SecurityConfigVersionDocument.class
                    );

                    doc.setSeqNo(getResponse.getSeqNo());
                    doc.setPrimaryTerm(getResponse.getPrimaryTerm());

                    listener.onResponse(doc);
                } catch (IOException e) {
                    log.error("Failed to parse config versions doc", e);
                    listener.onFailure(e);
                }
            }

            @Override
            public void onFailure(Exception e) {
                log.error("Failed to load config versions doc from {}", opendistroSecurityConfigVersionsIndex, e);
                listener.onFailure(e);
            }
        });
    }

    public void loadLatestVersionAsync(ActionListener<SecurityConfigVersionDocument.Version<?>> listener) {
        getSecurityConfigVersionDocAsync(new ActionListener<>() {
            @Override
            public void onResponse(SecurityConfigVersionDocument doc) {
                List<SecurityConfigVersionDocument.Version<?>> versions = doc.getVersions();
                if (versions == null || versions.isEmpty()) {
                    listener.onResponse(null);
                } else {
                    sortVersionsById(versions);
                    listener.onResponse(versions.get(versions.size() - 1)); // latest
                }
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    public SecurityConfigVersionDocument.Version<?> loadLatestVersion() {
        CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<SecurityConfigVersionDocument.Version<?>> result = new AtomicReference<>();

        final Exception[] failure = new Exception[1];

        loadLatestVersionAsync(new ActionListener<>() {
            @Override
            public void onResponse(SecurityConfigVersionDocument.Version<?> version) {
                result.set(version);
                latch.countDown();
            }

            @Override
            public void onFailure(Exception e) {
                failure[0] = e;
                latch.countDown();
            }
        });

        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new RuntimeException("Timeout waiting for loadLatestVersionAsync()");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while waiting for config version load", e);
        }

        if (failure[0] != null) {
            throw new RuntimeException("Failed to load latest config version", failure[0]);
        }

        return result.get();
    }

    public SecurityConfigVersionDocument loadFullDocument() {
        final AtomicReference<SecurityConfigVersionDocument> result = new AtomicReference<>();

        final Exception[] error = new Exception[1];
        final CountDownLatch latch = new CountDownLatch(1);

        getSecurityConfigVersionDocAsync(new ActionListener<>() {
            @Override
            public void onResponse(SecurityConfigVersionDocument doc) {
                result.set(doc);
                ;
                latch.countDown();
            }

            @Override
            public void onFailure(Exception e) {
                error[0] = e;
                latch.countDown();
            }
        });

        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new RuntimeException("Timeout while loading full config version document");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while loading full config version document", e);
        }

        if (error[0] != null) {
            throw new RuntimeException("Failed to load full config version document", error[0]);
        }

        return result.get() != null ? result.get() : new SecurityConfigVersionDocument();

    }

    public static <T> void sortVersionsById(List<SecurityConfigVersionDocument.Version<?>> versions) {
        versions.sort((v1, v2) -> {
            try {
                int n1 = Integer.parseInt(v1.getVersion_id().substring(1));
                int n2 = Integer.parseInt(v2.getVersion_id().substring(1));
                return Integer.compare(n1, n2);
            } catch (Exception e) {
                log.warn("Invalid version_id format", e);
                return 0;
            }
        });
    }

}
