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
package org.opensearch.security.privileges.dlsfls;

import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.privileges.ClusterStateMetadataDependentPrivileges;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

/**
 * Encapsulates the processed DLS/FLS configuration from roles.yml.
 * The current instance is held and managed by DlsFlsValveImpl.
 */
public class DlsFlsProcessedConfig extends ClusterStateMetadataDependentPrivileges {
    private static final Logger log = LogManager.getLogger(DlsFlsProcessedConfig.class);

    private final DocumentPrivileges documentPrivileges;
    private final FieldPrivileges fieldPrivileges;
    private final FieldMasking fieldMasking;
    private long metadataVersionEffective = -1;

    public DlsFlsProcessedConfig(
        SecurityDynamicConfiguration<RoleV7> rolesConfiguration,
        Map<String, IndexAbstraction> indexMetadata,
        NamedXContentRegistry xContentRegistry,
        Settings settings,
        FieldMasking.Config fieldMaskingConfig
    ) {
        this.documentPrivileges = new DocumentPrivileges(rolesConfiguration, indexMetadata, xContentRegistry, settings);
        this.fieldPrivileges = new FieldPrivileges(rolesConfiguration, indexMetadata, settings);
        this.fieldMasking = new FieldMasking(rolesConfiguration, indexMetadata, fieldMaskingConfig, settings);
    }

    public DocumentPrivileges getDocumentPrivileges() {
        return this.documentPrivileges;
    }

    public FieldPrivileges getFieldPrivileges() {
        return this.fieldPrivileges;
    }

    public FieldMasking getFieldMasking() {
        return this.fieldMasking;
    }

    @Override
    protected void updateClusterStateMetadata(Metadata metadata) {
        long start = System.currentTimeMillis();
        Map<String, IndexAbstraction> indexLookup = metadata.getIndicesLookup();

        this.documentPrivileges.updateIndices(indexLookup);
        this.fieldPrivileges.updateIndices(indexLookup);
        this.fieldMasking.updateIndices(indexLookup);

        long duration = System.currentTimeMillis() - start;

        log.debug("Updating DlsFlsProcessedConfig took {} ms", duration);
    }

    @Override
    protected long getCurrentlyUsedMetadataVersion() {
        return this.metadataVersionEffective;
    }
}
