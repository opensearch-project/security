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
package org.opensearch.security.privileges.actionlevel.nextgen;

import com.google.common.collect.ImmutableMap;

import org.opensearch.action.admin.indices.create.AutoCreateAction;
import org.opensearch.action.admin.indices.create.CreateIndexAction;
import org.opensearch.action.admin.indices.mapping.put.AutoPutMappingAction;
import org.opensearch.action.admin.indices.mapping.put.PutMappingAction;
import org.opensearch.action.admin.indices.upgrade.post.UpgradeAction;
import org.opensearch.action.admin.indices.upgrade.post.UpgradeSettingsAction;
import org.opensearch.common.settings.Settings;

class ActionNameMapping {
    private final ImmutableMap<String, String> actionToActionMap;

    ActionNameMapping(Settings settings) {
        ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();
        builder.put(UpgradeSettingsAction.NAME, UpgradeAction.NAME);
        builder.put(AutoCreateAction.NAME, CreateIndexAction.NAME);
        builder.put(AutoPutMappingAction.NAME, PutMappingAction.NAME);

        this.actionToActionMap = builder.build();
    }

    String normalize(String action) {
        String mapped = this.actionToActionMap.get(action);
        if (mapped != null) {
            return mapped;
        } else {
            return action;
        }
    }
}
