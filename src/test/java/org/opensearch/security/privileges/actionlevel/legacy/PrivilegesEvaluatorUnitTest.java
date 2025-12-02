/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges.actionlevel.legacy;

import java.util.List;

import com.google.common.collect.ImmutableList;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.securityconf.impl.v7.ConfigV7;

import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.privileges.actionlevel.legacy.PrivilegesEvaluatorImpl.DNFOF_MATCHER;
import static org.opensearch.security.privileges.actionlevel.legacy.PrivilegesEvaluatorImpl.isClusterPerm;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class PrivilegesEvaluatorUnitTest {

    private static final List<String> allowedDnfof = ImmutableList.of(
        "indices:admin/mappings/fields/get",
        "indices:admin/resolve/index",
        "indices:admin/shards/search_shards",
        "indices:data/read/explain",
        "indices:data/read/field_caps",
        "indices:data/read/get",
        "indices:data/read/mget",
        "indices:data/read/msearch",
        "indices:data/read/msearch/template",
        "indices:data/read/mtv",
        "indices:data/read/plugins/replication/file_chunk",
        "indices:data/read/plugins/replication/changes",
        "indices:data/read/scroll",
        "indices:data/read/scroll/clear",
        "indices:data/read/search",
        "indices:data/read/search/template",
        "indices:data/read/tv",
        "indices:monitor/settings/get",
        "indices:monitor/stats",
        "indices:admin/aliases/get"
    );

    private static final List<String> disallowedDnfof = ImmutableList.of(
        "indices:admin/aliases",
        "indices:admin/aliases/exists",
        "indices:admin/analyze",
        "indices:admin/cache/clear",
        "indices:admin/close",
        "indices:admin/create",
        "indices:admin/data_stream/create",
        "indices:admin/data_stream/delete",
        "indices:admin/data_stream/get",
        "indices:admin/delete",
        "indices:admin/exists",
        "indices:admin/flush",
        "indices:admin/forcemerge",
        "indices:admin/get",
        "indices:admin/mapping/put",
        "indices:admin/mappings/get",
        "indices:admin/open",
        "indices:admin/plugins/replication/index/setup/validate",
        "indices:admin/plugins/replication/index/start",
        "indices:admin/plugins/replication/index/pause",
        "indices:admin/plugins/replication/index/resume",
        "indices:admin/plugins/replication/index/stop",
        "indices:admin/plugins/replication/index/update",
        "indices:admin/plugins/replication/index/status_check",
        "indices:admin/refresh",
        "indices:admin/rollover",
        "indices:admin/seq_no/global_checkpoint_sync",
        "indices:admin/settings/update",
        "indices:admin/shrink",
        "indices:admin/synced_flush",
        "indices:admin/template/delete",
        "indices:admin/template/get",
        "indices:admin/template/put",
        "indices:admin/types/exists",
        "indices:admin/upgrade",
        "indices:admin/validate/query",
        "indices:data/write/bulk",
        "indices:data/write/delete",
        "indices:data/write/delete/byquery",
        "indices:data/write/plugins/replication/changes",
        "indices:data/write/index",
        "indices:data/write/reindex",
        "indices:data/write/update",
        "indices:data/write/update/byquery",
        "indices:monitor/data_stream/stats",
        "indices:monitor/recovery",
        "indices:monitor/segments",
        "indices:monitor/shard_stores",
        "indices:monitor/upgrade"
    );

    @Test
    public void testClusterPerm() {
        String multiSearchTemplate = "indices:data/read/msearch/template";
        String monitorHealth = "cluster:monitor/health";
        String writeIndex = "indices:data/write/reindex";
        String adminClose = "indices:admin/close";
        String monitorUpgrade = "indices:monitor/upgrade";

        // Cluster Permissions
        assertTrue(isClusterPerm(multiSearchTemplate));
        assertTrue(isClusterPerm(writeIndex));
        assertTrue(isClusterPerm(monitorHealth));

        // Index Permissions
        assertFalse(isClusterPerm(adminClose));
        assertFalse(isClusterPerm(monitorUpgrade));
    }

    @Test
    public void testDnfofPermissions_negative() {
        for (final String permission : disallowedDnfof) {
            assertThat(DNFOF_MATCHER.test(permission), equalTo(false));
        }
    }

    @Test
    public void testDnfofPermissions_positive() {
        for (final String permission : allowedDnfof) {
            assertThat(DNFOF_MATCHER.test(permission), equalTo(true));
        }
    }

    @Test
    public void testFromConfigV7_defaultValues() {
        ConfigV7 cfg = new ConfigV7();
        // dynamic defaults are present by the constructor
        PrivilegesEvaluator.GlobalDynamicSettings settings = PrivilegesEvaluator.GlobalDynamicSettings.fromConfigV7(cfg);

        // do_not_fail_on_forbidden default is false
        assertFalse(settings.dnfofEnabled);
        // do_not_fail_on_forbidden_empty default is false
        assertFalse(settings.dnfofForEmptyResultsEnabled);
    }

    @Test
    public void testFromConfigV7_customValues() {
        ConfigV7 cfg = new ConfigV7();
        cfg.dynamic = new ConfigV7.Dynamic();
        cfg.dynamic.do_not_fail_on_forbidden = true;
        cfg.dynamic.do_not_fail_on_forbidden_empty = true;
        cfg.dynamic.filtered_alias_mode = "none";

        PrivilegesEvaluator.GlobalDynamicSettings settings = PrivilegesEvaluator.GlobalDynamicSettings.fromConfigV7(cfg);

        assertTrue(settings.dnfofEnabled);
        assertTrue(settings.dnfofForEmptyResultsEnabled);
        assertEquals("none", settings.filteredAliasMode);
    }

    @Test
    public void testFromConfigV7_nullDynamic() {
        ConfigV7 cfg = new ConfigV7();
        cfg.dynamic = null;

        PrivilegesEvaluator.GlobalDynamicSettings settings = PrivilegesEvaluator.GlobalDynamicSettings.fromConfigV7(cfg);

        // when dynamic is null, defaults: dnfof false, dnfof empty false, filtered_alias_mode -> "none"
        assertFalse(settings.dnfofEnabled);
        assertFalse(settings.dnfofForEmptyResultsEnabled);
        assertEquals("none", settings.filteredAliasMode);
    }

    @Test
    public void testEqualsAndHashCode() {
        ConfigV7 cfg1 = new ConfigV7();
        cfg1.dynamic = new ConfigV7.Dynamic();
        cfg1.dynamic.do_not_fail_on_forbidden = true;
        cfg1.dynamic.do_not_fail_on_forbidden_empty = false;
        cfg1.dynamic.filtered_alias_mode = "warn";

        ConfigV7 cfg2 = new ConfigV7();
        cfg2.dynamic = new ConfigV7.Dynamic();
        cfg2.dynamic.do_not_fail_on_forbidden = true;
        cfg2.dynamic.do_not_fail_on_forbidden_empty = false;
        cfg2.dynamic.filtered_alias_mode = "warn";

        PrivilegesEvaluator.GlobalDynamicSettings s1 = PrivilegesEvaluator.GlobalDynamicSettings.fromConfigV7(cfg1);
        PrivilegesEvaluator.GlobalDynamicSettings s2 = PrivilegesEvaluator.GlobalDynamicSettings.fromConfigV7(cfg2);

        // reflexive
        assertTrue(s1.equals(s1));
        // symmetric and equal
        assertTrue(s1.equals(s2));
        assertTrue(s2.equals(s1));
        // hashCode equal when equals
        assertEquals(s1.hashCode(), s2.hashCode());

        // change one field
        cfg2.dynamic.filtered_alias_mode = "none";
        PrivilegesEvaluator.GlobalDynamicSettings s3 = PrivilegesEvaluator.GlobalDynamicSettings.fromConfigV7(cfg2);

        // now they should not be equal
        assertFalse(s1.equals(s3));

        // null and different type comparisons
        assertFalse(s1.equals(null));
        assertFalse(s1.equals("some string"));
    }
}
