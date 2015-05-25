package com.floragunn.searchguard;

import io.searchbox.client.JestResult;

import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import com.floragunn.searchguard.util.ConfigConstants;

public class AuditLogTest extends AbstractScenarioTest {

    @Test
    public void testSearchOnlyAllowedAction() throws Exception {

        username = "jacksonm";
        password = "secret";

        final Settings settings = ImmutableSettings.settingsBuilder().putArray("searchguard.actionrequestfilter.names", "readonly")
                .putArray("searchguard.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .put(getAuthSettings(false, "ceo")).build();

        startES(settings);
        setupTestData("ac_rules_execute_all.json");
        executeIndexAsString("{}", "audittest", "audittesttype", "x1", false, false);

        Thread.sleep(3000);

        final JestResult result = executeSearch("ac_query_matchall.json", new String[] { ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX },
                new String[] { "audit" }, true, true).v1();
        log.debug(toPrettyJson(result.getJsonString()));
        assertJestResultCount(result, 1);

    }

}
