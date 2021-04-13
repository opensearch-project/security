package com.amazon.opendistroforelasticsearch.security;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterConfiguration;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.util.Arrays;

public class AdvancedSecurityMigrationTests extends SingleClusterTest {

    @Before
    public void setupBefore() {
        System.setProperty("security.default_init.dir", new File("./src/test/resources/security_passive").getAbsolutePath());
    }

    @After
    public void cleanupAfter() {
        System.setProperty("security.default_init.dir", new File("./securityconfig").getAbsolutePath());
    }

    /**
     * 2 data nodes are adv sec enabled. 1 master node and 1 data node are SSL only.
     * Rest request lands on SSL only data node
     * @throws Exception
     */
    @Test
    public void testPluginEnabledDataNodeWithSSlOnlyMasterNode_ReqOnSSLNode() throws Exception {
        final Settings advSecSettings = getAdvSecSettings().build();
        final Settings sslOnlySettings = getSSLOnlyModeSettings().build();

        setupGenericNodes(Arrays.asList(sslOnlySettings, advSecSettings, advSecSettings, sslOnlySettings),
                Arrays.asList(true, false, false, true), ClusterConfiguration.ONE_MASTER_THREE_DATA);
        Thread.sleep(10000);

        commonTestsForAdvancedSecurityMigration(nonSslRestHelper(), null);
    }

    /**
     * 2 data nodes are adv sec enabled. 1 master node and 1 data node are SSL only.
     * Rest request lands on adv sec data node
     * @throws Exception
     */
    @Test
    public void testPluginEnabledDataNodeWithSSlOnlyMasterNode_ReqOnAdvSecNode() throws Exception {
        final Settings advSecSettings = getAdvSecSettings().build();
        final Settings sslOnlySettings = getSSLOnlyModeSettings().build();

        setupGenericNodes(Arrays.asList(advSecSettings, sslOnlySettings, advSecSettings, sslOnlySettings),
                Arrays.asList(false, true, false, true), ClusterConfiguration.ONE_MASTER_THREE_DATA);
        Thread.sleep(10000);

        commonTestsForAdvancedSecurityMigration(nonSslRestHelper(), encodeBasicHeader("admin", "admin"));
    }

    /**
     * 1 Master node and 1 Data node is adv sec enabled. 2 Data nodes are SSL only.
     * Rest request lands on ssl only data node
     * @throws Exception
     */
    @Test
    public void testPluginEnabledMasterNodeWithSSlOnlyDataNode_ReqOnSSLNode() throws Exception {
        final Settings advSecSettings = getAdvSecSettings().build();
        final Settings sslOnlySettings = getSSLOnlyModeSettings().build();

        setupGenericNodes(Arrays.asList(sslOnlySettings, sslOnlySettings, advSecSettings, advSecSettings),
                Arrays.asList(true, true, false, false), ClusterConfiguration.ONE_MASTER_THREE_DATA);
        Thread.sleep(10000);

        commonTestsForAdvancedSecurityMigration(nonSslRestHelper(),null);
    }

    /**
     * 1 Master node and 1 Data node is adv sec enabled. 2 Data nodes are SSL only.
     * Rest request lands on adv sec data node
     * @throws Exception
     */
    @Test
    public void testPluginEnabledMasterNodeWithSSlOnlyDataNode_ReqOnAdvSecNode() throws Exception {
        final Settings advSecSettings = getAdvSecSettings().build();
        final Settings sslOnlySettings = getSSLOnlyModeSettings().build();

        setupGenericNodes(Arrays.asList(advSecSettings, sslOnlySettings, sslOnlySettings, advSecSettings),
                Arrays.asList(false, true, true, false), ClusterConfiguration.ONE_MASTER_THREE_DATA);
        Thread.sleep(10000);

        commonTestsForAdvancedSecurityMigration(nonSslRestHelper(), encodeBasicHeader("admin", "admin"));
    }

    /**
     * 2 Data nodes are adv sec enabled. 1 Master node and 1 Data node are plugin disabled.
     * Rest request lands on plugin disabled node
     * @throws Exception
     */
    @Test
    public void testPluginEnabledDataNodeWithDisabledMasterNode_ReqOnDisabledNode() throws Exception {
        final Settings advSecSettings = getAdvSecSettingsDualMode().build();
        final Settings disabledSettings = getDisabledSettings().build();

        setupGenericNodes(Arrays.asList(disabledSettings, advSecSettings, advSecSettings, disabledSettings),
                Arrays.asList(false, false, false, false), ClusterConfiguration.ONE_MASTER_THREE_DATA);
        Thread.sleep(10000);

        commonTestsForAdvancedSecurityMigration(nonSslRestHelper(),null);
    }

    /**
     * 2 Data nodes are adv sec enabled. 1 Master node and 1 Data node are plugin disabled.
     * Rest request lands on adv sec data node
     * @throws Exception
     */
    @Test
    public void testPluginEnabledDataNodeWithDisabledMasterNode_ReqOnAdvSecNode() throws Exception {
        final Settings advSecSettings = getAdvSecSettingsDualMode().build();
        final Settings disabledSettings = getDisabledSettings().build();

        setupGenericNodes(Arrays.asList(advSecSettings, disabledSettings, advSecSettings, disabledSettings),
                Arrays.asList(false, false, false, false), ClusterConfiguration.ONE_MASTER_THREE_DATA);
        Thread.sleep(10000);

        commonTestsForAdvancedSecurityMigration(nonSslRestHelper(), encodeBasicHeader("admin", "admin"));
    }

    /**
     * 1 Master node and 1 Data node are adv sec enabled. 2 Data nodes are plugin disabled.
     * Rest request lands on plugin disabled node
     * @throws Exception
     */
    @Test
    public void testPluginEnabledMasterNodeWithDisabledDataNode_ReqOnDisabledNode() throws Exception {
        final Settings advSecSettings = getAdvSecSettingsDualMode().build();
        final Settings disabledSettings = getDisabledSettings().build();

        setupGenericNodes(Arrays.asList(disabledSettings, disabledSettings, advSecSettings, advSecSettings),
                Arrays.asList(false, false, false, false), ClusterConfiguration.ONE_MASTER_THREE_DATA);
        Thread.sleep(10000);

        commonTestsForAdvancedSecurityMigration(nonSslRestHelper(), null);
    }

    /**
     * 1 Master node and 2 Data nodes are adv sec enabled. 1 Data node is plugin disabled.
     * Rest request lands on plugin adv sec node
     * @throws Exception
     */
    @Test
    public void testPluginEnabledMasterNodeWithDisabledDataNode_ReqOnAdvSecNode() throws Exception {
        final Settings advSecSettings = getAdvSecSettingsDualMode().build();
        final Settings disabledSettings = getDisabledSettings().build();

        setupGenericNodes(Arrays.asList(advSecSettings, disabledSettings, advSecSettings, advSecSettings),
                Arrays.asList(false, false, false, false), ClusterConfiguration.ONE_MASTER_THREE_DATA);
        Thread.sleep(10000);

        commonTestsForAdvancedSecurityMigration(nonSslRestHelper(), encodeBasicHeader("admin", "admin"));
    }

    private void commonTestsForAdvancedSecurityMigration(final RestHelper rh, final Header basicHeaders) throws Exception {
        //Thread.sleep(5*1000);

        RestHelper.HttpResponse res;
        res = rh.executePutRequest("testindex", getIndexSettingsForAdvSec(), basicHeaders);
        Assert.assertEquals(res.getBody(), HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executePutRequest("testindex2", getIndexSettingForSSLOnlyNode(), basicHeaders);
        Assert.assertEquals(res.getBody(), HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executeGetRequest("/_cluster/health", basicHeaders);
        Assert.assertEquals(res.getBody(), HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("/_cat/shards", basicHeaders);
        Assert.assertEquals(res.getBody(), HttpStatus.SC_OK, res.getStatusCode());

        commonTestsForAnIndex(rh, "testindex", basicHeaders);
        commonTestsForAnIndex(rh, "testindex2", basicHeaders);
    }

    private void commonTestsForAnIndex(final RestHelper rh, final String index, final Header basicHeaders) throws Exception {
        RestHelper.HttpResponse res;
        String slashIndex = "/" + index;

        res = rh.executeGetRequest(slashIndex, basicHeaders);
        Assert.assertEquals(res.getBody(), HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executePutRequest(slashIndex + "/_doc/1", "{}", basicHeaders);
        Assert.assertEquals(res.getBody(), HttpStatus.SC_CREATED, res.getStatusCode());
        res = rh.executePutRequest(slashIndex + "/_doc/1", "{}", basicHeaders);
        Assert.assertEquals(res.getBody(), HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeDeleteRequest(slashIndex + "/_doc/1", basicHeaders);
        Assert.assertEquals(res.getBody(), HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeDeleteRequest(slashIndex, basicHeaders);
        Assert.assertEquals(res.getBody(), HttpStatus.SC_OK, res.getStatusCode());
    }

    private Settings.Builder getAdvSecSettings() {
        return Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_PASSIVE_INTERTRANSPORT_AUTH_INITIALLY, true)
                .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, true)
                .put("node.attr.custom_node", true);
    }

    private Settings.Builder getAdvSecSettingsDualMode() {
        return getAdvSecSettings()
                .put(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED, true);
    }

    private Settings.Builder getSSLOnlyModeSettings() {
        return Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_SSL_ONLY, true);
    }

    private Settings.Builder getDisabledSettings() {
        return Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_DISABLED, true);
    }

    // Create index with shards only in adv sec nodes
    private String getIndexSettingsForAdvSec() {
        return "{\n" +
                "    \"settings\" : {\n" +
                "        \"index\" : {\n" +
                "            \"number_of_shards\" : 2, \n" +
                "            \"number_of_replicas\" : 1, \n" +
                "            \"routing.allocation.include.custom_node\" : true \n" +
                "        }\n" +
                "    }\n" +
                "}";
    }

    // Create index with shards only in non adv sec nodes
    private String getIndexSettingForSSLOnlyNode() {
        return "{\n" +
                "    \"settings\" : {\n" +
                "        \"index\" : {\n" +
                "            \"number_of_shards\" : 2, \n" +
                "            \"number_of_replicas\" : 1, \n" +
                "            \"routing.allocation.exclude.custom_node\" : true \n" +
                "        }\n" +
                "    }\n" +
                "}";
    }
}
