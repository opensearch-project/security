package org.opensearch.security;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.opensearch.security.tools.PasswordSetup;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

public class PasswordSetupTests extends SingleClusterTest {
    @Test
    public void testPasswordSetup() throws Exception {
        final Settings settings = Settings.builder()
                .put("plugins.security.ssl.http.enabled",true)
                .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        DynamicSecurityConfig config = new DynamicSecurityConfig().setSecurityInternalUsers("internal_users_password_setup.yml");
        setup(Settings.EMPTY, config, settings, true);
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-nhnv");

        String userInput = "Admins#1\nKibanaServer@2\nKibanaro*3\nLogstash&4\nReadall%5\nSnapshotrestore$6";
        ByteArrayInputStream input = new ByteArrayInputStream(userInput.getBytes());
        System.setIn(input);
        
        int returnCode  = (new PasswordSetup()).execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        System.setIn(System.in);
        
        RestHelper rh = restHelper();

        Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("admin", "Admins#1")).getStatusCode());
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("kibanaserver", "KibanaServer@2")).getStatusCode());
    }

    @Test
    public void testInvalidInput() throws Exception {
        final Settings settings = Settings.builder()
                .put("plugins.security.ssl.http.enabled",true)
                .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        
        DynamicSecurityConfig config = new DynamicSecurityConfig().setSecurityInternalUsers("internal_users_password_setup.yml");
        setup(Settings.EMPTY, config, settings, true);
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-nhnv");

        String userInput = "Admins#1";
        ByteArrayInputStream input = new ByteArrayInputStream(userInput.getBytes());
        System.setIn(input);
        
        int returnCode  = (new PasswordSetup()).execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(-1, returnCode);
    }

    @Test
    public void testAutoGenerate() throws Exception {
        final Settings settings = Settings.builder()
                .put("plugins.security.ssl.http.enabled",true)
                .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        
        DynamicSecurityConfig config = new DynamicSecurityConfig().setSecurityInternalUsers("internal_users_password_setup.yml");
        setup(Settings.EMPTY, config, settings, true);
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-nhnv");
        argsAsList.add("-a");

        int returnCode  = (new PasswordSetup()).execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        RestHelper rh = restHelper();
        Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
    }
}
