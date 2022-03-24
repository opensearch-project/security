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

import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

public class PasswordSetupTests extends SingleClusterTest {
    @Test
    public void testSecurityAdmin() throws Exception {
        final Settings settings = Settings.builder()
                .put("plugins.security.ssl.http.enabled",true)
                .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        setup(Settings.EMPTY, null, settings, false);
        
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
        argsAsList.add("-cd");
        argsAsList.add(new File("src/test/resources/").getAbsolutePath());
        argsAsList.add("-nhnv");

        String userInput = "Admins#1";
        //\nKibanaServer@2\nKibanaro!3\nLogstash&4\nReadall%5\nSnapshotrestore$6";
        ByteArrayInputStream input = new ByteArrayInputStream(userInput.getBytes());
        System.setIn(input);
        int returnCode  = PasswordSetup.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        System.setIn(System.in);
        
        RestHelper rh = restHelper();

        Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
    }
}
