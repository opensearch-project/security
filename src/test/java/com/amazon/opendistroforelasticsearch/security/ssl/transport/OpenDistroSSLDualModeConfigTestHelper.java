package com.amazon.opendistroforelasticsearch.security.ssl.transport;

public class OpenDistroSSLDualModeConfigTestHelper {
    public static void resetDualModeConfig() {
        try {
            OpenDistroSSLDualModeConfig.getInstance().destroy();
        }catch (AssertionError assertionError){
            //do nothing, as the dual mode config is not initialized
        }
    }
}
