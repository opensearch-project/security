package com.floragunn.searchguard.support;

import org.elasticsearch.common.xcontent.DeprecationHandler;

public class SearchGuardDeprecationHandler {
    
    public final static DeprecationHandler INSTANCE = new DeprecationHandler() {
        @Override
        public void usedDeprecatedField(String usedName, String replacedWith) {
            throw new UnsupportedOperationException("deprecated fields not supported here but got ["
                + usedName + "] which is a deprecated name for [" + replacedWith + "]");
        }
        @Override
        public void usedDeprecatedName(String usedName, String modernName) {
            throw new UnsupportedOperationException("deprecated fields not supported here but got ["
                + usedName + "] which has been replaced with [" + modernName + "]");
        }
    };

}
