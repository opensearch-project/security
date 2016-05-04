package com.floragunn.searchguard.configuration;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;

public interface DlsFlsRequestValve {
    
    /**
     * 
     * @param request
     * @param listener
     * @return false to stop
     */
    boolean invoke(final ActionRequest<?> request, final ActionListener listener);

    public static class NoopDlsFlsRequestValve implements DlsFlsRequestValve {

        @Override
        public boolean invoke(ActionRequest<?> request, ActionListener listener) {
            return true;
        }
        
    }
    
}
