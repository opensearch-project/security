package com.floragunn.searchguard.configuration;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.common.util.concurrent.ThreadContext;

public interface DlsFlsRequestValve {
    
    /**
     * 
     * @param request
     * @param listener
     * @return false to stop
     */
    boolean invoke(final ActionRequest request, final ActionListener listener, ThreadContext threadContext);

    public static class NoopDlsFlsRequestValve implements DlsFlsRequestValve {

        @Override
        public boolean invoke(ActionRequest request, ActionListener listener, ThreadContext threadContext) {
            return true;
        }
        
    }
    
}
