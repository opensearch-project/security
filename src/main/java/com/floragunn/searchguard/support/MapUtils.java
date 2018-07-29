package com.floragunn.searchguard.support;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class MapUtils {
    
    public static void deepTraverseMap(Map<String, Object> map, Callback cb) {
        deepTraverseMap(map, cb, null);
    }
    
    private static void deepTraverseMap(Map<String, Object> map, Callback cb, List<String> stack) {
        if(stack == null) {
            stack = new ArrayList<String>(30);
        }
        for(Map.Entry<String, Object> entry: map.entrySet()) {
            if(entry.getValue() != null && entry.getValue() instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> inner = (Map<String, Object>) entry.getValue();
                stack.add(entry.getKey());
                deepTraverseMap(inner, cb, stack);
            } else {
                cb.call(entry.getKey(), map, Collections.unmodifiableList(stack));
            }
        }
    }
    
    public static interface Callback {
        public void call(String key, Map<String, Object> map, List<String> stack);
    }
}
