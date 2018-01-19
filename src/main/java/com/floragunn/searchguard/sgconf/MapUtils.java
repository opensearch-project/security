package com.floragunn.searchguard.sgconf;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class MapUtils {
 /*   
    //Map<String, Object>
    //               Map
    //               Collection
    
    Map<String, Object> map;
    
    String getLeafAsString(String... path) {
        for(String p: path) {
            get(p)
        }
    }
    
    List<String> getLeafAsList(String... path) {
        return null;
    }

    Map<String, Object> getSubMap(String... path) {
        return null;
    }
    
    Val get(String path) {
        
        Object o = map.get(path);
        
        if(o == null) {
            
        } else if(o instanceof Boolean) {
            
            
        } else if(o instanceof Number) {
            
        } else if(o instanceof String) {
            
        } else if(o instanceof Map) {
            
        } else if(o instanceof Collection) {
            
        }
    }
    
    private abstract class Val {
        boolean isLeaf() {
            return getType() != Type.MAP && getType() != Type.COLLECTION;
        }
        boolean isNull(){
            return getType() == Type.NULL;
        }
        
        abstract Type getType();
        
        boolean getValueAsBool() {
            throw new IllegalStateException();
        }
        String getValueAsString(){
            throw new IllegalStateException();
        }
        Number getValueAsNumber(){
            throw new IllegalStateException();
        }
        Map<String, Val> getValueAsMao(){
            throw new IllegalStateException();
        }
        Collection<Val> getValueAsCollection(){
            throw new IllegalStateException();
        }
    }
    
    private enum Type {
        MAP,
        COLLECTION,
        NUMBER,
        STRING,
        BOOL,
        NULL
    }*/
}
