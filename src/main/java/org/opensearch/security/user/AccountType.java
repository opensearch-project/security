package org.opensearch.security.user;

public enum AccountType {

    INTERNAL("internal"),
    SERVICE("service");

    private String name;

    AccountType(String name){
        this.name = name;
    }

    public String getName() {
        return this.name;
    }
    public static AccountType fromString(String name) {
        for (AccountType b : AccountType.values()) {
            if (b.name.equalsIgnoreCase(name)) {
                return b;
            }
        }
        return null;
    }

}
