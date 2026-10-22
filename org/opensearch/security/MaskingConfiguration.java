import java.util.Set;

public class MaskingConfiguration {

    private boolean enabled;
    private Set<String> maskedFields;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Set<String> getMaskedFields() {
        return maskedFields;
    }

    public void setMaskedFields(Set<String> maskedFields) {
        this.maskedFields = maskedFields;
    }

    public boolean isFieldMasked(String field) {
        return maskedFields.contains(field);
    }
}