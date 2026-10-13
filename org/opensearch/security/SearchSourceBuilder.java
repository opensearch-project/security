import java.util.Set;

public class SearchSourceBuilder {

    private Set<String> fields;

    public SearchSourceBuilder() {
        fields = new HashSet<>();
    }

    public void addField(String field) {
        fields.add(field);
    }

    public Set<String> getFields() {
        return fields;
    }

    public boolean containsMaskedFields() {
        // Check if any of the fields are masked
        for (String field : fields) {
            if (Masking.isFieldMasked(field)) {
                return true;
            }
        }
        return false;
    }
}