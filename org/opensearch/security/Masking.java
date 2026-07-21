import java.util.Set;

public class Masking {

    public static boolean isEnabled() {
        // Check if field masking is enabled in the configuration
        return getConfiguration().isEnabled();
    }

    public static boolean isFieldMasked(String field) {
        // Check if the field is masked in the configuration
        return getConfiguration().isFieldMasked(field);
    }

    private static MaskingConfiguration getConfiguration() {
        // Return the masking configuration
        return new MaskingConfiguration();
    }
}