package burp.utilities.helpers;

import java.util.ResourceBundle;

public class Utilities {
    private static final String RESOURCE_BUNDLE = "strings";

    public static String getResourceString(String id) {
        return ResourceBundle.getBundle(RESOURCE_BUNDLE).getString(id);
    }

    public static String replaceWithIncrementingId(String input, String search) {
        if (input == null || search == null || search.isEmpty()) {
            return input;
        }

        StringBuilder result = new StringBuilder();
        int currentIndex = 0;
        int searchIndex;
        int idCounter = 0;

        while ((searchIndex = input.indexOf(search, currentIndex)) != -1) {
            result.append(input, currentIndex, searchIndex);
            result.append(search);
            result.append(idCounter++);
            currentIndex = searchIndex + search.length();
        }

        result.append(input.substring(currentIndex));
        return result.toString();
    }

}
