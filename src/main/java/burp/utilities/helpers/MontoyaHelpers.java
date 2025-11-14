package burp.utilities.helpers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;

import java.util.HashMap;
import java.util.List;

/**
 * Singleton helper class to provide access to Montoya API instance for live tests.
 * This allows live tests to access HTTP functionality and other Burp Suite features.
 */
public class MontoyaHelpers {
    private static MontoyaHelpers instance;
    private static MontoyaApi montoyaApi;

    private MontoyaHelpers() {
        // Private constructor to enforce singleton pattern
    }

    /**
     * Initializes the LiveHelpers with a MontoyaApi instance.
     * Should be called once during extension initialization.
     *
     * @param api The MontoyaApi instance to use
     */
    public static void initialize(MontoyaApi api) {
        if (instance == null) {
            instance = new MontoyaHelpers();
            montoyaApi = api;
        }
    }

    /**
     * Gets the singleton instance of LiveHelpers.
     * Must be called after initialize().
     *
     * @return The LiveHelpers instance
     * @throws IllegalStateException if initialize() hasn't been called yet
     */
    public static MontoyaHelpers getInstance() {
        if (instance == null) {
            throw new IllegalStateException("LiveHelpers not initialized. Call initialize() first.");
        }
        return instance;
    }

    public static HashMap<String, Object> calculateFingerprint(HttpResponse response) {
        HashMap<String, Object> fingerprint = new HashMap<>();
        List<Attribute> attributes = response.attributes(
                AttributeType.CONTENT_LENGTH,
                AttributeType.PAGE_TITLE,
                AttributeType.WORD_COUNT,
                AttributeType.STATUS_CODE,
                AttributeType.LOCATION
        );
        for (Attribute attribute : attributes) {
            fingerprint.put(attribute.type().name(), attribute.value());
        }
        return fingerprint;
    }

    /**
     * Gets the MontoyaApi instance for making HTTP requests and accessing other Burp features.
     *
     * @return The MontoyaApi instance
     * @throws IllegalStateException if not initialized
     */
    public MontoyaApi getMontoyaApi() {
        if (montoyaApi == null) {
            throw new IllegalStateException("MontoyaApi not available. Ensure LiveHelpers is properly initialized.");
        }
        return montoyaApi;
    }

    /**
     * Convenience method to get HTTP functionality directly.
     *
     * @return The HTTP interface from MontoyaApi
     */
    public burp.api.montoya.http.Http getHttp() {
        return getMontoyaApi().http();
    }

    /**
     * Convenience method to get logging functionality directly.
     *
     * @return The Logging interface from MontoyaApi
     */
    public burp.api.montoya.logging.Logging getLogging() {
        return getMontoyaApi().logging();
    }
}