package burp.models;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Thread-safe grouping of Response by a calculated fingerprint,
 * allowing efficient matching and diffing of attributes across messages.
 */
public final class ResponseGroup {

    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final Function<HttpResponse, Map<String, Object>> fingerprintCalculator;

    // guarded by lock
    private Map<String, Object> fingerprint = Collections.emptyMap();
    private HttpResponse firstMessage;

    /**
     * Constructs an empty group with the given fingerprint calculator.
     */
    public ResponseGroup(Function<HttpResponse, Map<String, Object>> fingerprintCalculator) {
        this.fingerprintCalculator =
                Objects.requireNonNull(fingerprintCalculator, "fingerprintCalculator cannot be null");
    }

    /**
     * Constructs a group and seeds it with an initial message.
     */
    public ResponseGroup(
            Function<HttpResponse, Map<String, Object>> fingerprintCalculator,
            HttpResponse initialMessage
    ) {
        this(fingerprintCalculator);
        add(initialMessage);
    }

    /**
     * Clears all accumulated state, so this group is as-if newly constructed.
     * Thread-safe.
     */
    public void reset() {
        lock.writeLock().lock();
        try {
            firstMessage = null;
            fingerprint = Collections.emptyMap();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * @return the first message added to this group, or null if none.
     */
    public HttpResponse getFirstMessage() {
        lock.readLock().lock();
        try {
            return firstMessage;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Adds a message to this group, updating the group fingerprint to the
     * intersection of existing and new fingerprint entries.
     */
    public ResponseGroup add(HttpResponse message) {
        Objects.requireNonNull(message, "message cannot be null");
        Map<String, Object> newPrint = fingerprintCalculator.apply(message);

        lock.writeLock().lock();
        try {
            if (firstMessage == null) {
                firstMessage = message;
            }

            if (fingerprint.isEmpty()) {
                // initialize fingerprint
                fingerprint = Collections.unmodifiableMap(newPrint);
            } else {
                // intersect keys with matching values
                fingerprint = Collections.unmodifiableMap(
                        fingerprint.entrySet().stream()
                                .filter(e -> e.getValue().equals(newPrint.get(e.getKey())))
                                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue))
                );
            }
            return this;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Tests whether a message matches the group's fingerprint.
     */
    public boolean matches(HttpResponse message) {
        Objects.requireNonNull(message, "message cannot be null");
        Map<String, Object> newPrint = fingerprintCalculator.apply(message);

        lock.readLock().lock();
        try {
            return fingerprint.entrySet().stream()
                    .allMatch(e -> Objects.equals(e.getValue(), newPrint.get(e.getKey())));
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * @return true if no fingerprint entries remain (i.e., completely diverged).
     */
    public boolean isFingerprintEmpty() {
        lock.readLock().lock();
        try {
            return fingerprint.isEmpty();
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Returns keys whose fingerprint value differs from the given message.
     */
    public List<String> diffKeys(HttpResponse message) {
        Objects.requireNonNull(message, "message cannot be null");
        Map<String, Object> newPrint = fingerprintCalculator.apply(message);

        lock.readLock().lock();
        try {
            return fingerprint.keySet().stream()
                    .filter(key -> !Objects.equals(fingerprint.get(key), newPrint.get(key)))
                    .collect(Collectors.toList());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Describes differences between the group's fingerprint and a message.
     * Output lines are in format "key expected -> actual".
     */
    public String describeDiff(HttpResponse message) {
        Objects.requireNonNull(message, "message cannot be null");
        Map<String, Object> newPrint = fingerprintCalculator.apply(message);

        lock.readLock().lock();
        try {
            return fingerprint.entrySet().stream()
                    .filter(e -> !Objects.equals(e.getValue(), newPrint.get(e.getKey())))
                    .map(e -> String.format("%s %s->%s", e.getKey(), e.getValue(), newPrint.get(e.getKey())))
                    .collect(Collectors.joining(", "));
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public String toString() {
        lock.readLock().lock();
        try {
            return fingerprint.entrySet().stream()
                    .map(e -> e.getKey() + ":" + e.getValue())
                    .collect(Collectors.joining(", "));
        } finally {
            lock.readLock().unlock();
        }
    }
}