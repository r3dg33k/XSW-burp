package burp.utilities.helpers;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;

import java.util.Map;
import java.util.Optional;

public class EphemeralMetadataStore {

    private final DB db;
    private final Map<String, String> store;

    public EphemeralMetadataStore() {
        this.db = DBMaker.tempFileDB()
                .fileMmapEnableIfSupported()
                .transactionEnable()
                .fileDeleteAfterClose()
                .make();

        this.store = db.hashMap("metadata")
                .keySerializer(Serializer.STRING)
                .valueSerializer(Serializer.STRING)
                .createOrOpen();
    }

    public Optional<String> get(String key) {
        return Optional.ofNullable(store.get(key));
    }

    public void put(String key, String value) {
        store.put(key, value);
        db.commit();
    }

    public void close() {
        db.close();
    }
}