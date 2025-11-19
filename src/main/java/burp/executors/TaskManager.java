package burp.executors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.utilities.exceptions.SAMLException;
import burp.utilities.helpers.Utilities;
import burp.utilities.helpers.WrapHelpers;
import burp.utilities.helpers.XMLHelpers;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class TaskManager {
    private static final long SHUTDOWN_TIMEOUT_MILLISECONDS = 100;
    private final ConcurrentHashMap<Long, Runnable> activeTaskRegistry;
    private final AtomicLong taskIdGenerator;
    private final ConcurrentHashMap<String, String> metadatas;
    private final TaskContext context;
    private final MontoyaApi montoyaApi;
    private final ThreadPoolExecutor taskEngine;

    public TaskManager(MontoyaApi montoyaApi, ThreadPoolExecutor taskEngine, TaskContext context) {
        this.montoyaApi = montoyaApi;
        this.taskEngine = taskEngine;
        this.context = context;
        this.activeTaskRegistry = new ConcurrentHashMap<>();
        this.taskIdGenerator = new AtomicLong(0);
        this.metadatas = new ConcurrentHashMap<>();
    }

    public void execute(Runnable command) {
        long taskId = taskIdGenerator.incrementAndGet();
        Runnable wrappedTask = () -> {
            activeTaskRegistry.put(taskId, command);
            try {
                command.run();
            } finally {
                activeTaskRegistry.remove(taskId);
            }
        };
        taskEngine.execute(wrappedTask);
    }

    public void unload() {
        try {
            montoyaApi.logging().logToOutput("Initiating graceful shutdown...");

            // Stop accepting new tasks
            taskEngine.shutdown();

            // Wait for running tasks to complete
            boolean terminated = taskEngine.awaitTermination(SHUTDOWN_TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);

            if (!terminated) {
                montoyaApi.logging().logToError("Tasks did not complete within timeout, forcing shutdown");
                montoyaApi.logging().logToOutput("Active tasks remaining: " + activeTaskRegistry.size());

                // Force shutdown
                taskEngine.shutdownNow();

                // Wait again briefly
                taskEngine.awaitTermination(SHUTDOWN_TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
            }

            montoyaApi.logging().logToOutput("Shutdown complete. Final active tasks: " + activeTaskRegistry.size());
        } catch (InterruptedException e) {
            montoyaApi.logging().logToError("Shutdown interrupted: " + e.getMessage());
            taskEngine.shutdownNow();
            Thread.currentThread().interrupt();
        } finally {
            activeTaskRegistry.clear();
            montoyaApi.logging().logToOutput(Utilities.getResourceString("unloaded"));
        }
    }

    public MontoyaApi getMontoyaApi() {
        return montoyaApi;
    }

    public boolean hasActiveTasks() {
        return !activeTaskRegistry.isEmpty();
    }

    public int getActiveTaskCount() {
        return activeTaskRegistry.size();
    }

    public TaskContext getContext() {
        return context;
    }

    public String extractSAMLMetadata(String destination) {
        if (metadatas.contains(destination))
            return metadatas.get(destination);

        XMLHelpers xmlHelpers = XMLHelpers.getInstance();
        String metadataURI = null;
        String url = WrapHelpers.getMetadataURL(destination);
        if (url != null && !url.isEmpty()) {
            HttpRequestResponse metadataRequest = montoyaApi
                    .http()
                    .sendRequest(HttpRequest.httpRequestFromUrl(url));
            if (metadataRequest.hasResponse()) {
                String body = metadataRequest.response().bodyToString();
                try {
                    xmlHelpers.getXMLDocumentOfSAMLMessage(body);
                    metadataURI = url;
                } catch (SAMLException ignored) {
                }
            }
        }
        if (metadataURI == null) {
            try {
                URI destUri = new URI(destination);
                for (String location : WrapHelpers.DEFAULT_METADATA) {
                    HttpRequestResponse metadataRequest = montoyaApi
                            .http()
                            .sendRequest(HttpRequest.httpRequestFromUrl(destination).withPath(location));
                    if (metadataRequest.hasResponse()) {
                        String body = metadataRequest.response().bodyToString();
                        try {
                            xmlHelpers.getXMLDocumentOfSAMLMessage(body);
                            metadataURI = destUri.resolve(location).toString();
                            break;
                        } catch (SAMLException ignored) {
                        }
                    }
                }
            } catch (URISyntaxException ignored) {
            }
        }
        if (metadataURI == null || metadataURI.isEmpty()) return null;
        metadatas.put(destination, metadataURI);
        return metadataURI;
    }
}
