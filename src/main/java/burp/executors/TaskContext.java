package burp.executors;

public class TaskContext {
    private boolean sign;
    private boolean refresh;
    private int timeout;
    private String nameId;
    private String assertionConsumerServiceURL;
    private String metadataURL;

    public TaskContext() {
    }

    public String getNameId() {
        return nameId;
    }

    public void setNameId(String nameId) {
        this.nameId = nameId;
    }

    public String getAssertionConsumerServiceURL() {
        return assertionConsumerServiceURL;
    }

    public void setAssertionConsumerServiceURL(String assertionConsumerServiceURL) {
        this.assertionConsumerServiceURL = assertionConsumerServiceURL;
    }

    public String getMetadataURL() {
        return metadataURL;
    }

    public void setMetadataURL(String metadataURL) {
        this.metadataURL = metadataURL;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public boolean isRefresh() {
        return refresh;
    }

    public void setRefresh(boolean refresh) {
        this.refresh = refresh;
    }

    public boolean isSign() {
        return sign;
    }

    public void setSign(boolean sign) {
        this.sign = sign;
    }


    public void defaults() {
        this.refresh = false;
        this.sign = true;
        this.timeout = 100;
        this.nameId = "administrator";
        this.metadataURL = "";
    }
}
