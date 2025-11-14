package burp.executors;

import burp.api.montoya.ui.settings.SettingsPanelWithData;
import burp.utilities.helpers.Utilities;

public class TaskContext {
    private final SettingsPanelWithData settings;
    private boolean sign;
    private int timeout;
    private String nameId;
    private String destination;
    private String metadata;

    public TaskContext(SettingsPanelWithData settings) {
        this.settings = settings;
    }

    public String getNameId() {
        return nameId;
    }

    public void setNameId(String nameId) {
        this.nameId = nameId;
    }

    public String getSettingsNameID() {
        if (settings != null)
            return this.settings.getString(Utilities.getResourceString("settings_panel_name_id"));
        else
            return nameId;
    }

    public String getDestination() {
        return destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public String getMetadata() {
        return metadata;
    }

    public void setMetadata(String metadata) {
        this.metadata = metadata;
    }

    public String getSettingsMetadata() {
        if (settings != null)
            return this.settings.getString(Utilities.getResourceString("settings_panel_metadata"));
        else
            return metadata;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public int getSettingsTimeout() {
        if (settings != null)
            return this.settings.getInteger(Utilities.getResourceString("settings_panel_timeout"));
        else
            return timeout;
    }

    public boolean isSign() {
        return sign;
    }

    public void setSign(boolean sign) {
        this.sign = sign;
    }

    public boolean getSettingsSign() {
        if (settings != null)
            return this.settings.getBoolean(Utilities.getResourceString("settings_panel_sign"));
        else
            return sign;
    }

    public void defaults() {
        this.sign = getSettingsSign();
        this.timeout = getSettingsTimeout();
        this.nameId = getSettingsNameID();
        this.metadata = getSettingsMetadata();
    }
}
