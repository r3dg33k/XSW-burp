package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.executors.TaskExecutor;
import burp.executors.TaskManager;
import burp.utilities.helpers.TaskType;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class SAMLContextMenuItemsProvider implements ContextMenuItemsProvider {

    private final TaskManager manager;

    public SAMLContextMenuItemsProvider(TaskManager manager) {
        this.manager = manager;
    }

    @Override
    public java.util.List<Component> provideMenuItems(ContextMenuEvent contextMenuEvent) {
        java.util.List<Component> menuItemList = new ArrayList<>();
        List<HttpRequestResponse> requestResponses = new ArrayList<>();

        if (contextMenuEvent.messageEditorRequestResponse().isPresent()) {
            MessageEditorHttpRequestResponse message = contextMenuEvent.messageEditorRequestResponse().get();
            requestResponses.add(message.requestResponse());
        } else {
            requestResponses = contextMenuEvent.selectedRequestResponses();
        }

        if (requestResponses.isEmpty()) return null;

        for (TaskType taskType : TaskType.values()) {
            JMenuItem item = new JMenuItem(taskType.getType());
            item.setActionCommand(taskType.getType());
            item.addActionListener(new TaskExecutor(manager, requestResponses));
            menuItemList.add(item);
        }
        return menuItemList;
    }
}
