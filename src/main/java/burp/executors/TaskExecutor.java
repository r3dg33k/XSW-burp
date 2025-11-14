package burp.executors;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKeyEvent;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
import burp.utilities.helpers.TaskType;
import burp.views.TaskInputDialog;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.Optional;

public class TaskExecutor implements ActionListener, HotKeyHandler {
    private final TaskManager manager;
    private final List<HttpRequestResponse> requestResponses;

    public TaskExecutor(TaskManager manager, List<HttpRequestResponse> requestResponses) {
        this.manager = manager;
        this.requestResponses = requestResponses;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (requestResponses.isEmpty()) return;

        TaskContext context = manager.getContext();
        Frame parentFrame = getParentFrame(e);
        TaskInputDialog dialog = new TaskInputDialog(
                parentFrame,
                context.isSign(),
                context.getTimeout()
        );
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            String nameId = dialog.getNameId();
            String destination = dialog.getDestination();

            if (!nameId.isEmpty()) {
                context.setNameId(nameId);
            }
            if (!destination.isEmpty()) {
                context.setDestination(destination);
            }
            context.setTimeout(dialog.getTimeout());
            context.setSign(dialog.isSign());

            TaskType actionCommand = TaskType.fromString(e.getActionCommand());
            switch (actionCommand) {
                case Wrap -> manager.execute(new WrapTask(manager, requestResponses));
                case null -> {
                }
            }
        }
    }

    private Frame getParentFrame(ActionEvent e) {
        if (e.getSource() instanceof Component component) {
            Window window = SwingUtilities.getWindowAncestor(component);
            if (window instanceof Frame) {
                return (Frame) window;
            }
        }
        return null;
    }

    @Override
    public void handle(HotKeyEvent event) {
        manager.getMontoyaApi().logging().logToOutput("Clicked!");
        Optional<MessageEditorHttpRequestResponse> requestResponse = event.messageEditorRequestResponse();
        if (requestResponse.isPresent()) {
            requestResponses.add(requestResponse.get().requestResponse());
            TaskContext context = manager.getContext();
            context.defaults();
            WrapTask task = new WrapTask(manager, requestResponses);
            manager.execute(task);
        }
    }
}
