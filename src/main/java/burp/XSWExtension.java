package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import burp.executors.TaskContext;
import burp.executors.TaskExecutor;
import burp.executors.TaskManager;
import burp.utilities.helpers.EphemeralMetadataStore;
import burp.utilities.helpers.MontoyaHelpers;
import burp.utilities.helpers.Utilities;
import burp.utilities.helpers.XMLHelpers;

import java.util.ArrayList;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class XSWExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName(Utilities.getResourceString("tool_name"));
        MontoyaHelpers.initialize(montoyaApi);
        XMLHelpers.initialize();

        try {
            BlockingQueue<Runnable> tasks = new LinkedBlockingQueue<>();
            ThreadFactory threadFactory = new ThreadFactory() {
                private final AtomicInteger threadNumber = new AtomicInteger(1);

                @Override
                public Thread newThread(Runnable r) {
                    Thread thread = new Thread(r);
                    thread.setName(Utilities.getResourceString("worker_name") + threadNumber.getAndIncrement());
                    thread.setDaemon(false);
                    return thread;
                }
            };
            ThreadPoolExecutor taskEngine = new ThreadPoolExecutor(
                    0, 1, 10, TimeUnit.SECONDS, tasks, threadFactory
            );
            taskEngine.allowCoreThreadTimeOut(true);
            EphemeralMetadataStore storage = new EphemeralMetadataStore();

            SettingsPanelWithData settingsPanel = SettingsPanelBuilder.settingsPanel()
                    .withTitle(Utilities.getResourceString("tool_name"))
                    .withDescription("Configure extension settings")
                    .withKeywords("XSW")
                    .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
                    .withSetting(SettingsPanelSetting.integerSetting(Utilities.getResourceString("settings_panel_timeout"), 100))
                    .withSetting(SettingsPanelSetting.booleanSetting(Utilities.getResourceString("settings_panel_sign"), false))
                    .withSetting(SettingsPanelSetting.stringSetting(Utilities.getResourceString("settings_panel_name_id"), "administrator"))
                    .withSetting(SettingsPanelSetting.stringSetting(Utilities.getResourceString("settings_panel_metadata"), "Signed metadata xml"))
                    .build();

            TaskContext context = new TaskContext(settingsPanel);
            TaskManager manager = new TaskManager(montoyaApi, taskEngine, storage, context);

            montoyaApi.userInterface().registerHotKeyHandler(
                    HotKeyContext.HTTP_MESSAGE_EDITOR,
                    "Ctrl+Shift+E",
                    new TaskExecutor(manager, new ArrayList<>())
            );
            montoyaApi.userInterface().registerSettingsPanel(settingsPanel);
            montoyaApi.userInterface().registerContextMenuItemsProvider(new SAMLContextMenuItemsProvider(manager));
            montoyaApi.logging().logToOutput(Utilities.getResourceString("greetings"));
            montoyaApi.extension().registerUnloadingHandler(manager::unload);

        } catch (Exception e) {
            montoyaApi.logging().logToError(e.getLocalizedMessage());
        }
    }
}