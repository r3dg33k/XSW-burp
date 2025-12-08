package burp.views;

import burp.utilities.helpers.Utilities;

import javax.swing.*;
import java.awt.*;

public class TaskInputDialog extends JDialog {
    private final JTextField nameIdField = new JTextField(20);
    private final JTextField assertionURLField = new JTextField(20);
    private final JTextField metadataURLField = new JTextField(20);
    private final JTextField timeoutField = new JTextField(20);
    private final JCheckBox refreshCheckBox = new JCheckBox();
    private boolean confirmed = false;

    public TaskInputDialog(Frame parent, String nameId, boolean defaultRefresh, int defaultTimeout) {
        super(parent, Utilities.getResourceString("dialog_menu_title"), true);
        nameIdField.setText(nameId);
        refreshCheckBox.setSelected(defaultRefresh);
        timeoutField.setText(String.valueOf(defaultTimeout));
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout(10, 10));

        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        gbc.gridx = 0;
        gbc.gridy = row;
        inputPanel.add(new JLabel(Utilities.getResourceString("dialog_menu_name_id")), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        inputPanel.add(nameIdField, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        inputPanel.add(new JLabel(Utilities.getResourceString("dialog_menu_acs_url")), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        inputPanel.add(assertionURLField, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        inputPanel.add(new JLabel(Utilities.getResourceString("dialog_menu_metadata_url")), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        inputPanel.add(metadataURLField, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        inputPanel.add(new JLabel(Utilities.getResourceString("dialog_menu_timeout")), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        inputPanel.add(timeoutField, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        inputPanel.add(new JLabel(Utilities.getResourceString("dialog_menu_refresh")), gbc);

        gbc.gridx = 1;
        inputPanel.add(refreshCheckBox, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okButton = new JButton(Utilities.getResourceString("dialog_menu_ok_button"));
        JButton cancelButton = new JButton(Utilities.getResourceString("dialog_menu_cancel_button"));

        okButton.addActionListener(e -> {
            confirmed = true;
            dispose();
        });

        cancelButton.addActionListener(e -> {
            confirmed = false;
            dispose();
        });

        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);

        add(inputPanel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        getRootPane().setDefaultButton(okButton);

        pack();
        setLocationRelativeTo(getParent());
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public String getNameId() {
        return nameIdField.getText().trim();
    }

    public String getAssertionURL() {
        return assertionURLField.getText().trim();
    }

    public String getMetadataURL() {
        return metadataURLField.getText().trim();
    }

    public int getTimeout() {
        try {
            return Integer.parseInt(timeoutField.getText().trim());
        } catch (NumberFormatException e) {
            return 100;
        }
    }

    public boolean isRefresh() {
        return refreshCheckBox.isSelected();
    }

}