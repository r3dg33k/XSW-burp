package burp.views;

import javax.swing.*;
import java.awt.*;

public class TaskInputDialog extends JDialog {
    private final JTextField nameIdField = new JTextField(20);
    private final JTextField destinationField = new JTextField(20);
    private final JTextField timeoutField = new JTextField(20);
    private final JCheckBox signCheckBox = new JCheckBox();
    private boolean confirmed = false;

    public TaskInputDialog(Frame parent, boolean defaultSign, int defaultTimeout) {
        super(parent, "Task Input", true);
        signCheckBox.setSelected(defaultSign);
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
        inputPanel.add(new JLabel("Name ID:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        inputPanel.add(nameIdField, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        inputPanel.add(new JLabel("ACS URL:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        inputPanel.add(destinationField, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        inputPanel.add(new JLabel("Timeout:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        inputPanel.add(timeoutField, gbc);

        row++;
        gbc.gridx = 0;
        gbc.gridy = row;
        inputPanel.add(new JLabel("Self-Sign:"), gbc);

        gbc.gridx = 1;
        inputPanel.add(signCheckBox, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okButton = new JButton("OK");
        JButton cancelButton = new JButton("Cancel");

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

    public String getDestination() {
        return destinationField.getText().trim();
    }

    public int getTimeout() {
        try {
            return Integer.parseInt(timeoutField.getText().trim());
        } catch (NumberFormatException e) {
            return 100;
        }
    }

    public boolean isSign() {
        return signCheckBox.isSelected();
    }

}