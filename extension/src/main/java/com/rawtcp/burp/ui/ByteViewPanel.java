package com.rawtcp.burp.ui;

import com.rawtcp.burp.util.HexText;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Font;
import java.nio.charset.StandardCharsets;

/** Derived read-only views. The displayed text is never used as a payload. */
final class ByteViewPanel extends JPanel {
    private final JTextArea hex = area();
    private final JTextArea text = area();
    private BodyParametersPanel parameters;

    ByteViewPanel() {
        this(false);
    }

    ByteViewPanel(boolean showParameters) {
        super(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Hex", new JScrollPane(hex));
        tabs.addTab("Text (UTF-8 preview)", new JScrollPane(text));
        if (showParameters) {
            parameters = new BodyParametersPanel(bytes -> {});
            parameters.setEditable(false);
            JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tabs, parameters);
            tabs.setPreferredSize(new java.awt.Dimension(550, 250));
            split.setResizeWeight(1.0);
            add(split, BorderLayout.CENTER);
        } else add(tabs, BorderLayout.CENTER);
    }

    private static JTextArea area() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    void setBytes(byte[] bytes) {
        hex.setText(HexText.toHexDump(bytes));
        text.setText(new String(bytes, StandardCharsets.UTF_8));
        hex.setCaretPosition(0);
        text.setCaretPosition(0);
        if (parameters != null) parameters.setPayload(bytes);
    }

    String hexDump() { return hex.getText(); }
}
