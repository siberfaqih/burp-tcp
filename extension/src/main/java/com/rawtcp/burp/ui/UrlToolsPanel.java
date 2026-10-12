package com.rawtcp.burp.ui;

import com.rawtcp.burp.util.UrlCodec;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;

/** Offline URL encoder/decoder; importing data never changes captured or held bytes. */
final class UrlToolsPanel extends JPanel {
    private final JTextArea input = area();
    private final JTextArea output = area();
    private final JCheckBox form = new JCheckBox("Form encoding (+ = space)", true);
    private final JLabel status = new JLabel("Paste text or use Send to Decoder from traffic.");

    UrlToolsPanel() {
        super(new BorderLayout(6, 6));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton encode = new JButton("URL encode");
        JButton decode = new JButton("URL decode");
        JButton again = new JButton("Use output as input");
        encode.addActionListener(event -> transform(true));
        decode.addActionListener(event -> transform(false));
        again.addActionListener(event -> input.setText(output.getText()));
        actions.add(encode);
        actions.add(decode);
        actions.add(form);
        actions.add(again);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, pane("Input", input), pane("Output", output));
        split.setResizeWeight(0.5);
        add(actions, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);
    }

    private static JTextArea area() {
        JTextArea area = new JTextArea(10, 70);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setLineWrap(true);
        return area;
    }

    private static JScrollPane pane(String title, JTextArea area) {
        JScrollPane scroll = new JScrollPane(area);
        scroll.setBorder(BorderFactory.createTitledBorder(title));
        return scroll;
    }

    void load(byte[] bytes) {
        try {
            input.setText(UrlCodec.text(bytes));
            output.setText("");
            status.setText("Traffic copied · one decode per click · original traffic is unchanged");
        } catch (IllegalArgumentException invalid) {
            input.setText("");
            output.setText("");
            status.setText(invalid.getMessage() + " · use Hex for this payload");
        }
    }

    private void transform(boolean encoding) {
        try {
            output.setText(encoding ? UrlCodec.encode(input.getText(), form.isSelected())
                    : UrlCodec.decode(input.getText(), form.isSelected()));
            output.setCaretPosition(0);
            status.setText("URL " + (encoding ? "encoded" : "decoded") + " once · UTF-8");
        } catch (IllegalArgumentException invalid) {
            output.setText("");
            status.setText(invalid.getMessage());
        }
    }
}
