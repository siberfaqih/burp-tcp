package com.rawtcp.burp.ui;

import com.rawtcp.burp.util.HexText;
import com.rawtcp.burp.util.UrlCodec;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.undo.UndoManager;
import javax.swing.undo.CompoundEdit;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.KeyEvent;
import java.nio.charset.StandardCharsets;

/** Wire-byte editor with a reversible decoded form projection and sticky view preference. */
public final class BinaryEditorPanel extends JPanel {
    private static final String HEX = "Hex";
    private static final String TEXT = "Text (UTF-8)";
    private final JTextArea area = new JTextArea(12, 48);
    private final JComboBox<String> mode = new JComboBox<>(new String[] {HEX, TEXT});
    private final JLabel status = new JLabel(" ");
    private final JLabel notice = new JLabel(" ");
    private final UndoManager undo = new UndoManager();
    private CompoundEdit compound;
    private final BodyParametersPanel parameters = new BodyParametersPanel(this::replaceWireBytes);
    private final JButton encode = new JButton("URL encode");
    private final JButton decode = new JButton("URL decode");
    private boolean suppress;
    private boolean refreshQueued;
    private boolean preferredHex = true;
    private boolean displayedHex = true;
    private boolean editable = true;
    /** Invalid UTF-8 can be viewed, but its original bytes must never be reconstructed from that preview. */
    private byte[] preservedBytes;

    record Draft(boolean hex, String text, byte[] preserved) {}

    public BinaryEditorPanel() {
        super(new BorderLayout(4, 4));
        setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setLineWrap(true);
        area.getDocument().addUndoableEditListener(event -> {
            if (compound == null) undo.addEdit(event.getEdit());
            else compound.addEdit(event.getEdit());
        });
        area.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { changed(); }
            @Override public void removeUpdate(DocumentEvent event) { changed(); }
            @Override public void changedUpdate(DocumentEvent event) { changed(); }
        });
        TrafficActions.shortcut(this, KeyEvent.VK_Z, "Undo", () -> {
            if (area.isEditable() && undo.canUndo()) undo.undo();
        });
        TrafficActions.shortcut(this, KeyEvent.VK_Y, "Redo", () -> {
            if (area.isEditable() && undo.canRedo()) undo.redo();
        });
        mode.addActionListener(event -> changeMode());
        encode.addActionListener(event -> transformSelection(true));
        decode.addActionListener(event -> transformSelection(false));
        encode.setToolTipText("URL-encode selected text (or all text). Manual change to wire bytes.");
        decode.setToolTipText("URL-decode selected text once. Use Body parameters for automatic re-encoding.");

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        bar.add(new JLabel("View:"));
        bar.add(mode);
        bar.add(encode);
        bar.add(decode);
        JCheckBox inspector = new JCheckBox("Parameters", true);
        bar.add(inspector);
        JPanel raw = new JPanel(new BorderLayout(4, 4));
        raw.add(bar, BorderLayout.NORTH);
        raw.add(new JScrollPane(area), BorderLayout.CENTER);
        raw.setPreferredSize(new Dimension(550, 280));
        raw.setMinimumSize(new Dimension(220, 100));
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, raw, parameters);
        split.setResizeWeight(1.0);
        inspector.addActionListener(event -> {
            parameters.setVisible(inspector.isSelected());
            split.setDividerSize(inspector.isSelected() ? UIManager.getInt("SplitPane.dividerSize") : 0);
            if (inspector.isSelected()) split.setDividerLocation(Math.max(220, split.getWidth() - 320));
        });
        JPanel footer = new JPanel(new java.awt.GridLayout(0, 1));
        footer.add(status);
        footer.add(notice);
        add(split, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);
        loadBytes(new byte[0]);
    }

    /** Explicit initial preference, for callers setting up a new editor. */
    public void setBytes(byte[] bytes, boolean hexMode) {
        preferredHex = hexMode;
        loadBytes(bytes);
    }

    /** New traffic inherits the user's last view choice, including UTF-8 for binary previews. */
    public void loadBytes(byte[] bytes) {
        display(bytes, preferredHex);
        undo.discardAllEdits();
        parameters.setPayload(bytes);
    }

    private void display(byte[] bytes, boolean hex) {
        suppress = true;
        preservedBytes = null;
        displayedHex = hex;
        notice.setText(" ");
        compound = new CompoundEdit();
        try {
            mode.setSelectedItem(hex ? HEX : TEXT);
            if (hex) area.setText(formattedHex(bytes));
            else {
                try { area.setText(UrlCodec.text(bytes)); }
                catch (IllegalArgumentException invalid) {
                    preservedBytes = bytes.clone();
                    area.setText(new String(bytes, StandardCharsets.UTF_8));
                    notice.setText("Bytes are not valid UTF-8 · read-only preview; Forward preserves original bytes. Choose Hex to edit.");
                }
            }
            area.setCaretPosition(0);
        } finally {
            suppress = false;
            compound.end();
            undo.addEdit(compound);
            compound = null;
        }
        updateEditable();
        updateStatus();
    }

    private void replaceWireBytes(byte[] bytes) {
        display(bytes, displayedHex);
        // Preserve the undo stack: parameter changes are ordinary byte edits.
    }

    private void changed() {
        if (suppress) return;
        updateStatus();
        if (!refreshQueued) {
            refreshQueued = true;
            SwingUtilities.invokeLater(() -> {
                refreshQueued = false;
                syncParameters();
            });
        }
    }

    private void syncParameters() {
        try { parameters.setPayload(readWireBytes()); }
        catch (IllegalArgumentException invalid) { parameters.unavailable(invalid.getMessage()); }
    }

    public byte[] getBytes() {
        syncParameters();
        parameters.commitEditing(); // includes a cell still being edited when Forward is clicked
        return readWireBytes();
    }

    private byte[] readWireBytes() {
        if (preservedBytes != null) return preservedBytes.clone();
        return displayedHex ? HexText.fromHex(area.getText()) : UrlCodec.utf8(area.getText());
    }

    private void changeMode() {
        if (suppress) return;
        boolean hex = HEX.equals(mode.getSelectedItem());
        if (hex == displayedHex) return;
        try {
            byte[] bytes = getBytes();
            preferredHex = hex;
            display(bytes, hex);
            undo.discardAllEdits();
        } catch (IllegalArgumentException invalid) {
            suppress = true;
            mode.setSelectedItem(displayedHex ? HEX : TEXT);
            suppress = false;
            notice.setText(invalid.getMessage());
        }
    }

    void transformSelection(boolean encoding) {
        if (!area.isEditable() || displayedHex) return;
        try {
            parameters.commitEditing();
            String selected = area.getSelectedText();
            String value = selected == null ? area.getText() : selected;
            String transformed = encoding ? UrlCodec.encode(value, true) : UrlCodec.decode(value, true);
            if (selected == null) area.selectAll();
            area.replaceSelection(transformed);
            notice.setText("Manual URL " + (encoding ? "encode" : "decode") + " applied to wire bytes");
        } catch (IllegalArgumentException invalid) {
            notice.setText(invalid.getMessage());
        }
    }

    Draft captureDraft() {
        syncParameters();
        try { parameters.commitEditing(); }
        catch (IllegalArgumentException invalid) { notice.setText(invalid.getMessage()); }
        return new Draft(displayedHex, area.getText(), preservedBytes == null ? null : preservedBytes.clone());
    }

    void restoreDraft(Draft draft) {
        if (draft.preserved() != null) loadBytes(draft.preserved());
        else {
            try { loadBytes(draft.hex() ? HexText.fromHex(draft.text()) : UrlCodec.utf8(draft.text())); }
            catch (IllegalArgumentException incomplete) {
                // Keep a partially typed hex draft intact; do not treat its digits as UTF-8 bytes.
                display(new byte[0], draft.hex());
                area.setText(draft.text());
                syncParameters();
                undo.discardAllEdits();
            }
        }
    }

    private void updateStatus() {
        try {
            byte[] bytes = readWireBytes();
            status.setText(bytes.length + " bytes" + (preservedBytes == null ? "" : " · original binary preserved"));
            status.setForeground(UIManager.getColor("Label.foreground"));
        } catch (IllegalArgumentException invalid) {
            status.setText(invalid.getMessage());
            status.setForeground(Color.RED);
        }
    }

    public void setEditable(boolean editable) { this.editable = editable; updateEditable(); }
    private void updateEditable() {
        area.setEditable(editable && preservedBytes == null);
        mode.setEnabled(editable);
        parameters.setEditable(editable && preservedBytes == null);
        encode.setEnabled(area.isEditable() && !displayedHex);
        decode.setEnabled(area.isEditable() && !displayedHex);
    }

    public boolean isHexMode() { return displayedHex; }
    public JTextArea textArea() { return area; }
    void selectMode(boolean hex) { mode.setSelectedItem(hex ? HEX : TEXT); }
    String lossWarning() { return notice.getText(); }
    BodyParametersPanel parameters() { syncParameters(); return parameters; }

    private static String formattedHex(byte[] bytes) {
        String hex = HexText.toHex(bytes);
        StringBuilder out = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) out.append(i % 16 == 0 ? '\n' : ' ');
            out.append(hex, i * 2, i * 2 + 2);
        }
        return out.toString();
    }

    @Override public Dimension getPreferredSize() { return new Dimension(870, 300); }
}
