package com.rawtcp.burp.ui;

import com.rawtcp.burp.util.FormBody;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.Arrays;
import java.util.function.Consumer;

/** Decoded form fields; duplicate names and original ordering stay intact. */
final class BodyParametersPanel extends JPanel {
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final JLabel status = new JLabel("No body parameters");
    private final JLabel hint = new JLabel("Decoded values · auto-encode on edit");
    private final Consumer<byte[]> onEdit;
    private FormBody form;
    private byte[] lastPayload;
    private boolean editable = true;
    private String editError;

    BodyParametersPanel(Consumer<byte[]> onEdit) {
        super(new BorderLayout(4, 4));
        this.onEdit = onEdit;
        setBorder(BorderFactory.createTitledBorder("Body parameters"));
        setPreferredSize(new Dimension(310, 280));
        setMinimumSize(new Dimension(160, 100));
        table.putClientProperty("terminateEditOnFocusLost", true);
        table.setFillsViewportHeight(true);
        table.setRowHeight(Math.max(24, table.getRowHeight()));
        add(hint, BorderLayout.NORTH);
        add(TrafficActions.scroll(table), BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);
    }

    void setPayload(byte[] bytes) {
        if (Arrays.equals(lastPayload, bytes)) return;
        cancelEditing();
        lastPayload = bytes.clone();
        editError = null;
        try {
            form = FormBody.parse(bytes);
            String where = form.isHttp() ? "Form body · Content-Length updated automatically" : "Form fields in this TCP chunk";
            if (form.isNormalized()) where += " · line endings normalized";
            message(where);
        } catch (IllegalArgumentException error) {
            form = null;
            message(error.getMessage());
        }
        model.fireTableDataChanged();
    }

    void unavailable(String reason) {
        cancelEditing();
        lastPayload = null;
        form = null;
        editError = null;
        message(reason);
        model.fireTableDataChanged();
    }

    private void message(String text) {
        status.setText(text);
        status.setToolTipText(text);
    }

    void commitEditing() {
        if (table.isEditing() && !table.getCellEditor().stopCellEditing())
            throw new IllegalArgumentException("Finish the body parameter edit first");
        if (editError != null) throw new IllegalArgumentException(editError);
    }

    private void cancelEditing() {
        if (table.isEditing()) table.getCellEditor().cancelCellEditing();
    }

    void setEditable(boolean editable) {
        this.editable = editable;
        table.setEnabled(editable);
        hint.setText(editable ? "Decoded values · auto-encode on edit" : "Decoded values · read only");
    }

    JTable table() { return table; }

    private final class Model extends AbstractTableModel {
        @Override public int getRowCount() { return form == null ? 0 : form.fields().size(); }
        @Override public int getColumnCount() { return 2; }
        @Override public String getColumnName(int column) { return column == 0 ? "Name" : "Value"; }
        @Override public boolean isCellEditable(int row, int column) { return editable && form != null; }
        @Override public Object getValueAt(int row, int column) {
            FormBody.Field field = form.fields().get(row);
            return column == 0 ? field.name() : field.value();
        }
        @Override public void setValueAt(Object value, int row, int column) {
            if (!editable || form == null) return;
            FormBody.Field field = form.fields().get(row);
            try {
                FormBody next = form.edit(row, column == 0 ? value.toString() : field.name(),
                        column == 1 ? value.toString() : field.value());
                byte[] bytes = next.bytes();
                if (bytes.length > 65_536) throw new IllegalArgumentException("Edited payload exceeds 64 KiB");
                form = next;
                lastPayload = bytes;
                editError = null;
                onEdit.accept(bytes);
                message("Changes encoded · ready to Forward / Send");
                fireTableRowsUpdated(row, row);
            } catch (IllegalArgumentException error) {
                editError = error.getMessage();
                message(editError);
            }
        }
    }
}
