package com.rawtcp.burp.ui;

import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.KeyStroke;
import java.awt.GraphicsEnvironment;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/** Shared table interaction conventions; popup actions always use the clicked row. */
final class TrafficActions {
    private TrafficActions() {}

    static JScrollPane scroll(JTable table) {
        JScrollPane scroll = new JScrollPane(table);
        scroll.setColumnHeaderView(table.getTableHeader());
        return scroll;
    }

    static void popup(JTable table, JPopupMenu menu) {
        table.addMouseListener(new MouseAdapter() {
            private void show(MouseEvent event) {
                if (!event.isPopupTrigger()) return;
                int row = table.rowAtPoint(event.getPoint());
                if (row < 0) return;
                table.setRowSelectionInterval(row, row);
                menu.show(table, event.getX(), event.getY());
            }
            @Override public void mousePressed(MouseEvent event) { show(event); }
            @Override public void mouseReleased(MouseEvent event) { show(event); }
        });
    }

    static void shortcut(JComponent component, int key, String name, Runnable run) {
        int mask = GraphicsEnvironment.isHeadless() ? InputEvent.CTRL_DOWN_MASK
                : Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        component.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                .put(KeyStroke.getKeyStroke(key, mask), name);
        component.getActionMap().put(name, new AbstractAction() {
            @Override public void actionPerformed(ActionEvent event) { run.run(); }
        });
    }
}
