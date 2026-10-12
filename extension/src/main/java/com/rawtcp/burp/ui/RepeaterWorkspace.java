package com.rawtcp.burp.ui;

import com.rawtcp.burp.ipc.ControlPlane;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;

/** Independent drafts/results, with one active send across the IPC session. */
final class RepeaterWorkspace extends JPanel {
    private static final int MAX_DRAFTS = 16;
    private final ControlPlane client;
    private final JTabbedPane tabs = new JTabbedPane();
    private final List<RepeaterPanel> drafts = new ArrayList<>();
    private final JLabel status = new JLabel(" ");
    private boolean connected;
    private RepeaterPanel active;
    private int nextNumber;
    private java.util.function.Consumer<java.awt.Component> theme = component -> {};

    RepeaterWorkspace(ControlPlane client) {
        super(new BorderLayout(4, 4));
        this.client = client;
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton add = new JButton("New draft");
        add.addActionListener(event -> create());
        JButton close = new JButton("Close draft");
        close.addActionListener(event -> {
            RepeaterPanel panel = selected();
            if (panel.isActive()) {
                status.setText("Stop the active send before closing this draft.");
                return;
            }
            drafts.remove(panel);
            tabs.remove(panel);
            if (drafts.isEmpty()) create();
            status.setText(" ");
        });
        bar.add(add);
        bar.add(close);
        bar.add(status);
        add(bar, BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);
        create();
    }

    private RepeaterPanel create() {
        if (drafts.size() >= MAX_DRAFTS) {
            status.setText("16 drafts open — close a draft before adding another.");
            return null;
        }
        RepeaterPanel panel = new RepeaterPanel(client);
        theme.accept(panel);
        panel.setConnected(connected);
        panel.setWorkspaceBusy(active != null);
        panel.setActivityListener(busy -> {
            if (busy) active = panel;
            else if (active == panel) active = null;
            for (RepeaterPanel draft : drafts) draft.setWorkspaceBusy(active != null && active != draft);
            status.setText(active == null ? " " : "One send active · other drafts remain editable");
        });
        drafts.add(panel);
        tabs.addTab(Integer.toString(++nextNumber), panel);
        tabs.setSelectedComponent(panel);
        return panel;
    }

    boolean open(String host, int port, byte[] bytes, String origin) {
        RepeaterPanel panel = create();
        if (panel == null) return false;
        panel.loadDraft(host, port, bytes, origin);
        tabs.setTitleAt(tabs.indexOfComponent(panel), nextNumber + " · "
                + (host.isEmpty() ? "Unknown target" : host + ":" + port));
        return true;
    }

    void setConnected(boolean connected) {
        this.connected = connected;
        for (RepeaterPanel panel : drafts) panel.setConnected(connected);
    }

    RepeaterPanel selected() { return (RepeaterPanel) tabs.getSelectedComponent(); }
    int draftCount() { return drafts.size(); }
    void setTheme(java.util.function.Consumer<java.awt.Component> theme) { this.theme = theme; }
}
