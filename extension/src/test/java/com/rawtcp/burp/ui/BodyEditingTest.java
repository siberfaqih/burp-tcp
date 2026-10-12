package com.rawtcp.burp.ui;

import com.google.protobuf.ByteString;
import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.testutil.FakeControlPlane;
import org.junit.jupiter.api.Test;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class BodyEditingTest {
    private static void edt(Runnable action) throws Exception { SwingUtilities.invokeAndWait(action); }
    private static void flush() throws Exception { edt(() -> {}); }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static String text(byte[] bytes) { return new String(bytes, StandardCharsets.UTF_8); }
    private static BurpTcp.PendingUnitInfo unit(String id, byte[] bytes) {
        return BurpTcp.PendingUnitInfo.newBuilder().setUnitId(id).setConnId("conn")
                .setRevision(1).setBytes(ByteString.copyFrom(bytes)).build();
    }
    private static void queue(FakeControlPlane fake, BurpTcp.PendingUnitInfo... units) {
        fake.pendingResult = CompletableFuture.completedFuture(
                BurpTcp.PendingList.newBuilder().addAllUnits(List.of(units)).build());
    }

    @Test void activeParameterCellIsEncodedAndCommittedByForward() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        queue(fake, unit("a", bytes("name=Alice+Smith&token=%2f%252F&name=second")));
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        edt(() -> {
            ref.set(new InterceptPanel(fake));
            ref.get().setConnected(true);
            ref.get().refreshAll();
        });
        flush();
        edt(() -> {
            BinaryEditorPanel editor = ref.get().editor();
            editor.selectMode(false);
            JTable parameters = editor.parameters().table();
            assertEquals("Alice Smith", parameters.getValueAt(0, 1));
            assertEquals("/%2F", parameters.getValueAt(1, 1));
            assertTrue(parameters.editCellAt(0, 1));
            ((JTextField) parameters.getEditorComponent()).setText("Bob & +%é");
            // Do not press Enter in the cell: Forward must commit it itself.
            ref.get().forwardEdited();
        });
        assertEquals(1, fake.decideCalls.size());
        BurpTcp.Decide decision = fake.decideCalls.getFirst();
        assertEquals("a", decision.getUnitId());
        assertEquals(BurpTcp.InterceptActionKind.REPLACE, decision.getAction());
        assertEquals("name=Bob+%26+%2B%25%C3%A9&token=%2f%252F&name=second", text(decision.getReplaceBytes().toByteArray()));
    }

    @Test void utf8ChoiceSurvivesNewUnitsBinaryPreviewAndReturningToDraft() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        queue(fake, unit("a", bytes("name=one")), unit("b", new byte[] {0, (byte) 255}), unit("c", bytes("name=three")));
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        edt(() -> {
            ref.set(new InterceptPanel(fake));
            ref.get().setConnected(true);
            ref.get().refreshAll();
        });
        flush();
        edt(() -> {
            BinaryEditorPanel editor = ref.get().editor();
            editor.selectMode(false);
            editor.textArea().setText("name=edited");
            ref.get().selectRow(1);
            assertFalse(editor.isHexMode());
            assertFalse(editor.textArea().isEditable());
            assertArrayEquals(new byte[] {0, (byte) 255}, editor.getBytes());
            ref.get().selectRow(2);
            assertFalse(editor.isHexMode());
            assertTrue(editor.textArea().isEditable());
            ref.get().selectRow(0);
            assertFalse(editor.isHexMode());
            assertEquals("name=edited", text(editor.getBytes()));
            ref.get().forwardEdited();
        });
        flush();
        flush();
        edt(() -> assertFalse(ref.get().editor().isHexMode(), "auto-advance must keep UTF-8"));
    }

    @Test void refreshDoesNotTerminateAnActiveParameterEdit() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        BurpTcp.PendingUnitInfo a = unit("a", bytes("name=one"));
        queue(fake, a);
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        edt(() -> {
            ref.set(new InterceptPanel(fake));
            ref.get().setConnected(true);
            ref.get().refreshAll();
        });
        flush();
        edt(() -> {
            JTable table = ref.get().editor().parameters().table();
            assertTrue(table.editCellAt(0, 1));
            ((JTextField) table.getEditorComponent()).setText("still typing");
        });
        queue(fake, a, unit("b", bytes("other=two")));
        edt(() -> ref.get().refreshAll());
        flush();
        edt(() -> {
            JTable table = ref.get().editor().parameters().table();
            assertTrue(table.isEditing());
            assertEquals("still typing", ((JTextField) table.getEditorComponent()).getText());
            ref.get().forwardEdited();
        });
        assertEquals("name=still+typing", text(fake.decideCalls.getFirst().getReplaceBytes().toByteArray()));
    }

    @Test void merelyViewingDecodedParametersForwardsOriginalEncoding() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        queue(fake, unit("a", bytes("a=%2f%252F&empty=&a=one+two")));
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        edt(() -> {
            ref.set(new InterceptPanel(fake));
            ref.get().setConnected(true);
            ref.get().refreshAll();
        });
        flush();
        edt(() -> {
            assertEquals("/%2F", ref.get().editor().parameters().table().getValueAt(0, 1));
            ref.get().editor().selectMode(false);
            ref.get().forwardEdited();
        });
        assertEquals(BurpTcp.InterceptActionKind.FORWARD, fake.decideCalls.getFirst().getAction());
    }

    @Test void urlToolsOnlyTransformSelectedTextAndRejectMalformedEscapes() throws Exception {
        edt(() -> {
            BinaryEditorPanel editor = new BinaryEditorPanel();
            editor.setBytes(bytes("prefix a+b suffix"), false);
            editor.textArea().select(7, 10);
            editor.transformSelection(true);
            assertEquals("prefix a%2Bb suffix", text(editor.getBytes()));
            editor.textArea().select(7, 12);
            editor.transformSelection(false);
            assertEquals("prefix a+b suffix", text(editor.getBytes()));
            editor.loadBytes(bytes("x=%FF"));
            editor.transformSelection(false);
            assertEquals("x=%FF", text(editor.getBytes()));
            assertTrue(editor.lossWarning().contains("not valid UTF-8"));
        });
    }

    @Test void rawEditingInvalidatesOldParameterProjectionBeforeItCanBeUsed() throws Exception {
        AtomicReference<BinaryEditorPanel> ref = new AtomicReference<>();
        edt(() -> {
            ref.set(new BinaryEditorPanel());
            ref.get().setBytes(bytes("a=one"), false);
            assertEquals(1, ref.get().parameters().table().getRowCount());
            ref.get().textArea().setText("arbitrary payload");
        });
        flush();
        edt(() -> {
            assertEquals(0, ref.get().parameters().table().getRowCount());
            assertEquals("arbitrary payload", text(ref.get().getBytes()));
        });
    }

    @Test void parameterEditUndoRestoresOriginalWireBytesInOneStep() throws Exception {
        edt(() -> {
            BinaryEditorPanel editor = new BinaryEditorPanel();
            byte[] original = bytes("name=one+two&token=%2f");
            editor.setBytes(original, false);
            editor.parameters().table().setValueAt("edited & value", 0, 1);
            assertEquals("name=edited+%26+value&token=%2f", text(editor.getBytes()));
            editor.getActionMap().get("Undo").actionPerformed(null);
            assertArrayEquals(original, editor.getBytes());
            assertEquals("one two", editor.parameters().table().getValueAt(0, 1));
            editor.getActionMap().get("Redo").actionPerformed(null);
            assertEquals("name=edited+%26+value&token=%2f", text(editor.getBytes()));
        });
    }

    @Test void pastedLfOnlyHttpRequestShowsParameters() throws Exception {
        edt(() -> {
            BinaryEditorPanel editor = new BinaryEditorPanel();
            String wire = "POST /login HTTP/1.1\nHost: localhost\n"
                    + "Content-Type: application/x-www-form-urlencoded\n"
                    + "Content-Length:  12\n\nname=Ali&x=1";
            editor.setBytes(bytes(wire), false);
            // The exact pasted bytes must survive the text view untouched.
            assertArrayEquals(bytes(wire), editor.getBytes());
            assertEquals(2, editor.parameters().table().getRowCount());
            assertEquals("Ali", editor.parameters().table().getValueAt(0, 1));
        });
    }
}
