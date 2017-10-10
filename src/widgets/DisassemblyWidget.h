#ifndef DISASSEMBLYWIDGET_H
#define DISASSEMBLYWIDGET_H

#include <QDebug>
#include <QTextEdit>
#include <QDockWidget>
#include <QTreeWidget>
#include <QTabWidget>
#include <QWebEngineView>
#include <QUrl>
#include <QPlainTextEdit>
#include <QMouseEvent>
#include <memory>
#include "cutter.h"
#include "utils/Highlighter.h"
#include "utils/HexAsciiHighlighter.h"
#include "utils/HexHighlighter.h"
#include "Dashboard.h"
#include "widgets/DisassemblerGraphView.h"


namespace Ui
{
    class DisassemblyWidget;
}

class DisassemblyWidget : public DockWidget
{
    Q_OBJECT

public:
    explicit DisassemblyWidget();
    ~DisassemblyWidget();

    void setup() override;

    void refresh() override;

    QPlainTextEdit   *disasTextEdit;
    QTreeWidget      *xrefToTreeWidget_2;
    QTreeWidget      *xreFromTreeWidget_2;
    QWebEngineView         *histoWebView;
    DisassemblerGraphView *mGraphView;

    Highlighter        *highlighter;
    Highlighter        *highlighter_5;
    AsciiHighlighter   *ascii_highlighter;
    HexHighlighter     *hex_highlighter;
    Highlighter        *preview_highlighter;
    Highlighter        *deco_highlighter;

signals:
    void fontChanged(QFont font);

public slots:
    void addTextDisasm(QString txt);
    void replaceTextDisasm(QString txt);
    void refreshDisasm();
    void fill_refs(QList<XrefDescription> refs, QList<XrefDescription> xrefs, QList<int> graph_data);
    void fillOffsetInfo(QString off);
    void seek_to(const QString &offset);
    QString normalize_addr(QString addr);
    QString normalizeAddr(QString addr);
    void setMiniGraph(QString at);
    void switchTheme(bool dark);
    void highlightDisasms();

protected:
    void resizeEvent(QResizeEvent *event) override;
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    std::unique_ptr<Ui::DisassemblyWidget> ui;
    CutterCore *core;

    ut64 hexdumpTopOffset;
    ut64 hexdumpBottomOffset;
    QString last_fcn;

    RVA disasm_top_offset;
    RVA next_disasm_top_offset;

    RVA last_graph_fcn;
    RVA last_hexdump_fcn;

    void setFcnName(RVA addr);
    void get_refs_data(RVA addr);

    void setScrollMode();

    bool loadMoreDisassembly();

private slots:
    void on_cursorAddressChanged(RVA addr);
    void on_seekChanged(RVA addr);

    void highlightCurrentLine();

    void highlightPreviewCurrentLine();
    void highlightDecoCurrentLine();
    RVA readCurrentDisassemblyOffset();
    void setFonts(QFont font);

    void on_showInfoButton_2_clicked();
    void on_actionSettings_menu_1_triggered();
    void on_actionHideDisasm_side_panel_triggered();

    void showDisasContextMenu(const QPoint &pt);
    void on_actionSend_to_Notepad_triggered();

    void disasmScrolled();
    QList<QString> get_hexdump(const QString &offset);

    void showXrefsDialog();
    void updateViews(RVA offset = RVA_INVALID);
    void on_xreFromTreeWidget_2_itemDoubleClicked(QTreeWidgetItem *item, int column);
    void on_xrefToTreeWidget_2_itemDoubleClicked(QTreeWidgetItem *item, int column);
    void on_xrefFromToolButton_2_clicked();
    void on_xrefToToolButton_2_clicked();
    void on_disasTextEdit_2_cursorPositionChanged();
    void on_offsetToolButton_clicked();
    void on_polarToolButton_clicked();
    void on_radarToolButton_clicked();
    void on_hexSideTab_2_currentChanged(int index);
    void on_memSideToolButton_clicked();
    void on_previewToolButton_clicked();
    void on_decoToolButton_clicked();
    void on_previewToolButton_2_clicked();
    void on_simpleGrapgToolButton_clicked();
    void seek_back();
    void on_memTabWidget_currentChanged(int index);
};

#endif // DisassemblyWidget_H
