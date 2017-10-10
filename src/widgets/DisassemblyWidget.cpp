#include "DisassemblyWidget.h"
#include "ui_DisassemblyWidget.h"
#include "DisassemblerGraphView.h"

#include "MainWindow.h"
#include "utils/Helpers.h"
#include "dialogs/XrefsDialog.h"
#include "menus/DisassemblyContextMenu.h"

#include <QTemporaryFile>
#include <QFontDialog>
#include <QScrollBar>
#include <QClipboard>
#include <QShortcut>
#include <QWebEnginePage>
#include <QMenu>
#include <QFont>
#include <QUrl>
#include <QWebEngineSettings>
#include <QWebEngineProfile>
#include <QSettings>

#include <cassert>

DisassemblyWidget::DisassemblyWidget() :
    ui(new Ui::DisassemblyWidget),
    core(CutterCore::getInstance())
{
    ui->setupUi(this);

    this->disasTextEdit = ui->disasTextEdit_2;
    this->xrefToTreeWidget_2 = ui->xrefToTreeWidget_2;
    this->xreFromTreeWidget_2 = ui->xreFromTreeWidget_2;

    this->last_fcn = "entry0";
    this->last_graph_fcn = 0; //"";
    this->last_hexdump_fcn = 0; //"";

    disasm_top_offset = 0;
    next_disasm_top_offset = 0;

    // Increase asm text edit margin
    QTextDocument *asm_docu = this->disasTextEdit->document();
    asm_docu->setDocumentMargin(10);

    // Setup disasm highlight
    connect(ui->disasTextEdit_2, SIGNAL(cursorPositionChanged()), this, SLOT(highlightCurrentLine()));
    highlightCurrentLine();
    //this->on_actionSettings_menu_1_triggered();

    // Setup hex highlight
    //connect(ui->hexHexText, SIGNAL(cursorPositionChanged()), this, SLOT(highlightHexCurrentLine()));
    //highlightHexCurrentLine();

    // Highlight current line on previews and decompiler
    connect(ui->previewTextEdit, SIGNAL(cursorPositionChanged()), this, SLOT(highlightPreviewCurrentLine()));
    connect(ui->decoTextEdit, SIGNAL(cursorPositionChanged()), this, SLOT(highlightDecoCurrentLine()));

    // Hide memview notebooks tabs
    QTabBar *preTab = ui->memPreviewTab->tabBar();
    preTab->setVisible(false);

    // Hide fcn graph notebooks tabs
    QTabBar *graph_bar = ui->fcnGraphTabWidget->tabBar();
    graph_bar->setVisible(false);

    // Debug console
    // For QWebEngine debugging see: https://doc.qt.io/qt-5/qtwebengine-debugging.html
    //QWebSettings::globalSettings()->setAttribute(QWebSettings::DeveloperExtrasEnabled, true);

    // Add margin to function name line edit
    ui->fcnNameEdit->setTextMargins(5, 0, 0, 0);

    // Normalize fonts for other OS
    qhelpers::normalizeFont(this->disasTextEdit);

    // Popup menu on Settings toolbutton
    QMenu *memMenu = new QMenu();
    ui->memSettingsButton_2->addAction(ui->actionSettings_menu_1);
    memMenu->addAction(ui->actionSettings_menu_1);
    ui->memSettingsButton_2->setMenu(memMenu);

    // Event filter to intercept double clicks in the textbox
    ui->disasTextEdit_2->viewport()->installEventFilter(this);

    // Set Splitter stretch factor
    ui->splitter->setStretchFactor(0, 10);
    ui->splitter->setStretchFactor(1, 1);

    // Set Disas context menu
    ui->disasTextEdit_2->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->disasTextEdit_2, SIGNAL(customContextMenuRequested(const QPoint &)),
            this, SLOT(showDisasContextMenu(const QPoint &)));

    // x or X to show XRefs
    connect(new QShortcut(QKeySequence(Qt::Key_X), ui->disasTextEdit_2),
            SIGNAL(activated()), this, SLOT(showXrefsDialog()));
    connect(new QShortcut(Qt::SHIFT + Qt::Key_X, ui->disasTextEdit_2),
            SIGNAL(activated()), this, SLOT(showXrefsDialog()));

    // Space to switch between disassembly and graph
    QShortcut *graph_shortcut = new QShortcut(QKeySequence(Qt::Key_Space), this);
    connect(graph_shortcut, SIGNAL(activated()), this, SLOT(cycleViews()));
    //graph_shortcut->setContext(Qt::WidgetShortcut);

    // Semicolon to add comment
    QShortcut *comment_shortcut = new QShortcut(QKeySequence(Qt::Key_Semicolon), ui->disasTextEdit_2);
    connect(comment_shortcut, SIGNAL(activated()), this, SLOT(on_actionDisasAdd_comment_triggered()));
    comment_shortcut->setContext(Qt::WidgetShortcut);

    // N to rename function
    QShortcut *rename_shortcut = new QShortcut(QKeySequence(Qt::Key_N), ui->disasTextEdit_2);
    connect(rename_shortcut, SIGNAL(activated()), this, SLOT(on_actionFunctionsRename_triggered()));
    rename_shortcut->setContext(Qt::WidgetShortcut);

    // Esc to seek back
    QShortcut *back_shortcut = new QShortcut(QKeySequence(Qt::Key_Escape), ui->disasTextEdit_2);
    connect(back_shortcut, SIGNAL(activated()), this, SLOT(seek_back()));
    back_shortcut->setContext(Qt::WidgetShortcut);

    // CTRL + R to refresh the disasm
    QShortcut *refresh_shortcut = new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_R), ui->disasTextEdit_2);
    connect(refresh_shortcut, SIGNAL(activated()), this, SLOT(refreshDisasm()));
    refresh_shortcut->setContext(Qt::WidgetShortcut);

    // Control Disasm and Hex scroll to add more contents
    connect(this->disasTextEdit->verticalScrollBar(), SIGNAL(valueChanged(int)), this, SLOT(disasmScrolled()));

    connect(core, SIGNAL(seekChanged(RVA)), this, SLOT(on_seekChanged(RVA)));
    //connect(main, SIGNAL(cursorAddressChanged(RVA)), this, SLOT(on_cursorAddressChanged(RVA)));
    connect(core, SIGNAL(flagsChanged()), this, SLOT(updateViews()));
    connect(core, SIGNAL(commentsChanged()), this, SLOT(updateViews()));
    connect(core, SIGNAL(asmOptionsChanged()), this, SLOT(updateViews()));
}


void DisassemblyWidget::on_seekChanged(RVA addr)
{
    updateViews(addr);
}

void DisassemblyWidget::on_cursorAddressChanged(RVA addr)
{
    setFcnName(addr);
    get_refs_data(addr);
}

/*
 * Text highlight functions
 */

void DisassemblyWidget::highlightDisasms()
{
    // Syntax Highliting
    highlighter = new Highlighter(ui->disasTextEdit_2->document());
    preview_highlighter = new Highlighter(ui->previewTextEdit->document());
    deco_highlighter = new Highlighter(ui->decoTextEdit->document());

}

void DisassemblyWidget::highlightCurrentLine()
{
    QList<QTextEdit::ExtraSelection> extraSelections;

    // Highlight the current line in yellow
    if (ui->disasTextEdit_2->isReadOnly())
    {
        QTextEdit::ExtraSelection selection;

        QColor lineColor = QColor(190, 144, 212);

        selection.format.setBackground(lineColor);
        selection.format.setProperty(QTextFormat::FullWidthSelection, true);
        selection.cursor = ui->disasTextEdit_2->textCursor();
        selection.cursor.clearSelection();
        extraSelections.append(selection);
    }

    // Highlight the current word
    QTextCursor cursor = ui->disasTextEdit_2->textCursor();
    cursor.select(QTextCursor::WordUnderCursor);

    QTextEdit::ExtraSelection currentWord;

    QColor blueColor = QColor(Qt::blue).lighter(160);
    currentWord.format.setBackground(blueColor);

    currentWord.cursor = cursor;
    extraSelections.append(currentWord);
    currentWord.cursor.clearSelection();

    // Highlight all the words in the document same as the actual one
    QString searchString = cursor.selectedText();
    QTextDocument *document = ui->disasTextEdit_2->document();

    //QTextCursor highlightCursor(document);
    QTextEdit::ExtraSelection highlightSelection;
    highlightSelection.cursor = cursor;
    highlightSelection.format.setBackground(blueColor);
    QTextCursor cursor2(document);

    cursor2.beginEditBlock();

    highlightSelection.cursor.movePosition(QTextCursor::Start, QTextCursor::MoveAnchor);
    while (!highlightSelection.cursor.isNull() && !highlightSelection.cursor.atEnd())
    {
        highlightSelection.cursor = document->find(searchString, highlightSelection.cursor, QTextDocument::FindWholeWords);

        if (!highlightSelection.cursor.isNull())
        {
            highlightSelection.cursor.movePosition(QTextCursor::EndOfWord, QTextCursor::KeepAnchor);
            extraSelections.append(highlightSelection);
        }
    }
    cursor2.endEditBlock();

    ui->disasTextEdit_2->setExtraSelections(extraSelections);
}

void DisassemblyWidget::highlightPreviewCurrentLine()
{

    QList<QTextEdit::ExtraSelection> extraSelections;

    if (ui->previewTextEdit->toPlainText() != "")
    {
        if (ui->previewTextEdit->isReadOnly())
        {
            QTextEdit::ExtraSelection selection;

            QColor lineColor = QColor(190, 144, 212);

            selection.format.setBackground(lineColor);
            selection.format.setProperty(QTextFormat::FullWidthSelection, true);
            selection.cursor = ui->previewTextEdit->textCursor();
            selection.cursor.clearSelection();
            extraSelections.append(selection);
        }
    }
    ui->previewTextEdit->setExtraSelections(extraSelections);
}

void DisassemblyWidget::highlightDecoCurrentLine()
{

    QList<QTextEdit::ExtraSelection> extraSelections;

    if (ui->decoTextEdit->toPlainText() != "")
    {
        if (ui->decoTextEdit->isReadOnly())
        {
            QTextEdit::ExtraSelection selection;

            QColor lineColor = QColor(190, 144, 212);

            selection.format.setBackground(lineColor);
            selection.format.setProperty(QTextFormat::FullWidthSelection, true);
            selection.cursor = ui->decoTextEdit->textCursor();
            selection.cursor.clearSelection();
            extraSelections.append(selection);
        }
    }
    ui->decoTextEdit->setExtraSelections(extraSelections);
}

RVA DisassemblyWidget::readCurrentDisassemblyOffset()
{
    // TODO: do this in a different way without parsing the disassembly text
    QTextCursor tc = this->disasTextEdit->textCursor();
    tc.select(QTextCursor::LineUnderCursor);
    QString lastline = tc.selectedText();
    QStringList parts = lastline.split(" ", QString::SkipEmptyParts);

    if (parts.isEmpty())
        return RVA_INVALID;

    QString ele = parts[0];
    if (!ele.contains("0x"))
        return RVA_INVALID;

    return ele.toULongLong(0, 16);
}

DisassemblyWidget::~DisassemblyWidget() {}

void DisassemblyWidget::setup()
{
    setScrollMode();

    const QString off = core->cmd("afo entry0").trimmed();
    RVA offset = off.toULongLong(0, 16);
    updateViews(offset);

    //refreshDisasm();
    //refreshHexdump(off);
    //create_graph(off);
    get_refs_data(offset);
    //setFcnName(off);
}

void DisassemblyWidget::refresh()
{
    setScrollMode();

    // TODO: honor the offset
    updateViews(RVA_INVALID);
}

/*
 * Content management functions
 */

void DisassemblyWidget::addTextDisasm(QString txt)
{
    //QTextDocument *document = ui->disasTextEdit_2->document();
    //document->undo();
    ui->disasTextEdit_2->appendPlainText(txt);
}

void DisassemblyWidget::replaceTextDisasm(QString txt)
{
    //QTextDocument *document = ui->disasTextEdit_2->document();
    ui->disasTextEdit_2->clear();
    //document->undo();
    ui->disasTextEdit_2->setPlainText(txt);
}

bool DisassemblyWidget::loadMoreDisassembly()
{
    /*
     * Add more disasm as the user scrolls
     * Not working properly when scrolling upwards
     * r2 doesn't handle properly 'pd-' for archs with variable instruction size
     */
    // Disconnect scroll signals to add more content
    disconnect(this->disasTextEdit->verticalScrollBar(), SIGNAL(valueChanged(int)), this, SLOT(disasmScrolled()));

    QScrollBar *sb = this->disasTextEdit->verticalScrollBar();

    bool loaded = false;

    if (sb->value() > sb->maximum() - 10)
    {
        //this->main->add_debug_output("End is coming");

        QTextCursor tc = this->disasTextEdit->textCursor();
        tc.movePosition(QTextCursor::End);
        RVA offset = readCurrentDisassemblyOffset();

        if (offset != RVA_INVALID)
        {
            core->seek(offset);
            QString raw = this->core->cmd("pd 200");
            QString txt = raw.section("\n", 1, -1);
            //this->disasTextEdit->appendPlainText(" ;\n ; New content here\n ;\n " + txt.trimmed());
            this->disasTextEdit->appendPlainText(txt.trimmed());
        }
        else
        {
            tc.movePosition(QTextCursor::End);
            tc.select(QTextCursor::LineUnderCursor);
            QString lastline = tc.selectedText();
            //this->main->addDebugOutput("Last line: " + lastline);
        }

        loaded = true;

        // Code below will be used to append more disasm upwards, one day
    } /* else if (sb->value() < sb->minimum() + 10) {
        //this->main->add_debug_output("Begining is coming");

        QTextCursor tc = this->disasTextEdit->textCursor();
        tc.movePosition( QTextCursor::Start );
        tc.select( QTextCursor::LineUnderCursor );
        QString firstline = tc.selectedText();
        //this->main->add_debug_output("First Line: " + firstline);
        QString ele = firstline.split(" ", QString::SkipEmptyParts)[0];
        //this->main->add_debug_output("First Offset: " + ele);
        if (ele.contains("0x")) {
            int b = this->disasTextEdit->verticalScrollBar()->maximum();
            this->core->cmd("ss " + ele);
            this->core->cmd("so -50");
            QString raw = this->core->cmd("pd 50");
            //this->main->add_debug_output(raw);
            //QString txt = raw.section("\n", 1, -1);
            //this->main->add_debug_output(txt);
            tc.movePosition(QTextCursor::Start, QTextCursor::MoveAnchor);
            //tc.insertText(raw.trimmed() + "\n ;\n ; New content prepended here\n ;\n");
            int c = this->disasTextEdit->verticalScrollBar()->maximum();
            int z = c -b;
            int a = this->disasTextEdit->verticalScrollBar()->sliderPosition();
            this->disasTextEdit->verticalScrollBar()->setValue(a + z);
        } else {
            tc.movePosition( QTextCursor::Start );
            tc.select( QTextCursor::LineUnderCursor );
            QString lastline = tc.selectedText();
            this->main->add_debug_output("Last line: " + lastline);
        }
    } */

    // Reconnect scroll signals
    connect(this->disasTextEdit->verticalScrollBar(), SIGNAL(valueChanged(int)), this, SLOT(disasmScrolled()));

    return loaded;
}


void DisassemblyWidget::disasmScrolled()
{
    loadMoreDisassembly();
}

void DisassemblyWidget::refreshDisasm()
{
    RCoreLocked lcore = this->core->core();

    // Prevent further scroll
    disconnect(this->disasTextEdit->verticalScrollBar(), SIGNAL(valueChanged(int)), this, SLOT(disasmScrolled()));
    disconnect(this->disasTextEdit, SIGNAL(cursorPositionChanged()), this, SLOT(on_disasTextEdit_2_cursorPositionChanged()));

    RVA offset = next_disasm_top_offset;
    next_disasm_top_offset = RVA_INVALID;
    bool offset_changed = offset != RVA_INVALID;

    if (offset_changed) // new offset (seek)
    {
        disasm_top_offset = offset;
        this->core->cmd(QString("s %1").arg(offset));
    }
    else // simple refresh
    {
        core->cmd(QString("s %1").arg(disasm_top_offset));
    }

    QString txt2 = this->core->cmd("pd 200");

    disasTextEdit->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);

    // if the offset changed, jump to the top
    // otherwise try to retain the position
    int cursor_pos = offset_changed ? 0 : disasTextEdit->textCursor().position();
    int scroll_pos = offset_changed ? 0 : disasTextEdit->verticalScrollBar()->value();

    this->disasTextEdit->setPlainText(txt2.trimmed());

    auto cursor = disasTextEdit->textCursor();
    cursor.setPosition(cursor_pos);
    disasTextEdit->setTextCursor(cursor);

    disasTextEdit->verticalScrollBar()->setValue(scroll_pos);

    // load more disassembly if necessary
    static const int load_more_limit = 10; // limit passes, so it can't take forever
    for (int load_more_i = 0; load_more_i < load_more_limit; load_more_i++)
    {
        if (!loadMoreDisassembly())
            break;
        disasTextEdit->verticalScrollBar()->setValue(scroll_pos);
    }

    connect(this->disasTextEdit->verticalScrollBar(), SIGNAL(valueChanged(int)), this, SLOT(disasmScrolled()));
    connect(this->disasTextEdit, SIGNAL(cursorPositionChanged()), this, SLOT(on_disasTextEdit_2_cursorPositionChanged()));
    this->on_disasTextEdit_2_cursorPositionChanged();
}

QList<QString> DisassemblyWidget::get_hexdump(const QString &offset)
{
    RCoreLocked lcore = this->core->core();
    QList<QString> ret;
    QString hexdump;

    int hexdumpLength;
    int cols = lcore->print->cols;
    ut64 bsize = 128 * cols;
    if (hexdumpBottomOffset < bsize)
    {
        hexdumpBottomOffset = 0;
        hexdumpLength = bsize;
        //-hexdumpBottomOffset;
    }
    else
    {
        hexdumpLength = bsize;
    }

    //this->main->add_debug_output("BSize: " + this->core->itoa(hexdumpLength, 10));

    if (offset.isEmpty())
    {
        hexdump = this->core->cmd("px " + this->core->itoa(hexdumpLength, 10));
    }
    else
    {
        hexdump = this->core->cmd("px " + this->core->itoa(hexdumpLength, 10) + " @ " + offset);
    }
    //QString hexdump = this->core->cmd ("px 0x" + this->core->itoa(size) + " @ 0x0");
    // TODO: use pxl to simplify
    QString offsets;
    QString hex;
    QString ascii;
    int ln = 0;

    for (const QString line : hexdump.split("\n"))
    {
        if (ln++ == 0)
        {
            continue;
        }
        int wc = 0;
        for (const QString a : line.split("  "))
        {
            switch (wc++)
            {
            case 0:
                offsets += a + "\n";
                break;
            case 1:
            {
                hex += a.trimmed() + "\n";
            }
            break;
            case 2:
                ascii += a + "\n";
                break;
            }
        }
    }
    ret << offsets.trimmed();
    ret << hex.trimmed();
    ret << ascii.trimmed();

    return ret;
}


void DisassemblyWidget::seek_to(const QString &offset)
{
    this->disasTextEdit->moveCursor(QTextCursor::End);
    this->disasTextEdit->find(offset, QTextDocument::FindBackward);
    this->disasTextEdit->moveCursor(QTextCursor::StartOfWord, QTextCursor::MoveAnchor);
}

/*
 * Context menu functions
 */

void DisassemblyWidget::showDisasContextMenu(const QPoint &pt)
{
    DisassemblyContextMenu menu(this->readCurrentDisassemblyOffset(), ui->disasTextEdit_2);
    menu.exec(ui->disasTextEdit_2->mapToGlobal(pt));
}

void DisassemblyWidget::on_showInfoButton_2_clicked()
{
    if (ui->showInfoButton_2->isChecked())
    {
        ui->fcnGraphTabWidget->hide();
        ui->showInfoButton_2->setArrowType(Qt::RightArrow);
    }
    else
    {
        ui->fcnGraphTabWidget->show();
        ui->showInfoButton_2->setArrowType(Qt::DownArrow);
    }
}

void DisassemblyWidget::on_offsetToolButton_clicked()
{
    if (ui->offsetToolButton->isChecked())
    {
        ui->offsetTreeWidget->hide();
        ui->offsetToolButton->setArrowType(Qt::RightArrow);
    }
    else
    {
        ui->offsetTreeWidget->show();
        ui->offsetToolButton->setArrowType(Qt::DownArrow);
    }
}


void DisassemblyWidget::showXrefsDialog()
{
    // Get current offset
    QTextCursor tc = this->disasTextEdit->textCursor();
    tc.select(QTextCursor::LineUnderCursor);
    QString lastline = tc.selectedText();
    QString ele = lastline.split(" ", QString::SkipEmptyParts)[0];
    if (ele.contains("0x"))
    {
        RVA addr = ele.toLongLong(0, 16);
        XrefsDialog *x = new XrefsDialog(this);
        x->fillRefsForAddress(addr, RAddressString(addr), false);
        x->exec();
    }
}


/*
 * Actions callback functions
 */

void DisassemblyWidget::on_actionSettings_menu_1_triggered()
{
    bool ok = true;

    // QFont font = QFont("Monospace", 8);
    // TODO Use global configuration
    QFont font = QFontDialog::getFont(&ok, ui->disasTextEdit_2->font(), this);

    if (ok)
    {
        setFonts(font);

        emit fontChanged(font);
    }
}
void DisassemblyWidget::setFonts(QFont font)
{
    ui->disasTextEdit_2->setFont(font);
    // the user clicked OK and font is set to the font the user selected
    ui->disasTextEdit_2->setFont(font);
    ui->previewTextEdit->setFont(font);
    ui->decoTextEdit->setFont(font);
}

void DisassemblyWidget::on_actionHideDisasm_side_panel_triggered()
{
    if (ui->sideWidget->isVisible())
    {
        ui->sideWidget->hide();
    }
    else
    {
        ui->sideWidget->show();
    }
}

/*
 * Buttons callback functions
 */

void DisassemblyWidget::on_actionSend_to_Notepad_triggered()
{
    QTextCursor cursor = ui->disasTextEdit_2->textCursor();
    QString text = cursor.selectedText();
    // TODO
    // this->main->sendToNotepad(text);
}

void DisassemblyWidget::on_xreFromTreeWidget_2_itemDoubleClicked(QTreeWidgetItem *item, int /*column*/)
{
    XrefDescription xref = item->data(0, Qt::UserRole).value<XrefDescription>();
    this->core->seek(xref.to);
}

void DisassemblyWidget::on_xrefToTreeWidget_2_itemDoubleClicked(QTreeWidgetItem *item, int /*column*/)
{
    XrefDescription xref = item->data(0, Qt::UserRole).value<XrefDescription>();
    this->core->seek(xref.from);
}

void DisassemblyWidget::on_xrefFromToolButton_2_clicked()
{
    if (ui->xrefFromToolButton_2->isChecked())
    {
        ui->xreFromTreeWidget_2->hide();
        ui->xrefFromToolButton_2->setArrowType(Qt::RightArrow);
    }
    else
    {
        ui->xreFromTreeWidget_2->show();
        ui->xrefFromToolButton_2->setArrowType(Qt::DownArrow);
    }
}

void DisassemblyWidget::on_xrefToToolButton_2_clicked()
{
    if (ui->xrefToToolButton_2->isChecked())
    {
        ui->xrefToTreeWidget_2->hide();
        ui->xrefToToolButton_2->setArrowType(Qt::RightArrow);
    }
    else
    {
        ui->xrefToTreeWidget_2->show();
        ui->xrefToToolButton_2->setArrowType(Qt::DownArrow);
    }
}

void DisassemblyWidget::get_refs_data(RVA addr)
{
    // refs = calls q hace esa funcion
    QList<XrefDescription> refs = core->getXRefs(addr, false, false);

    // xrefs = calls a esa funcion
    QList<XrefDescription> xrefs = core->getXRefs(addr, true, false);

    // Data for the disasm side graph
    QList<int> data;
    //qDebug() << "Refs:" << refs.size();
    data << refs.size();
    //qDebug() << "XRefs:" << xrefs.size();
    data << xrefs.size();
    //qDebug() << "CC: " << this->core->fcnCyclomaticComplexity(offset.toLong(&ok, 16));
    //data << this->core->fcnCyclomaticComplexity(offset.toLong(&ok, 16));
    data << this->core->getCycloComplex(addr);
    //qDebug() << "BB: " << this->core->fcnBasicBlockCount(offset.toLong(&ok, 16));
    data << this->core->fcnBasicBlockCount(addr);
    data << this->core->fcnEndBbs(addr);
    //qDebug() << "MEOW: " + this->core->fcnEndBbs(offset);

    // Update disasm side bar
    this->fill_refs(refs, xrefs, data);
}

void DisassemblyWidget::fill_refs(QList<XrefDescription> refs, QList<XrefDescription> xrefs, QList<int> graph_data)
{
    this->xreFromTreeWidget_2->clear();
    for (int i = 0; i < refs.size(); ++i)
    {
        XrefDescription xref = refs[i];
        QTreeWidgetItem *tempItem = new QTreeWidgetItem();
        tempItem->setText(0, RAddressString(xref.to));
        tempItem->setText(1, core->disassembleSingleInstruction(xref.from));
        tempItem->setData(0, Qt::UserRole, QVariant::fromValue(xref));
        QString tooltip = this->core->cmd("pdi 10 @ " + QString::number(xref.to)).trimmed();
        tempItem->setToolTip(0, tooltip);
        tempItem->setToolTip(1, tooltip);
        this->xreFromTreeWidget_2->insertTopLevelItem(0, tempItem);
    }
    // Adjust columns to content
    int count = this->xreFromTreeWidget_2->columnCount();
    for (int i = 0; i != count; ++i)
    {
        this->xreFromTreeWidget_2->resizeColumnToContents(i);
    }

    this->xrefToTreeWidget_2->clear();
    for (int i = 0; i < xrefs.size(); ++i)
    {
        XrefDescription xref = xrefs[i];

        QTreeWidgetItem *tempItem = new QTreeWidgetItem();
        tempItem->setText(0, RAddressString(xref.from));
        tempItem->setText(1, core->disassembleSingleInstruction(xref.from));
        tempItem->setData(0, Qt::UserRole, QVariant::fromValue(xref));
        QString tooltip = this->core->cmd("pdi 10 @ " + QString::number(xref.from)).trimmed();
        tempItem->setToolTip(0, this->core->cmd("pdi 10 @ " + tooltip).trimmed());
        tempItem->setToolTip(1, this->core->cmd("pdi 10 @ " + tooltip).trimmed());
        this->xrefToTreeWidget_2->insertTopLevelItem(0, tempItem);
    }
    // Adjust columns to content
    int count2 = this->xrefToTreeWidget_2->columnCount();
    for (int i = 0; i != count2; ++i)
    {
        this->xrefToTreeWidget_2->resizeColumnToContents(i);
    }

    // Add data to HTML Polar functions graph
    QFile html(":/html/fcn_graph.html");
    if (!html.open(QIODevice::ReadOnly))
    {
        QMessageBox::information(this, "error", html.errorString());
    }
    QString code = html.readAll();
    html.close();

    QString data = QString("\"%1\", \"%2\", \"%3\", \"%4\", \"%5\"").arg(graph_data.at(2)).arg(graph_data.at(0)).arg(graph_data.at(3)).arg(graph_data.at(1)).arg(graph_data.at(4));
    code.replace("MEOW", data);
    ui->fcnWebView->setHtml(code);

    // Add data to HTML Radar functions graph
    QFile html2(":/html/fcn_radar.html");
    if (!html2.open(QIODevice::ReadOnly))
    {
        QMessageBox::information(this, "error", html.errorString());
    }
    QString code2 = html2.readAll();
    html2.close();

    QString data2 = QString("%1, %2, %3, %4, %5").arg(graph_data.at(2)).arg(graph_data.at(0)).arg(graph_data.at(3)).arg(graph_data.at(1)).arg(graph_data.at(4));
    code2.replace("MEOW", data2);
    ui->radarGraphWebView->setHtml(code2);
}

void DisassemblyWidget::fillOffsetInfo(QString off)
{
    ui->offsetTreeWidget->clear();
    QString raw = this->core->getOffsetInfo(off);
    QList<QString> lines = raw.split("\n", QString::SkipEmptyParts);
    foreach (QString line, lines)
    {
        QList<QString> eles = line.split(":", QString::SkipEmptyParts);
        QTreeWidgetItem *tempItem = new QTreeWidgetItem();
        tempItem->setText(0, eles.at(0).toUpper());
        tempItem->setText(1, eles.at(1));
        ui->offsetTreeWidget->insertTopLevelItem(0, tempItem);
    }

    // Adjust column to contents
    int count = ui->offsetTreeWidget->columnCount();
    for (int i = 0; i != count; ++i)
    {
        ui->offsetTreeWidget->resizeColumnToContents(i);
    }

    // Add opcode description
    QStringList description = this->core->cmd("?d. @ " + off).split(": ");
    if (description.length() >= 2)
    {
        ui->opcodeDescText->setPlainText("# " + description[0] + ":\n" + description[1]);
    }
}

QString DisassemblyWidget::normalize_addr(QString addr)
{
    QString base = this->core->cmd("s").split("0x")[1].trimmed();
    int len = base.length();
    if (len < 8)
    {
        int padding = 8 - len;
        QString zero = "0";
        QString zeroes = zero.repeated(padding);
        QString s = "0x" + zeroes + base;
        return s;
    }
    else
    {
        return addr.trimmed();
    }
}

void DisassemblyWidget::setFcnName(RVA addr)
{
    RAnalFunction *fcn;
    QString addr_string;

    fcn = this->core->functionAt(addr);
    if (fcn)
    {
        QString segment = this->core->cmd("S. @ " + QString::number(addr)).split(" ").last();
        addr_string = segment.trimmed() + ":" + fcn->name;
    }
    else
    {
        addr_string = core->cmdFunctionAt(addr);
    }

    ui->fcnNameEdit->setText(addr_string);
}

void DisassemblyWidget::on_disasTextEdit_2_cursorPositionChanged()
{
    // Get current offset
    QTextCursor tc = this->disasTextEdit->textCursor();
    tc.select(QTextCursor::LineUnderCursor);
    QString lastline = tc.selectedText().trimmed();
    QList<QString> words = lastline.split(" ", QString::SkipEmptyParts);
    if (words.length() == 0)
    {
        return;
    }
    QString ele = words[0];
    if (ele.contains("0x"))
    {
        this->fillOffsetInfo(ele);
        QString at = this->core->cmdFunctionAt(ele);
        QString deco = this->core->getDecompiledCode(at);


        RVA addr = ele.midRef(2).toULongLong(0, 16);
        // FIXME per widget CursorAddress no?
        // this->main->setCursorAddress(addr);

        if (deco != "")
        {
            ui->decoTextEdit->setPlainText(deco);
        }
        else
        {
            ui->decoTextEdit->setPlainText("");
        }
        // Get jump information to fill the preview
        QString jump =  this->core->getOffsetJump(ele);
        if (!jump.isEmpty())
        {
            // Fill the preview
            QString jump_code = this->core->cmd("pdf @ " + jump);
            ui->previewTextEdit->setPlainText(jump_code.trimmed());
            ui->previewTextEdit->moveCursor(QTextCursor::End);
            ui->previewTextEdit->find(jump.trimmed(), QTextDocument::FindBackward);
            ui->previewTextEdit->moveCursor(QTextCursor::StartOfWord, QTextCursor::MoveAnchor);
        }
        else
        {
            ui->previewTextEdit->setPlainText("");
        }
        //this->main->add_debug_output("Fcn at: '" + at + "'");
        if (this->last_fcn != at)
        {
            this->last_fcn = at;
            //this->main->add_debug_output("New Fcn: '" + this->last_fcn + "'");
            // Refresh function information at sidebar
            ui->fcnNameEdit->setText(at);
            // FIXME TITLE?
            // this->main->memoryDock->setWindowTitle(at);
            //this->main->memoryDock->create_graph(ele);
            this->setMiniGraph(at);
        }
    }
}

QString DisassemblyWidget::normalizeAddr(QString addr)
{
    QString base = addr.split("0x")[1].trimmed();
    int len = base.length();
    if (len < 8)
    {
        int padding = 8 - len;
        QString zero = "0";
        QString zeroes = zero.repeated(padding);
        QString s = "0x" + zeroes + base;
        return s;
    }
    else
    {
        return addr;
    }
}

void DisassemblyWidget::setMiniGraph(QString at)
{
    QString dot = this->core->getSimpleGraph(at);
    //QString dot = this->core->cmd("agc " + at);
    // Add data to HTML Polar functions graph
    QFile html(":/html/graph.html");
    if (!html.open(QIODevice::ReadOnly))
    {
        QMessageBox::information(this, "error", html.errorString());
    }
    QString code = html.readAll();
    html.close();

    code.replace("MEOW", dot);
    ui->webSimpleGraph->setHtml(code);

}

void DisassemblyWidget::on_polarToolButton_clicked()
{
    ui->radarToolButton->setChecked(false);
    ui->fcnGraphTabWidget->setCurrentIndex(0);
}

void DisassemblyWidget::on_radarToolButton_clicked()
{
    ui->polarToolButton->setChecked(false);
    ui->fcnGraphTabWidget->setCurrentIndex(1);
}


void DisassemblyWidget::on_hexSideTab_2_currentChanged(int /*index*/)
{
    /*
    if (index == 2) {
        // Add data to HTML Polar functions graph
        QFile html(":/html/bar.html");
        if(!html.open(QIODevice::ReadOnly)) {
            QMessageBox::information(0,"error",html.errorString());
        }
        QString code = html.readAll();
        html.close();
        this->histoWebView->setHtml(code);
        this->histoWebView->show();
    } else {
        this->histoWebView->hide();
    }
    */
}

void DisassemblyWidget::on_memSideToolButton_clicked()
{
    if (ui->memSideToolButton->isChecked())
    {
        ui->sideWidget->hide();
        ui->memSideToolButton->setIcon(QIcon(":/img/icons/left_light.svg"));
    }
    else
    {
        ui->sideWidget->show();
        ui->memSideToolButton->setIcon(QIcon(":/img/icons/right_light.svg"));
    }
}

void DisassemblyWidget::on_previewToolButton_clicked()
{
    ui->memPreviewTab->setCurrentIndex(0);
}

void DisassemblyWidget::on_decoToolButton_clicked()
{
    ui->memPreviewTab->setCurrentIndex(1);
}

void DisassemblyWidget::on_simpleGrapgToolButton_clicked()
{
    ui->memPreviewTab->setCurrentIndex(2);
}

void DisassemblyWidget::on_previewToolButton_2_clicked()
{
    if (ui->previewToolButton_2->isChecked())
    {
        ui->frame_3->setVisible(true);
    }
    else
    {
        ui->frame_3->setVisible(false);
    }
}

void DisassemblyWidget::resizeEvent(QResizeEvent *event)
{
    // FIXME
    /*
    if (main->responsive && isVisible())
    {
        if (event->size().width() <= 1150)
        {
            ui->frame_3->setVisible(false);
            ui->memPreviewTab->setVisible(false);
            ui->previewToolButton_2->setChecked(false);
            if (event->size().width() <= 950)
            {
                ui->memSideTabWidget_2->hide();
                ui->hexSideTab_2->hide();
                ui->memSideToolButton->setChecked(true);
            }
            else
            {
                ui->memSideTabWidget_2->show();
                ui->hexSideTab_2->show();
                ui->memSideToolButton->setChecked(false);
            }
        }
        else
        {
            ui->frame_3->setVisible(true);
            ui->memPreviewTab->setVisible(true);
            ui->previewToolButton_2->setChecked(true);
        }
    }
    */
    QDockWidget::resizeEvent(event);
}

bool DisassemblyWidget::eventFilter(QObject *obj, QEvent *event)
{
    if ((obj == ui->disasTextEdit_2 || obj == ui->disasTextEdit_2->viewport()) && event->type() == QEvent::MouseButtonDblClick)
    {
        QMouseEvent *mouseEvent = static_cast<QMouseEvent *>(event);
        //qDebug()<<QString("Click location: (%1,%2)").arg(mouseEvent->x()).arg(mouseEvent->y());
        QTextCursor cursor = ui->disasTextEdit_2->cursorForPosition(QPoint(mouseEvent->x(), mouseEvent->y()));
        cursor.select(QTextCursor::LineUnderCursor);
        QString lastline = cursor.selectedText();
        auto eles = lastline.split(" ", QString::SkipEmptyParts);
        QString ele = eles.isEmpty() ? "" : eles[0];
        if (ele.contains("0x"))
        {
            QString jump = this->core->getOffsetJump(ele);
            if (!jump.isEmpty())
            {
                if (jump.contains("0x"))
                {
                    QString fcn = this->core->cmdFunctionAt(jump);
                    if (!fcn.isEmpty())
                    {
                        RVA addr = jump.trimmed().toULongLong(0, 16);
                        this->core->seek(addr);
                    }
                }
                else
                {
                    RVA addr = this->core->cmd("?v " + jump).toULongLong(0, 16);
                    this->core->seek(addr);
                }
            }
        }
    }
    return QDockWidget::eventFilter(obj, event);
}

void DisassemblyWidget::setScrollMode()
{
    qhelpers::setVerticalScrollMode(ui->xreFromTreeWidget_2);
    qhelpers::setVerticalScrollMode(ui->xrefToTreeWidget_2);
}

void DisassemblyWidget::switchTheme(bool dark)
{
    if (dark)
    {
        ui->webSimpleGraph->page()->setBackgroundColor(QColor(64, 64, 64));
    }
    else
    {
        ui->webSimpleGraph->page()->setBackgroundColor(QColor(255, 255, 255));
    }
}

void DisassemblyWidget::seek_back()
{
    //this->main->add_debug_output("Back!");
    // FIXME
    // this->main->backButton_clicked();
}

void DisassemblyWidget::on_memTabWidget_currentChanged(int /*index*/)
{
    /*this->main->add_debug_output("Update index: " + QString::number(index) + " to function: " + RAddressString(main->getCursorAddress()));
    this->main->add_debug_output("Last disasm: " + RAddressString(this->last_disasm_fcn));
    this->main->add_debug_output("Last graph: " + RAddressString(this->last_graph_fcn));
    this->main->add_debug_output("Last hexdump: " + RAddressString(this->last_hexdump_fcn));*/
    this->updateViews(RVA_INVALID);
}

void DisassemblyWidget::updateViews(RVA offset)
{
    this->refreshDisasm();
}