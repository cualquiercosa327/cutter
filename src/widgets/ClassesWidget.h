#ifndef CLASSWSWIDGET_H
#define CLASSWSWIDGET_H

#include <memory>

#include "cutter.h"

#include <QAbstractListModel>
#include <QSortFilterProxyModel>
#include <QDockWidget>

class MainWindow;
class QTreeWidget;

namespace Ui
{
    class ClassesWidget;
}


class MainWindow;
class QTreeWidgetItem;


class ClassesModel: public QAbstractListModel
{
    Q_OBJECT

private:
    QList<ExportDescription> *exports;

public:
    enum Columns { OFFSET = 0, SIZE, TYPE, NAME, COUNT };
    static const int ExportDescriptionRole = Qt::UserRole;

    ClassesModel(QList<ExportDescription> *exports, QObject *parent = 0);

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

    void beginReloadExports();
    void endReloadExports();
};



class ClassesSortFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    ClassesSortFilterProxyModel(ClassesModel *source_model, QObject *parent = 0);

protected:
    bool filterAcceptsRow(int row, const QModelIndex &parent) const override;
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override;
};



class ClassesWidget : public QDockWidget
{
    Q_OBJECT

public:
    explicit ClassesWidget(MainWindow *main, QWidget *parent = 0);
    ~ClassesWidget();

private slots:
    void on_exportsTreeView_doubleClicked(const QModelIndex &index);

    void refreshExports();

private:
    std::unique_ptr<Ui::ClassesWidget> ui;
    MainWindow      *main;

    ClassesModel *model;
    ClassesSortFilterProxyModel *proxy_model;
    QList<ExportDescription> exports;
};


#endif // CLASSWSWIDGET_H
