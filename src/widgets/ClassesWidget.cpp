#include "ClassesWidget.h"
#include "ui_ClassesWidget.h"
#include "MainWindow.h"
#include "utils/Helpers.h"

ClassesModel::ClassesModel(QList<ExportDescription> *exports, QObject *parent)
    : QAbstractListModel(parent),
      exports(exports)
{
}

int ClassesModel::rowCount(const QModelIndex &) const
{
    return exports->count();
}

int ClassesModel::columnCount(const QModelIndex &) const
{
    return Columns::COUNT;
}

QVariant ClassesModel::data(const QModelIndex &index, int role) const
{
    if (index.row() >= exports->count())
        return QVariant();

    const ExportDescription &exp = exports->at(index.row());

    switch (role)
    {
    case Qt::DisplayRole:
        switch (index.column())
        {
        case OFFSET:
            return RAddressString(exp.vaddr);
        case SIZE:
            return RSizeString(exp.size);
        case TYPE:
            return exp.type;
        case NAME:
            return exp.name;
        default:
            return QVariant();
        }
    case ExportDescriptionRole:
        return QVariant::fromValue(exp);
    default:
        return QVariant();
    }
}

QVariant ClassesModel::headerData(int section, Qt::Orientation, int role) const
{
    switch (role)
    {
    case Qt::DisplayRole:
        switch (section)
        {
        case OFFSET:
            return tr("Address");
        case SIZE:
            return tr("Size");
        case TYPE:
            return tr("Type");
        case NAME:
            return tr("Name");
        default:
            return QVariant();
        }
    default:
        return QVariant();
    }
}

void ClassesModel::beginReloadExports()
{
    beginResetModel();
}

void ClassesModel::endReloadExports()
{
    endResetModel();
}





ClassesSortFilterProxyModel::ClassesSortFilterProxyModel(ClassesModel *source_model, QObject *parent)
    : QSortFilterProxyModel(parent)
{
    setSourceModel(source_model);
}

bool ClassesSortFilterProxyModel::filterAcceptsRow(int row, const QModelIndex &parent) const
{
    QModelIndex index = sourceModel()->index(row, 0, parent);
    ExportDescription exp = index.data(ClassesModel::ExportDescriptionRole).value<ExportDescription>();
    return exp.name.contains(filterRegExp());
}

bool ClassesSortFilterProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    ExportDescription left_exp = left.data(ClassesModel::ExportDescriptionRole).value<ExportDescription>();
    ExportDescription right_exp = right.data(ClassesModel::ExportDescriptionRole).value<ExportDescription>();

    switch (left.column())
    {
    case ClassesModel::SIZE:
        if (left_exp.size != right_exp.size)
            return left_exp.size < right_exp.size;
    // fallthrough
    case ClassesModel::OFFSET:
        if (left_exp.vaddr != right_exp.vaddr)
            return left_exp.vaddr < right_exp.vaddr;
    // fallthrough
    case ClassesModel::NAME:
        return left_exp.name < right_exp.name;
    case ClassesModel::TYPE:
        if (left_exp.type != right_exp.type)
            return left_exp.type < right_exp.type;
    default:
        break;
    }

    // fallback
    return left_exp.vaddr < right_exp.vaddr;
}



ClassesWidget::ClassesWidget(MainWindow *main, QWidget *parent) :
    QDockWidget(parent),
    ui(new Ui::ClassesWidget),
    main(main)
{
    ui->setupUi(this);

    // Radare core found in:
    this->main = main;

    model = new ClassesModel(&exports, this);
    proxy_model = new ClassesSortFilterProxyModel(model, this);
    ui->classesTreeView->setModel(proxy_model);
    ui->classesTreeView->sortByColumn(ClassesModel::OFFSET, Qt::AscendingOrder);

    connect(Core(), SIGNAL(refreshAll()), this, SLOT(refreshExports()));
}

ClassesWidget::~ClassesWidget() {}

void ClassesWidget::refreshExports()
{
    model->beginReloadExports();
    exports = CutterCore::getInstance()->getAllExports();
    model->endReloadExports();

    ui->classesTreeView->resizeColumnToContents(0);
    ui->classesTreeView->resizeColumnToContents(1);
    ui->classesTreeView->resizeColumnToContents(2);
}

void ClassesWidget::on_exportsTreeView_doubleClicked(const QModelIndex &index)
{
    ExportDescription exp = index.data(ClassesModel::ExportDescriptionRole).value<ExportDescription>();
    CutterCore::getInstance()->seek(exp.vaddr);
}
