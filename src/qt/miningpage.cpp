#include <qt/miningpage.h>
#include <qt/forms/ui_miningpage.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/platformstyle.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactiontablemodel.h>
#include <qt/walletmodel.h>
#include <interfaces/wallet.h>
#include <qt/transactiondescdialog.h>
#include <qt/transactionview.h>
#include <qt/styleSheet.h>
#include <qt/bitcoinunits.h>
#include <qt/execrpccommand.h>

#include <util/check.h>
#include <validation.h>
#include <miner.h>
#include <pow.h>

#include <QSortFilterProxyModel>
#include <QString>
#include <QTimer>

Q_DECLARE_METATYPE(interfaces::WalletBalances)

#include <qt/miningpage.moc>

MiningPage::MiningPage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MiningPage),
    platformStyle(_platformStyle),
    clientModel(nullptr),
    walletModel(nullptr),
    miningState(false),
    transactionView(0),
    cmdStart(nullptr)
{
    ui->setupUi(this);
    transactionView = new TransactionView(platformStyle, this, true);
    ui->frameMiningRecords->layout()->addWidget(transactionView);

    ui->threadSlider->setMinimum(1);
    ui->threadSlider->setMaximum(std::thread::hardware_concurrency() / 2);
    ui->threadSlider->setTickPosition(QSlider::TicksBothSides);
    ui->threadSlider->setTickInterval(1);
    ui->threadSlider->setSingleStep(1);

    ui->labelMinThreads->setText(QString::number(1));
    ui->labelMaxThreads->setText(QString::number(std::thread::hardware_concurrency() / 2));

    ui->advancedWarning->hide();

    updateMiningStatsTimer = new QTimer(this);
    updateNethashTimer = new QTimer(this);

    connect(ui->threadSlider, &QSlider::valueChanged, this, &MiningPage::updateThreads);

    updateNethashTimer->start(1000);

    // Misc
    ui->miningButton->setText("Start mining");

    static const QString PRC_COMMAND_START = "minerstart";
    static const QString PRC_COMMAND_STOP = "minerstop";
    QString PARAM_THREADS = "threads";

    QStringList lstMandatory = QStringList() << PARAM_THREADS;

    cmdStart = new ExecRPCCommand(PRC_COMMAND_START, lstMandatory, QStringList(), QMap<QString, QString>(), this);
    cmdStop = new ExecRPCCommand(PRC_COMMAND_STOP, QStringList(), QStringList(), QMap<QString, QString>(), this);
}

MiningPage::~MiningPage()
{
    delete ui;
}

void MiningPage::on_checkEnableAdvanced_clicked(bool checked)
{
    int threads = std::thread::hardware_concurrency();

    if (!checked) {
        ui->threadSlider->setMaximum(threads / 2);
        ui->labelMaxThreads->setText(QString::number(threads / 2));
        ui->advancedWarning->hide();
    } else {
        ui->threadSlider->setMaximum(threads);
        ui->labelMaxThreads->setText(QString::number(threads));
        ui->advancedWarning->show();
    }
}

void MiningPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
}

void MiningPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        transactionView->setModel(model);
        transactionView->chooseType(6);
    }
}

void MiningPage::manageMiningState(bool state, int nThreads)
{
    QMap<QString, QString> lstParams;
    QVariant result;
    QString errorMessage;
    QString resultJson;

    QString PARAM_THREADS = "threads";

    if (!walletModel)
        return;

    if (state != miningState)
        miningState = state;

    if (!miningState) {
        if (cmdStop->exec(this->walletModel->node(), this->walletModel, lstParams, result, resultJson, errorMessage)) {
            updateMiningStatsTimer->stop();
            ui->miningButton->setText("Start mining");
        }
    } else {
        ExecRPCCommand::appendParam(lstParams, PARAM_THREADS, QString::number(nThreads));

        if (cmdStart->exec(this->walletModel->node(), this->walletModel, lstParams, result, resultJson, errorMessage)) {
            // Update stats every 5s
            updateMiningStatsTimer->start(1000);
            ui->miningButton->setText("Stop mining");
        }
    }
}

void MiningPage::on_miningButton_clicked()
{
    if (!miningState) {
        int nThreads = ui->threadSlider->value();
        MiningPage::manageMiningState(true, nThreads);
    } else {
        MiningPage::manageMiningState(false, 0);
    }
}

void MiningPage::updateThreads(int value)
{
    manageMiningState(miningState, value);
}
