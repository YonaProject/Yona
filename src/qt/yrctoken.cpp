#include <qt/yrctoken.h>
#include <qt/forms/ui_yrctoken.h>
#include <qt/tokenitemmodel.h>
#include <qt/walletmodel.h>
#include <qt/tokentransactionview.h>
#include <qt/platformstyle.h>
#include <qt/styleSheet.h>
#include <qt/tokenlistwidget.h>

#include <QPainter>
#include <QAbstractItemDelegate>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QSortFilterProxyModel>
#include <QSizePolicy>
#include <QMenu>

YRCToken::YRCToken(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::YRCToken),
    m_model(0),
    m_clientModel(0),
    m_tokenTransactionView(0)
{
    ui->setupUi(this);

    m_platformStyle = platformStyle;

    m_sendTokenPage = new SendTokenPage(this);
    m_receiveTokenPage = new ReceiveTokenPage(platformStyle, this);
    m_addTokenPage = new AddTokenPage(this);

    m_sendTokenPage->setEnabled(false);
    m_receiveTokenPage->setEnabled(false);

    m_tokenTransactionView = new TokenTransactionView(m_platformStyle, this);
    m_tokenTransactionView->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->tokenViewLayout->addWidget(m_tokenTransactionView);

    QAction *copySenderAction = new QAction(tr("Copy receive address"), this);
    QAction *copyTokenBalanceAction = new QAction(tr("Copy token balance"), this);
    QAction *copyTokenNameAction = new QAction(tr("Copy token name"), this);
    QAction *copyTokenAddressAction = new QAction(tr("Copy contract address"), this);
    QAction *removeTokenAction = new QAction(tr("Remove token"), this);

    m_tokenList = new TokenListWidget(platformStyle, this);
    m_tokenList->setContextMenuPolicy(Qt::CustomContextMenu);
    new QVBoxLayout(ui->scrollArea);
    ui->scrollArea->setWidget(m_tokenList);
    ui->scrollArea->setWidgetResizable(true);
    connect(m_tokenList, &TokenListWidget::sendToken, this, &YRCToken::on_sendToken);
    connect(m_tokenList, &TokenListWidget::receiveToken, this, &YRCToken::on_receiveToken);
    connect(m_tokenList, &TokenListWidget::addToken, this, &YRCToken::on_addToken);

    contextMenu = new QMenu(m_tokenList);
    contextMenu->addAction(copySenderAction);
    contextMenu->addAction(copyTokenBalanceAction);
    contextMenu->addAction(copyTokenNameAction);
    contextMenu->addAction(copyTokenAddressAction);
    contextMenu->addAction(removeTokenAction);

    connect(copyTokenAddressAction, &QAction::triggered, this, &YRCToken::copyTokenAddress);
    connect(copyTokenBalanceAction, &QAction::triggered, this, &YRCToken::copyTokenBalance);
    connect(copyTokenNameAction, &QAction::triggered, this, &YRCToken::copyTokenName);
    connect(copySenderAction, &QAction::triggered, this, &YRCToken::copySenderAddress);
    connect(removeTokenAction, &QAction::triggered, this, &YRCToken::removeToken);

    connect(m_tokenList, &TokenListWidget::customContextMenuRequested, this, &YRCToken::contextualMenu);

    connect(m_sendTokenPage, &SendTokenPage::message, this, &YRCToken::message);
}

YRCToken::~YRCToken()
{
    delete ui;
}

void YRCToken::setModel(WalletModel *_model)
{
    m_model = _model;
    m_addTokenPage->setModel(m_model);
    m_sendTokenPage->setModel(m_model);
    m_tokenList->setModel(m_model);
    m_tokenTransactionView->setModel(_model);
    if(m_model && m_model->getTokenItemModel())
    {
        // Set current token
        connect(m_tokenList->tokenModel(), &QAbstractItemModel::dataChanged, this, &YRCToken::on_dataChanged);
        connect(m_tokenList->tokenModel(), &QAbstractItemModel::rowsInserted, this, &YRCToken::on_rowsInserted);
        if(m_tokenList->tokenModel()->rowCount() > 0)
        {
            QModelIndex currentToken(m_tokenList->tokenModel()->index(0, 0));
            on_currentTokenChanged(currentToken);
        }
    }
}

void YRCToken::setClientModel(ClientModel *_clientModel)
{
    m_clientModel = _clientModel;
    m_sendTokenPage->setClientModel(_clientModel);
    m_addTokenPage->setClientModel(_clientModel);
}

void YRCToken::on_goToSendTokenPage()
{
    m_sendTokenPage->show();
}

void YRCToken::on_goToReceiveTokenPage()
{
    m_receiveTokenPage->show();
}

void YRCToken::on_goToAddTokenPage()
{
    m_addTokenPage->show();
}

void YRCToken::on_currentTokenChanged(QModelIndex index)
{
    if(m_tokenList->tokenModel())
    {
        if(index.isValid())
        {
            m_selectedTokenHash = m_tokenList->tokenModel()->data(index, TokenItemModel::HashRole).toString();
            std::string address = m_tokenList->tokenModel()->data(index, TokenItemModel::AddressRole).toString().toStdString();
            std::string symbol = m_tokenList->tokenModel()->data(index, TokenItemModel::SymbolRole).toString().toStdString();
            std::string sender = m_tokenList->tokenModel()->data(index, TokenItemModel::SenderRole).toString().toStdString();
            int8_t decimals = m_tokenList->tokenModel()->data(index, TokenItemModel::DecimalsRole).toInt();
            std::string balance = m_tokenList->tokenModel()->data(index, TokenItemModel::RawBalanceRole).toString().toStdString();
            m_sendTokenPage->setTokenData(address, sender, symbol, decimals, balance);
            m_receiveTokenPage->setAddress(QString::fromStdString(sender));
            m_receiveTokenPage->setSymbol(QString::fromStdString(symbol));

            if(!m_sendTokenPage->isEnabled())
                m_sendTokenPage->setEnabled(true);
            if(!m_receiveTokenPage->isEnabled())
                m_receiveTokenPage->setEnabled(true);
        }
        else
        {
            m_sendTokenPage->setEnabled(false);
            m_receiveTokenPage->setEnabled(false);
            m_receiveTokenPage->setAddress(QString::fromStdString(""));
            m_receiveTokenPage->setSymbol(QString::fromStdString(""));
        }
    }
}

void YRCToken::on_dataChanged(const QModelIndex &topLeft, const QModelIndex &bottomRight, const QVector<int> &roles)
{
    Q_UNUSED(bottomRight);
    Q_UNUSED(roles);

    if(m_tokenList->tokenModel())
    {
        QString tokenHash = m_tokenList->tokenModel()->data(topLeft, TokenItemModel::HashRole).toString();
        if(m_selectedTokenHash.isEmpty() ||
                tokenHash == m_selectedTokenHash)
        {
            on_currentTokenChanged(topLeft);
        }
    }
}

void YRCToken::on_currentChanged(QModelIndex current, QModelIndex previous)
{
    Q_UNUSED(previous);

    on_currentTokenChanged(current);
}

void YRCToken::on_rowsInserted(QModelIndex index, int first, int last)
{
    Q_UNUSED(index);
    Q_UNUSED(first);
    Q_UNUSED(last);

    if(m_tokenList->tokenModel()->rowCount() == 1)
    {
        QModelIndex currentToken(m_tokenList->tokenModel()->index(0, 0));
        on_currentTokenChanged(currentToken);
    }
}

void YRCToken::contextualMenu(const QPoint &point)
{
    QModelIndex index = m_tokenList->indexAt(point);
    if(index.isValid())
    {
        indexMenu = index;
        contextMenu->exec(QCursor::pos());
    }
}

void YRCToken::copyTokenAddress()
{
    if(indexMenu.isValid())
    {
        GUIUtil::setClipboard(indexMenu.data(TokenItemModel::AddressRole).toString());
        indexMenu = QModelIndex();
    }
}

void YRCToken::copyTokenBalance()
{
    if(indexMenu.isValid())
    {
        GUIUtil::setClipboard(indexMenu.data(TokenItemModel::BalanceRole).toString());
        indexMenu = QModelIndex();
    }
}

void YRCToken::copyTokenName()
{
    if(indexMenu.isValid())
    {
        GUIUtil::setClipboard(indexMenu.data(TokenItemModel::NameRole).toString());
        indexMenu = QModelIndex();
    }
}

void YRCToken::copySenderAddress()
{
    if(indexMenu.isValid())
    {
        GUIUtil::setClipboard(indexMenu.data(TokenItemModel::SenderRole).toString());
        indexMenu = QModelIndex();
    }
}

void YRCToken::removeToken()
{
    QMessageBox::StandardButton btnRetVal = QMessageBox::question(this, tr("Confirm token remove"), tr("The selected token will be removed from the list. Are you sure?"),
        QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);

    if(btnRetVal == QMessageBox::Yes)
    {
        QModelIndex index = indexMenu;
        std::string sHash = index.data(TokenItemModel::HashRole).toString().toStdString();
        m_model->wallet().removeTokenEntry(sHash);
        indexMenu = QModelIndex();
    }
}

void YRCToken::on_sendToken(const QModelIndex &index)
{
    on_currentTokenChanged(index);
    on_goToSendTokenPage();
}

void YRCToken::on_receiveToken(const QModelIndex &index)
{
    on_currentTokenChanged(index);
    on_goToReceiveTokenPage();
}

void YRCToken::on_addToken()
{
    on_goToAddTokenPage();
}
