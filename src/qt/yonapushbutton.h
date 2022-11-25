#ifndef YONAPUSHBUTTON_H
#define YONAPUSHBUTTON_H
#include <QPushButton>
#include <QStyleOptionButton>
#include <QIcon>

class YonaPushButton : public QPushButton
{
public:
    explicit YonaPushButton(QWidget * parent = Q_NULLPTR);
    explicit YonaPushButton(const QString &text, QWidget *parent = Q_NULLPTR);

protected:
    void paintEvent(QPaintEvent *) Q_DECL_OVERRIDE;

private:
    void updateIcon(QStyleOptionButton &pushbutton);

private:
    bool m_iconCached;
    QIcon m_downIcon;
};

#endif // YONAPUSHBUTTON_H
