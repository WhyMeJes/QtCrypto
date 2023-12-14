#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:

    void on_pushButton_generateRSA_clicked();

    void on_pushButton_RSA_encrypt_clicked();

    void on_pushButton_RSA_decrypt_clicked();

    void on_pushButton_toLineEdit_clicked();

    void on_pushButton_saveToFile_clicked();

    void on_pushButton_generateAES_clicked();

    void on_pushButton_AES_encrypt_clicked();

    void on_pushButton_AES_decrypt_clicked();

private:
    void error(QString errorMessage);
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
