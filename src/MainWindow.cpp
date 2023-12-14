#include "MainWindow.h"
#include <ui_MainWindow.h>
#include <iostream>
#include <QtCrypto>
#include <QDebug>
#include <QFile>
#include <QMessageBox>
#include <QFileDialog>
#include <QFileInfo>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::error(QString errorMessage)
{
    qDebug() << errorMessage;
    ui->textBrowser_tech->setText(errorMessage);
    QMessageBox messageBox;
    messageBox.critical(0,"Ошибка",errorMessage);
    messageBox.setFixedSize(500,200);
}

void MainWindow::on_pushButton_generateRSA_clicked()
{
    QCA::Initializer init;
    QCA::PrivateKey seckey = QCA::KeyGenerator().createRSA(1024);
    QCA::PublicKey pubkey = seckey.toPublicKey();

    QString privateFileName = QFileDialog::getSaveFileName(this, tr("Сохранение закрытого ключа"),"keyprivate.pem",tr("*.pem"));
    seckey.toPEMFile(privateFileName);
    if(!QFile::exists(privateFileName)) error("Закрытый ключ не был создан!");

    QString publicFileName = QFileDialog::getSaveFileName(this, tr("Сохранение открытого ключа"),"keypublic.pem",tr("*.pem"));
    pubkey.toPEMFile(publicFileName);
    if(!QFile::exists(publicFileName)) error("Открытый ключ не был создан!");

    if (QFile::exists(publicFileName) && QFile::exists(privateFileName)) ui->textBrowser_result->setText("Ключи успешно созданы!");
    else ui->textBrowser_result->setText("Ключи не были созданы!");
}

void MainWindow::on_pushButton_RSA_encrypt_clicked()
{
    QCA::Initializer init;
    QString input = ui->plainTextEdit->toPlainText();
    QCA::SecureArray arg = input.toUtf8();

    QString publicFileName = QFileDialog::getOpenFileName(this, tr("Открытие открытого ключа"),"keypublic.pem",tr("*.pem"));
    QCA::PublicKey pubkey = QCA::PublicKey::fromPEMFile(publicFileName);
    if(pubkey.isNull()) error("Открытый ключ не найден!");

    else
    {
    QCA::SecureArray result = pubkey.encrypt(arg, QCA::EME_PKCS1_OAEP);
    QString rstr = QCA::arrayToHex(result.toByteArray());
    ui->textBrowser_result->setText(rstr);
    }
}

void MainWindow::on_pushButton_RSA_decrypt_clicked()
{
    QCA::Initializer init;
    QString input = ui->plainTextEdit->toPlainText();
    QCA::SecureArray arg = QCA::hexToArray(input);

    QString privateFileName = QFileDialog::getOpenFileName(this, tr("Открытие закрытого ключа"),"keyprivate.pem",tr("*.pem"));
    QCA::PrivateKey privateKey = QCA::PrivateKey::fromPEMFile(privateFileName);

    if (privateKey.isNull()) error("Закрытый ключ не найден!");
    else
    {
    QCA::SecureArray decrypt;
    if (0 == privateKey.decrypt(arg, &decrypt, QCA::EME_PKCS1_OAEP)) error("Текст не был дешифрован!");
    ui->textBrowser_result->setText(decrypt.data());
    }
}

void MainWindow::on_pushButton_toLineEdit_clicked()
{
    ui->plainTextEdit->setPlainText(ui->textBrowser_result->toPlainText());
}

void MainWindow::on_pushButton_saveToFile_clicked()
{
    QString saveFileName = QFileDialog::getSaveFileName(this,tr("Сохранение шифра"),"saveCipher.txt",tr("*.txt"));
    QFile file(saveFileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        stream << ui->textBrowser_result->toPlainText();
        file.close();
        ui->textBrowser_result->setText("Шифр был записан в файл!");
    } else error("Шифр не был записан в файл!");
}

void MainWindow::on_pushButton_generateAES_clicked()
{
    QCA::Initializer init;
    QCA::SymmetricKey key(16);
    QCA::InitializationVector iv(16);

    QString keyFileName = QFileDialog::getSaveFileName(this,tr("Создание файла с симметричным ключом"),"keyAES.txt",tr("*.txt"));
    QFile keyFile(keyFileName);
    if (!keyFile.open(QIODevice::WriteOnly)) {
        error("Файл с ключом не был создан!");
        return;
    } else keyFile.write(key.toByteArray());

    QString ivFileName = QFileDialog::getSaveFileName(this,tr("Открытие файла с вектором инициализации"),"ivAES.txt",tr("*.txt"));
    QFile ivFile(ivFileName);
    if (!ivFile.open(QIODevice::WriteOnly)) {
        error("Файл с вектором инициализации не был создан!");
        return;
    } else ivFile.write(iv.toByteArray());
}

void MainWindow::on_pushButton_AES_encrypt_clicked()
{
    QCA::Initializer init;
    QString text = ui->plainTextEdit->toPlainText();
    QByteArray byteArray = text.toUtf8();
    QCA::SecureArray data(byteArray);

    QString keyFileName = QFileDialog::getOpenFileName(this, tr("Открытие симметричного ключа"),"keyAES.txt",tr("*.txt"));
    QFile keyFile(keyFileName);
    if (!keyFile.open(QIODevice::ReadOnly)) {
        error("Симметричный ключ не был открыт!");
        return;
    }
    QByteArray keyData = keyFile.readAll();
    QCA::SymmetricKey key(keyData);

    QString ivFileName = QFileDialog::getOpenFileName(this, tr("Открытие вектора инициализации"),"ivAES.txt",tr("*.txt"));
    QFile ivFile(ivFileName);
    if (!ivFile.open(QIODevice::ReadOnly)) {
        error("Вектор инициализации не был открыт!");
        return;
    }
    QByteArray ivData = ivFile.readAll();
    QCA::InitializationVector iv(ivData);

    QCA::Cipher cipher(QStringLiteral("aes128"),QCA::Cipher::CBC,QCA::Cipher::DefaultPadding,QCA::Encode,key,iv);
    QCA::SecureArray u = cipher.update(data);
    QCA::SecureArray f = cipher.final();
    QString encryptedText = QCA::arrayToHex(u.append(f).toByteArray());
    ui->textBrowser_result->setPlainText(encryptedText);
}

void MainWindow::on_pushButton_AES_decrypt_clicked()
{
    QCA::Initializer init;
    QString text = ui->plainTextEdit->toPlainText();
    QByteArray byteArray = QByteArray::fromHex(text.toUtf8());
    QCA::SecureArray cipherText(byteArray);

    QString keyFileName = QFileDialog::getOpenFileName(this, tr("Открытие симметричного ключа"),"keyAES.txt",tr("*.txt"));
    QFile keyFile(keyFileName);
    if (!keyFile.open(QIODevice::ReadOnly)) {
        error("Симметричный ключ не был открыт!");
        return;
    }
    QByteArray keyData = keyFile.readAll();
    QCA::SymmetricKey key(keyData);

    QString ivFileName = QFileDialog::getOpenFileName(this, tr("Открытие вектора инициализации"),"ivAES.txt",tr("*.txt"));
    QFile ivFile(ivFileName);
    if (!ivFile.open(QIODevice::ReadOnly)) {
        error("Вектор инициализации не был открыт!");
        return;
    }
    QByteArray ivData = ivFile.readAll();
    QCA::InitializationVector iv(ivData);

    QCA::Cipher cipher(QStringLiteral("aes128"),QCA::Cipher::CBC, QCA::Cipher::DefaultPadding,QCA::Decode,key,iv);
    cipher.setup(QCA::Decode, key, iv);
    QCA::SecureArray u = cipher.update(cipherText);
    QCA::SecureArray f = cipher.final();
    QCA::SecureArray plainText = u.append(f);

    QString decryptedText = QString::fromUtf8(plainText.toByteArray());
    ui->textBrowser_result->setPlainText(decryptedText);
}
