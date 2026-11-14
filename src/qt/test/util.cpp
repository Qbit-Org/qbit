// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/util.h>

#include <common/args.h>
#include <logging.h>

#include <chrono>
#include <fstream>
#include <iterator>

#include <QApplication>
#include <QMessageBox>
#include <QPushButton>
#include <QString>
#include <QTimer>
#include <QWidget>

void ConfirmMessage(QString* text, std::chrono::milliseconds msec)
{
    QTimer::singleShot(msec, [text]() {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("QMessageBox")) {
                QMessageBox* messageBox = qobject_cast<QMessageBox*>(widget);
                if (text) *text = messageBox->text();
                messageBox->defaultButton()->click();
            }
        }
    });
}

std::map<fs::path, std::string> UnshownPSBTFiles()
{
    std::map<fs::path, std::string> files;
    for (const auto& entry : fs::directory_iterator{gArgs.GetDataDirNet()}) {
        const std::string name{fs::PathToString(entry.path().filename())};
        if (!entry.is_regular_file() || !name.starts_with("unshown-psbt-") || !name.ends_with(".psbt")) continue;
        std::ifstream in{entry.path(), std::ifstream::in | std::ifstream::binary};
        files.emplace(entry.path(), std::string{std::istreambuf_iterator<char>{in}, {}});
    }
    return files;
}

std::map<fs::path, std::string> NewUnshownPSBTFiles(const std::map<fs::path, std::string>& before)
{
    std::map<fs::path, std::string> files{UnshownPSBTFiles()};
    std::erase_if(files, [&](const auto& file) { return before.contains(file.first); });
    return files;
}

LogCapture::LogCapture()
    : m_callback{LogInstance().PushBackCallback([this](const std::string& line) {
          std::lock_guard lock{m_mutex};
          m_lines.push_back(line);
      })}
{
}

LogCapture::~LogCapture()
{
    LogInstance().DeleteCallback(m_callback);
}

std::string LogCapture::find(const std::vector<std::string>& texts) const
{
    std::lock_guard lock{m_mutex};
    for (const std::string& line : m_lines) {
        bool all{true};
        for (const std::string& text : texts) all = all && line.find(text) != std::string::npos;
        if (all) return line;
    }
    return {};
}
