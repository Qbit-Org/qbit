// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QBIT_QT_TEST_UTIL_H
#define QBIT_QT_TEST_UTIL_H

#include <util/fs.h>

#include <chrono>
#include <functional>
#include <list>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <qglobal.h>

QT_BEGIN_NAMESPACE
class QString;
QT_END_NAMESPACE

/**
 * Press "Ok" button in message box dialog.
 *
 * @param text - Optionally store dialog text.
 * @param msec - Number of milliseconds to pause before triggering the callback.
 */
void ConfirmMessage(QString* text, std::chrono::milliseconds msec);

//! Contents of the unshown-psbt-*.psbt files that PSBT dialogs saved to the
//! data directory, by path.
std::map<fs::path, std::string> UnshownPSBTFiles();
//! The UnshownPSBTFiles() that are not in before.
std::map<fs::path, std::string> NewUnshownPSBTFiles(const std::map<fs::path, std::string>& before);

/** Collect the debug log lines written, from any thread, while in scope. */
class LogCapture
{
public:
    LogCapture();
    ~LogCapture();
    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    //! The first captured line that contains every given text, or empty.
    std::string find(const std::vector<std::string>& texts) const;

private:
    mutable std::mutex m_mutex;
    std::vector<std::string> m_lines;
    std::list<std::function<void(const std::string&)>>::iterator m_callback;
};

#endif // QBIT_QT_TEST_UTIL_H
