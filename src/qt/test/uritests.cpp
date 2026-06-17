// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/uritests.h>

#include <chainparams.h>
#include <qt/guiutil.h>
#include <qt/sendcoinsrecipient.h>

#include <QUrl>

namespace {
void RunParseTestsForScheme(const QString& scheme)
{
    SendCoinsRecipient rv;
    QUrl uri;
    const QString uri_base = QString("%1:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W").arg(scheme);

    uri.setUrl(uri_base + "?req-dontexist=");
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(uri_base + "?dontexist=");
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(uri_base + "?label=Wikipedia Example Address");
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(uri_base + "?amount=0.001");
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(uri_base + "?amount=1.001");
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(uri_base + "?amount=100&label=Wikipedia Example");
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(uri_base + "?message=Wikipedia Example Address");
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI(uri_base + "?message=Wikipedia Example Address", &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    uri.setUrl(uri_base + "?req-message=Wikipedia Example Address");
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    // Commas in amounts are not allowed.
    uri.setUrl(uri_base + "?amount=1,000&label=Wikipedia Example");
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(uri_base + "?amount=1,000.0&label=Wikipedia Example");
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // There are two amount specifications. The last value wins.
    uri.setUrl(uri_base + "?amount=100&amount=200&label=Wikipedia Example");
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 20000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    // The first amount value is correct. However, the second amount value is not valid. Hence, the URI is not valid.
    uri.setUrl(uri_base + "?amount=100&amount=1,000&label=Wikipedia Example");
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // Test label containing a question mark ('?').
    uri.setUrl(uri_base + "?amount=100&label=?");
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("?"));

    // Escape sequences are not supported.
    uri.setUrl(uri_base + "?amount=100&label=%3F");
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("%3F"));
}
} // namespace

void URITests::uriTests()
{
    RunParseTestsForScheme("qbit");

    SendCoinsRecipient rv;
    QUrl uri;

    // Negative tests.
    uri.setUrl(QString("litecoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("bitcoin://175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    QVERIFY(!GUIUtil::parseBitcoinURI(QString("qbit://175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"), &rv));

    uri.setUrl(QString("QBIT:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    // Formatter tests.
    SendCoinsRecipient recipient;
    recipient.address = QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W");
    QVERIFY(GUIUtil::formatBitcoinURI(recipient).startsWith("qbit:"));

    SendCoinsRecipient bech32_recipient;
    bech32_recipient.address = QString::fromStdString(Params().Bech32HRP() + "1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq");
    QVERIFY(GUIUtil::formatBitcoinURI(bech32_recipient).startsWith("qbit:"));

    SendCoinsRecipient qb_bech32_recipient;
    qb_bech32_recipient.address = QString("qb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq");
    QVERIFY(GUIUtil::formatBitcoinURI(qb_bech32_recipient).startsWith("qbit:"));
}
