// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITPLUS_QT_BITPLUSADDRESSVALIDATOR_H
#define BITPLUS_QT_BITPLUSADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class BitplusAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit BitplusAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

/** Bitplus address widget validator, checks for a valid bitplus address.
 */
class BitplusAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit BitplusAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

#endif // BITPLUS_QT_BITPLUSADDRESSVALIDATOR_H
