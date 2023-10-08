#!/bin/bash
source IDs.sh
PKG_ID=1_6
VERSION=1.6
OPTIONS="--wait --no-progress --apple-id $APPLE_ID \
--team-id $DEV_ID --password $ONE_TIME_PASS --wait"

mkdir -p bin
cp ../macher bin
codesign -v -s $DEV_ID --timestamp --options runtime --force bin/macher
pkgbuild --root bin --identifier info.marc-culler.macher.$PKG_ID \
    --install-location /usr/local/bin bin.pkg
productsign --sign $DEV_ID bin.pkg macher.pkg
rm -f bin.pkg
xcrun notarytool submit $OPTIONS macher.pkg
xcrun stapler staple macher.pkg
