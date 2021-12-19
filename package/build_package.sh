#!/bin/bash
source IDs.sh
PKG_ID=1_4
VERSION=1.4

mkdir -p bin
cp ../macher bin
codesign -v -s $DEV_ID --timestamp --options runtime --force bin/macher
pkgbuild --root bin --identifier info.marc-culler.macher.$PKG_ID --version $VERSION --install-location /usr/local/bin bin.pkg
productsign --sign $DEV_ID bin.pkg macher.pkg
rm -f bin.pkg
xcrun altool --notarize-app --primary-bundle-id "macher-$VERSION" --username $USERNAME --password $ONE_TIME_PASS --file macher.pkg
echo Waiting 90 seconds ...
sleep 90
xcrun stapler staple macher.pkg
