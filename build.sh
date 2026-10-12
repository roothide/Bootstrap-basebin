#!/bin/sh

set -e

PREV_DIR=$(pwd)
WORK_DIR=$(dirname -- "$0")
cd "$WORK_DIR"

rm -rf .build
mkdir .build

if [ -f "$(xcrun --sdk iphoneos --show-sdk-path)/usr/include/xpc.modulemap" ] && [ -d "$WORK_DIR/common/xpc" ]; then
	echo "**** SDK provides xpc.modulemap, ignoring vendored $XPC_MODULE ****"
	rm -rf "$WORK_DIR/common/xpc"
fi

cd ChOma-main
make clean-all && make TARGET=ios
cd -

cd ldid
make clean && make
cp ./ldid ../.build/
cd -

cd fastPathSign
make clean && make
cp ./fastPathSign ../.build/
cd -

cd dyldhook
make clean && make
cp ./dyldhook ../.build/
cd -

cd common
make clean all
cd -

cd uicache
make clean all
cd -

cd bsctl
make clean all
cd -

cd appatch
make clean all
cd -

cd preload
make clean all
cd -

cd bootstrap
make clean all
cd -

cd bootstrapd
make clean all
cd -

cd devtest
make clean all
cd -

cd TaskPortHaxx
make clean all
cd -

cd launchdhook
make clean all
cd -

cd jailbreakd
make clean all
cd -

cd roothidehooks
make clean all
cd -

cd kexploit
make clean all
cd -

cp ./test.sh .build/
cp ./rebuildApps.sh .build/
cp ./resignList.plist .build/
cp -a ./entitlements .build/
cp -a ./fallback .build/

echo "**** basebin build successful ****"

cd "$PREV_DIR"
