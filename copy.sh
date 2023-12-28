#!/bin/sh

set -e

PREV_DIR=$(pwd)
WORK_DIR=$(dirname -- "$0")
cd "$WORK_DIR"

TARGET="../Bootstrap/basebin/"

if [ -d "$TARGET" ]; then
	rm -rf "$TARGET"
fi

mkdir $TARGET

cp ./ldid/ldid $TARGET
cp ./bootstrap.entitlements $TARGET
cp ./fastPathSign/fastPathSign $TARGET
cp ./preload/.theos/_/basebin/preload $TARGET
cp ./preload/.theos/_/basebin/preload.dylib $TARGET
cp ./bootstrap/.theos/_/basebin/bootstrap.dylib $TARGET
cp ./bootstrapd/.theos/_/basebin/bootstrapd $TARGET
cp ./rebuildapp/.theos/_/basebin/rebuildapp $TARGET
cp ./rebuildapp/.theos/_/basebin/rebuildapps.sh $TARGET

echo "***** copy finished *****"

cd "$PREV_DIR"
