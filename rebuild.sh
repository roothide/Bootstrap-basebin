#!/bin/sh

set -e

PREV_DIR=$(pwd)
WORK_DIR=$(dirname -- "$0")
cd "$WORK_DIR"

cd ldid
make clean && make
cd -

cd fastPathSign
make clean && make
cd -

cd rebuildapp
make clean && make package
cd -

cd preload
make clean && make package
cd -

cd bootstrap
make clean && make package
cd -

cd bootstrapd
make clean && make package
cd -

cd devtest
make clean && make package
cd -

echo "**** rebuild successful ****"

./copy.sh

cd "$PREV_DIR"
