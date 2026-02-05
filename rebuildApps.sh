#!/bin/sh

date || true;

ls /Applications/  | while read app; do
    echo "--$app--";
    
    uicache -p "/Applications/$app" || true
done

date || true;

ls -d /.sysroot/Applications/*.app/.jbroot | while read file; do
    bundle=$(dirname "$file")
    echo "--$bundle--"

    uicache -p "$bundle" || true
done

date || true;

ls -d /rootfs/var/containers/Bundle/Application/*/*.app/.jbroot | while read file; do
    bundle=$(dirname "$file")
    echo "--$bundle--"

    unlink "$bundle"/.jbroot
    ln -s /  "$bundle"/.jbroot

    uicache -s -p "$bundle" || true
done

date || true;
