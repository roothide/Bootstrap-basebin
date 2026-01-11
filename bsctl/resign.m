#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <roothide.h>
#include "commlib.h"
#include "resign.h"

#define LOG	printf

int ResignSystemExecutables()
{
    NSFileManager* fm = NSFileManager.defaultManager;

    NSArray* ResignList = [NSArray arrayWithContentsOfFile:jbroot(@"/basebin/resignList.plist")];
    if(!ResignList) {
        LOG("Unable to load resign list\n");
        return -1;
    }
    
    if([fm fileExistsAtPath:RESIGNED_SYSROOT_PATH]) {
        ASSERT([fm removeItemAtPath:RESIGNED_SYSROOT_PATH error:nil]);
    }
    
    for(NSString* sourcePath in ResignList)
    {
        if(![fm fileExistsAtPath:sourcePath]) {
            LOG("%s Not Found, Skip...\n", sourcePath.fileSystemRepresentation);
            continue;
        }
        
        LOG("Resign %s\n", sourcePath.fileSystemRepresentation);
        
        NSString* destPath = [RESIGNED_SYSROOT_PATH stringByAppendingPathComponent:sourcePath];
        NSString* destDirPath = [destPath stringByDeletingLastPathComponent];
        
        NSString* destSubPathTemp = RESIGNED_SYSROOT_PATH;
        NSArray<NSString *>* sourcePathComponents = sourcePath.pathComponents;
        for(NSString* item in sourcePathComponents)
        {
            destSubPathTemp = [destSubPathTemp stringByAppendingPathComponent:item];
            
            struct stat st={0};
            if(lstat(destSubPathTemp.fileSystemRepresentation, &st) != 0) {
                break;
            }
            
            if(S_ISLNK(st.st_mode)) {
                ASSERT(unlink(destSubPathTemp.fileSystemRepresentation)==0);
                break;
            }
        }
        
        if(![fm fileExistsAtPath:destDirPath]) {
            NSDictionary* attr = @{NSFilePosixPermissions:@(0755), NSFileOwnerAccountID:@(0), NSFileGroupOwnerAccountID:@(0)};
            ASSERT([fm createDirectoryAtPath:destDirPath withIntermediateDirectories:YES attributes:attr error:nil]);
        }
        
        ASSERT([fm copyItemAtPath:sourcePath toPath:destPath error:nil]);
        
        NSURL* sourceDirURL = [NSURL fileURLWithPath:sourcePath.stringByDeletingLastPathComponent];
        for (NSURL* fileURL in [fm contentsOfDirectoryAtURL:sourceDirURL includingPropertiesForKeys:nil options:0 error:nil]) {
            NSString* destfile = [destDirPath stringByAppendingPathComponent:fileURL.lastPathComponent];
            if(![fm fileExistsAtPath:destfile]) {
                ASSERT([fm createSymbolicLinkAtPath:destfile withDestinationPath:fileURL.path error:nil]);
            }
        }

        NSString* stripEntitlementsFile = [NSString stringWithFormat:@"/basebin/entitlements/executables/%@.strip", sourcePath.lastPathComponent];
        NSString* extraEntitlementsFile = [NSString stringWithFormat:@"/basebin/entitlements/executables/%@.extra", sourcePath.lastPathComponent];
        NSMutableArray* args = [NSMutableArray arrayWithArray:@[@"-M", [NSString stringWithFormat:@"-S%@", jbroot(extraEntitlementsFile)], destPath]];
        if([fm fileExistsAtPath:jbroot(stripEntitlementsFile)]) {
            [args addObject:[NSString stringWithFormat:@"--strip=%@", jbroot(stripEntitlementsFile)]];
        }
        if([fm fileExistsAtPath:jbroot(extraEntitlementsFile)]) {
            //note: only basebin/ldid -M supports deep merge
            ASSERT(spawn_root(jbroot(@"/basebin/ldid"), args, nil, nil) == 0);
        } else {
            LOG("Entitlements File %s Not Found!!!\n", extraEntitlementsFile.fileSystemRepresentation);
            return -1;
        }
        
        ASSERT(spawn_root(jbroot(@"/basebin/fastPathSign"), @[destPath], nil, nil) == 0);
    }

    return 0;
}
