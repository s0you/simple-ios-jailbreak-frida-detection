//
//  JailBreakChecker.m
//  jbdetect
//
//  Created by Wahyu Wira on 15/06/25.
//

#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <sys/syscall.h>
#import <dirent.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/vm_region.h>
#import <mach/vm_statistics.h>
#import <mach/task.h>
#import <mach/task_info.h>
#import <mach-o/dyld_images.h>
#import <dlfcn.h>
#import <unistd.h>
#import <sys/param.h>
#import <sys/mount.h>
#import <fcntl.h>
#import <mach-o/getsect.h>
#import <spawn.h>
#import <objc/runtime.h>
#import <string>
#import <uuid/uuid.h>
#import "JailbreakChecker.h"
#import "codesign.h"

bool isDebugged() {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

bool scan_taskinfo(){
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    kern_return_t kr = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    if (kr != KERN_SUCCESS) {
        //NSLog(@"[DEBUG] task_info(TASK_DYLD_INFO) failed: %d", kr);
        return false;
    }

    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    if (!infos) {
        //NSLog(@"[DEBUG] all_image_info_addr is NULL");
        return false;
    }

    uint32_t imageCount = infos->infoArrayCount;
    const struct dyld_image_info *imageArray = infos->infoArray;

    //NSLog(@"[DEBUG] image count from task_info: %u", imageCount);

    for (uint32_t i = 0; i < imageCount; i++) {
        const char *imageName = imageArray[i].imageFilePath;
        const void *imageLoadAddr = imageArray[i].imageLoadAddress;
        
        if (!imageName) continue;
        
        NSString *imageStr = [NSString stringWithUTF8String:imageName];
        
        // Log semua image path dan address
        //NSLog(@"[DEBUG] task info: #%u: %p => %@", i, imageLoadAddr, imageStr);
        
        if ([imageStr containsString:@"substrate"] ||
            [imageStr containsString:@"tweak"] ||
            [imageStr containsString:@"libhooker"] ||
            [imageStr containsString:@"frida"] ||
            [imageStr containsString:@".jbroot"] ||
            [imageStr containsString:@"roothide"] ||
            [imageStr containsString:@"rootpatch"]) {
            //NSLog(@"[DETECT] Suspicious dylib: %@", imageStr);
            // return YES;
        }
    }
    return false;
}

bool scan_csops() {
    void *flags;
    int ret = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    if (ret == -1) return NO;
    NSLog(@"[DEBUG] csops - flag : %p", flags);
    return false;
}

bool checkWritableRestrictedPaths() {
    const char *paths[] = {"/", "/jb/", "/private/", "/root/"};
    for (const char *base : paths) {
        NSString *uuidStr = [[NSUUID UUID] UUIDString];
        std::string path = std::string(base) + [uuidStr UTF8String];
        FILE *f = fopen(path.c_str(), "w");
        if (f) {
            fclose(f);
            remove(path.c_str());
            NSLog(@"[JAILBREAK] Writable path found: %s", base);
            return true;
        }
    }
    return false;
}

bool checkSuspiciousObjCClass() {
    Class cls = objc_getClass("ShadowRuleset");
    if (!cls) return false;
    SEL sel = sel_registerName("internalDictionary");
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        NSLog(@"[JAILBREAK] ShadowRuleset class with selector internalDictionary detected");
        return true;
    }
    return false;
}

bool checkFork() {
    pid_t pid = fork();
    if (pid >= 0) {
        if (pid > 0) kill(pid, SIGKILL);
        NSLog(@"[JAILBREAK] fork() succeeded, sandbox likely bypassed");
        return true;
    }
    return false;
}

bool scanForHiddenDylibs() {
    mach_port_t task = mach_task_self();
    vm_address_t address = 0;
    vm_size_t size = 0;
    natural_t depth = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t infoCount = VM_REGION_SUBMAP_INFO_COUNT_64;

    while (1) {
        kern_return_t kr = vm_region_recurse_64(task, &address, &size, &depth, (vm_region_info_t)&info, &infoCount);
        if (kr != KERN_SUCCESS) {
            break;
        }
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_EXECUTE)) {
            vm_address_t magic = 0;
            vm_size_t readSize;
            kr = vm_read_overwrite(task, address, sizeof(uint32_t), (vm_address_t)&magic, &readSize);

            if (kr == KERN_SUCCESS && readSize == sizeof(uint32_t)) {
                if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
                    Dl_info dlinfo;
                    if (dladdr((const void *)address, &dlinfo) && dlinfo.dli_fname) {
                        NSString *libName = [NSString stringWithUTF8String:dlinfo.dli_fname];
                        if (![libName containsString:@"/System/Library/"] &&
                            ![libName containsString:@"/usr/lib/"] &&
                            ![libName containsString:@"/private/preboot"]) {
                            //NSLog(@"[DEBUG] Suspicious Mach-O at: %p (%@)", (void *)address, libName);
                        }
                        if ([libName containsString:@"root"] || [libName containsString:@"hook"] || [libName containsString:@"substrate"] || [libName containsString:@"tweak"] || [libName containsString:@".jbroot"]) {
                            //NSLog(@"[DEBUG] Suspicious Mach-O at: %p (%@)", (void *)address, libName);
                            //return true;
                        }
                    } else {
                        NSLog(@"[DEBUG] Unknown Mach-O image at: %p", (void *)address);
                        //return true;
                    }
                }
            }
        }

        address += size;
    }

    return false;
}

@implementation Init

+ (BOOL)isDeviceJailbroken {
    NSArray *paths = @[
        @"/var/jb",
        @"/var/containers/Bundle/tweaksupport",
        @"/var/bin/bash",
        @"/var/LIB",
        @"/var/lib/filza",
        @"/var/lib/undecimus",
        @"/Applications/Cydia.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/Applications/Cydia.app",
        @"/Applications/blackra1n.app",
        @"/Applications/FakeCarrier.app",
        @"/Applications/Icy.app",
        @"/Applications/IntelliScreen.app",
        @"/Applications/MxTube.app",
        @"/Applications/RockApp.app",
        @"/Applications/SBSettings.app",
        @"/Applications/WinterBoard.app",
        @"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        @"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        @"/private/var/lib/apt",
        @"/private/var/lib/cydia",
        @"/private/var/mobile/Library/SBSettings/Themes",
        @"/private/var/stash",
        @"/private/var/tmp/cydia.log",
        @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        @"/usr/bin/sshd",
        @"/usr/libexec/sftp-server",
        @"/usr/sbin/sshd",
        @"/usr/sbin/frida-server",
        @"/etc/apt/sources.list.d/electra.list",
        @"/etc/apt/sources.list.d/sileo.sources",
        @"/.bootstrapped_electra",
        @"/usr/lib/libjailbreak.dylib",
        @"/jb/lzma",
        @"/.cydia_no_stash",
        @"/.installed_unc0ver",
        @"/jb/offsets.plist",
        @"/usr/share/jailbreak/injectme.plist",
        @"/etc/apt/undecimus/undecimus.list",
        @"/var/lib/dpkg/info/mobilesubstrate.md5sums",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/jb/jailbreakd.plist",
        @"/jb/amfid_payload.dylib",
        @"/jb/libjailbreak.dylib",
        @"/usr/libexec/cydia/firmware.sh",
        @"/var/lib/cydia",
        @"/etc/apt",
        @"/var/containers/Bundle/Application/.jbroot"
    ];
    
    for (NSString *path in paths) {
        BOOL foundByNSFileManager = [[NSFileManager defaultManager] fileExistsAtPath:path];
        
        if (foundByNSFileManager) {
            NSLog(@"[DEBUG] Path found: %@ via NSFileManager", path);
            //return YES;
        }
        
    }
    
    struct statfs sfs;
    if (statfs("/var/containers/Bundle/Application", &sfs) == 0) {
        //NSLog(@"[DEBUG] FS Bundle/Application Type: %d, Flags: 0x%x", sfs.f_type, sfs.f_flags);
    }
    
    if (statfs("/var/jb", &sfs) == 0) {
        //NSLog(@"[DEBUG] FS var/jb Type: %d, Flags: 0x%x", sfs.f_type, sfs.f_flags);
    }
    
    if (statfs("/private/", &sfs) == 0) {
        //NSLog(@"[DEBUG] FS /private Type: %d, Flags: 0x%x", sfs.f_type, sfs.f_flags);
    }
    
    if (statfs("/Applications", &sfs) == 0) {
        //NSLog(@"[DEBUG] FS /private Type: %d, Flags: 0x%x", sfs.f_type, sfs.f_flags);
    }

    struct stat s;
    if (lstat("/Applications", &s) == 0 && (s.st_mode & S_IFLNK)) {
        //NSLog(@"[DEBUG] /Applications is a symbolic link.");
        //return YES;
    }
    
    NSArray *envVars = @[
        @"DYLD_INSERT_LIBRARIES",
        @"DYLD_LIBRARY_PATH",
        @"DYLD_FRAMEWORK_PATH",
        @"DYLD_FALLBACK_FRAMEWORK_PATH",
        @"DYLD_FALLBACK_LIBRARY_PATH",
        @"DYLD_ROOT_PATH",
        @"DYLD_SHARED_CACHE_DIR",
        @"DYLD_SHARED_CACHE_DONT_VALIDATE",
        @"JB_ROOT_PATH",
        @"JBRAND",
        @"JBROOT",
        @"JB_SANDBOX_EXTENSIONS",
        @"DISABLE_TWEAK",
        @"_SafeMode",
        @"_MSSafeMode",
        @"CFFIXED_USER_HOME",
        @"HOME"
    ];
    
    for (NSString *var in envVars) {
        char *value = getenv([var UTF8String]);
        if (value != NULL) {
            NSString *strValue = [NSString stringWithUTF8String:value];
            NSLog(@"[DEBUG] found env var %@: %@", var, strValue);
            //return YES;
        }
    }
    
    if(isDebugged()){
        NSLog(@"[DEBUG] Debug detected.");
    }
    
    if(scanForHiddenDylibs()){
        //return YES;
    }
    
    if(scan_taskinfo()){
        
    }
    
    if(scan_csops()){
        
    }
    
    if(checkWritableRestrictedPaths()){
        
    }
    
    if(checkSuspiciousObjCClass()){
        
    }
    
    if(checkFork()){
        
    }
    
    for (int i = 0; i < _dyld_image_count(); i++) {
        const char *dyld = _dyld_get_image_name(i);
        NSString *dyldStr = [NSString stringWithUTF8String:dyld];
        //NSLog(@"[DEBUG] dladdr : sname: %s | fname: %s | fbase: %p | saddr: %p", info.dli_sname, info.dli_fname, info.dli_fbase, info.dli_saddr);
        if ([dyldStr containsString:@"substrate"] || [dyldStr containsString:@"tweak"] || [dyldStr containsString:@"libhooker"] || [dyldStr containsString:@"frida"] || [dyldStr containsString:@".jbroot"] || [dyldStr containsString:@"roothide"] || [dyldStr containsString:@"rootpatch"]) {
            //return YES;
        }
        //NSLog(@"[DEBUG] Found dyld loaded: %@", dyldStr);
    }
    
    return NO;
}

//Will be update soon
+ (BOOL)isFridaRunning {
    
    return NO;
}

@end
