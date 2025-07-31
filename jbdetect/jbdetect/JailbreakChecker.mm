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
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import "JailbreakChecker.h"
#import "codesign.h"

bool isDebugged() {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

bool check_csops() {
    void *flags;
    int ret = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    if (ret == -1) return NO;
    NSLog(@"[DEBUG] csops - flag : %p", flags);
    return false;
}

bool check_writablepath() {
    const char *paths[] = {"/", "/jb/", "/private/", "/root/"};
    for (const char *base : paths) {
        NSString *uuidStr = [[NSUUID UUID] UUIDString];
        std::string path = std::string(base) + [uuidStr UTF8String];
        FILE *f = fopen(path.c_str(), "w");
        if (f) {
            fclose(f);
            remove(path.c_str());
            NSLog(@"[DEBUG] (check_writablepath) found: %s", base);
            return true;
        }
    }
    return false;
}

bool check_fork() {
    pid_t pid = fork();
    if (pid >= 0) {
        if (pid > 0) kill(pid, SIGKILL);
        NSLog(@"[DEBUG] fork() succeeded");
        return true;
    }
    return false;
}

bool check_symbolic() {
    const char* paths[] = {
        "/Applications", "/Library/Ringtones", "/usr/arm-apple-darwin9",
        "/usr/include", "/usr/libexec", "/usr/share"
    };

    for (const char* path : paths) {
        struct stat s;
        if (lstat(path, &s) == 0 && S_ISLNK(s.st_mode)) {
            NSLog(@"[DEBUG] (check_symbolic) found: %s", path);
            return true;
        }
    }
    return false;
}

bool check_path2() {
    const char* suspiciousFiles[] = {
        "/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/cydia",
        "/usr/lib/libjailbreak.dylib", "/var/lib/cydia"
    };

    for (const char* path : suspiciousFiles) {
        struct stat s;
        if (stat(path, &s) == 0) {
            NSLog(@"[DEBUG] (check_path2) found: %s", path);
            return true;
        }
    }
    return false;
}

bool check_path(){
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
            NSLog(@"[DEBUG] (check_path) found: %@", path);
            return true;
        }
        
    }
    
    return false;
}

bool check_env(){
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
            NSLog(@"[DEBUG] (check_env) found: %@ - %@", var, strValue);
            return true;
        }
    }
    
    return false;
}

static NSArray<NSString *> *blacklist_lib() {
    return @[
        @"substrate", @"Substrate", @"TweakInject",
        @"tweak", @"libhooker", @"frida", @".jbroot",
        @"roothide", @"rootpatch", @"Shadow",
        @"systemhook", @"SubstrateLoader", @"SSLKillSwitch2",
        @"SSLKillSwitch", @"MobileSubstrate", @"CydiaSubstrate",
        @"cynject", @"CustomWidgetIcons", @"PreferenceLoader",
        @"RocketBootstrap", @"WeeLoader", @"/.file",
        @"libhooker", @"SubstrateInserter", @"SubstrateBootstrap",
        @"ABypass", @"FlyJB", @"Substitute", @"Cephei",
        @"Electra", @"AppSyncUnified-FrontBoard", @"Shadow",
        @"FridaGadget", @"libcycript", @"frida"
    ];
}
NSArray<NSString *> *suspicious = blacklist_lib();

bool check_dyld(){
    for (int i = 0; i < _dyld_image_count(); i++) {
        const char *dyld = _dyld_get_image_name(i);
        NSString *dyldStr = [NSString stringWithUTF8String:dyld];
        for (NSString *keyword in suspicious) {
            if ([dyldStr localizedCaseInsensitiveContainsString:keyword]) {
                NSLog(@"[DEBUG] (check_dyld) found: %@", dyldStr);
                return true;
            }
        }
    }
    return false;
}

bool check_vmdyld() {
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
                        for (NSString *keyword in suspicious) {
                            if ([libName localizedCaseInsensitiveContainsString:keyword]) {
                                NSLog(@"[DEBUG] (check_vmdyld) found: %p (%@)", (void *)address, libName);
                                return true;
                            }
                        }
                        
                    } else {
                        NSLog(@"[DEBUG] (check_vmdyld) Unknown Mach-O image at: %p", (void *)address);
                        //return true;
                    }
                }
            }
        }

        address += size;
    }

    return false;
}

bool check_taskinfo(){
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    kern_return_t kr = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    if (kr != KERN_SUCCESS) {
        return false;
    }

    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    if (!infos) {
        return false;
    }

    uint32_t imageCount = infos->infoArrayCount;
    const struct dyld_image_info *imageArray = infos->infoArray;
    for (uint32_t i = 0; i < imageCount; i++) {
        const char *imageName = imageArray[i].imageFilePath;
        //const void *imageLoadAddr = imageArray[i].imageLoadAddress;
    
        if (!imageName) continue;
        
        NSString *imageStr = [NSString stringWithUTF8String:imageName];
        //NSLog(@"[DEBUG] task info: #%u: %p => %@", i, imageLoadAddr, imageStr);
        
        for (NSString *keyword in suspicious) {
            if ([imageStr localizedCaseInsensitiveContainsString:keyword]) {
                NSLog(@"[DETECT] (check_taskinfo) found: %@", imageStr);
                return true;
            }
        }
    }
    return false;
}

bool check_frida_process() {
    FILE *pipe = popen("ps -e", "r");
    if (!pipe) return false;

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        if (strstr(buffer, "frida") || strstr(buffer, "Frida")) {
            NSLog(@"[DETECT] (check_frida_process) Found frida process: %s", buffer);
            pclose(pipe);
            return true;
        }
    }

    pclose(pipe);
    return false;
}

bool check_frida_ports() {
    int ports[] = { 27042, 27043 };
    for (int port : ports) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        int result = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
        close(sockfd);

        if (result == 0) {
            NSLog(@"[DETECT] (check_frida_ports) Port open: %d", port);
            return true;
        }
    }
    return false;
}

@implementation Init

+ (BOOL)isDeviceJailbroken {
    NSLog(@"[DEBUG] Detection..");
    
    if(check_csops()){
        
    }
    
    if(check_writablepath()){
        return YES;
    }
    
    if(check_path()){
        return YES;
    }
    
    if(check_path2()){
        return YES;
    }
    
    if(check_fork()){
        return YES;
    }
    
    if(check_env()){
        return YES;
    }
    
    if(check_symbolic()){
        return YES;
    }
    
    if(check_dyld()){
        return YES;
    }
    
    if(check_vmdyld()){
        return YES;
    }
    
    if(check_taskinfo()){
        return YES;
    }
    
    return NO;
}

+ (BOOL)isFridaRunning {
    
    if(check_frida_process()){
        return YES;
    }
    
    if(check_frida_ports()){
        return YES;
    }
    
    return NO;
}

@end
