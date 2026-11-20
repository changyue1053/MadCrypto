"""SDK-free install control, on its own simulator, never launched."""
from pathlib import Path
import time
from types import SimpleNamespace

BUNDLE_ID='org.example.madcrypto.installcontrol'
BUDGET=360
DEVICE='com.apple.CoreSimulator.SimDeviceType.iPhone-16'
SOURCE='''#import <UIKit/UIKit.h>
@interface InstallControlDelegate : UIResponder <UIApplicationDelegate>
@end
@implementation InstallControlDelegate
@end
int main(int argc, char **argv) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([InstallControlDelegate class])); }
}
'''
def document(hosted):
    doc=hosted.document()
    refs=doc['objects']; ident=hosted.ident
    refs[ident(40)]['files']=[ident(20)]  # only App/main.m
    flags=refs[ident(71)]['buildSettings']
    flags['PRODUCT_BUNDLE_IDENTIFIER']=BUNDLE_ID
    for k in ('EXPORTED_SYMBOLS_FILE','HEADER_SEARCH_PATHS'):
        flags.pop(k)
    flags['OTHER_LDFLAGS']=['$(inherited)','-framework','UIKit']
    return doc

def compare(product, control):
    if product is None or control is None: return 'inconclusive'
    if product=='installed' and control=='installed': return 'both-installed'
    if product=='timeout' and control=='timeout': return 'both-timeout'
    if product!='installed' and control=='installed': return 'only-control-installed'
    if product=='installed' and control!='installed': return 'only-product-installed'
    return 'neither-installed'

def invoke(work, product_uuid, runtime, toolkit):
    # Only the control device is ever touched by this function.
    hosted,graph,bind,pre,receipt,installer,run,failed=toolkit
    root=work/'control-app'
    root.mkdir(mode=0o700)
    project=root/(hosted.APP+'.xcodeproj')
    (project/'xcshareddata/xcschemes').mkdir(parents=True)
    (root/'App').mkdir()
    (root/'App/main.m').write_text(SOURCE)
    # No producer trees, SDK archives, headers, fixtures, or app sources copied.
    proxy=SimpleNamespace(document=lambda:document(hosted),ident=hosted.ident,
                          APP=hosted.APP,TEST=hosted.TEST,serialize=hosted.serialize)
    graph.install(proxy,root,'app')
    deadline=time.monotonic()+BUDGET
    def bounded(args, label, maximum):
        remaining=deadline-time.monotonic()
        if remaining<=0: raise failed('install-control-deadline')
        return run(args,label,cwd=root,timeout=min(remaining,maximum))
    sim=['xcrun','simctl']
    uuid=bounded(sim+['create','MadCrypto-Install-Control',DEVICE,runtime],
                 'install-control-create',45).strip()
    # Validate before ownership/cleanup; never delete an invalid or product ID.
    import re
    if not re.fullmatch(receipt.UUID,uuid) or uuid.lower()==product_uuid.lower():
        raise failed('install-control-id')
    try:
        xc=['xcodebuild','-project',hosted.APP+'.xcodeproj','-scheme','Diagnostic-app']
        pre.destination(bounded(xc+['-showdestinations'],'install-control-destination',90),uuid)
        derived=root/'derived'
        bounded(xc+['-destination','platform=iOS Simulator,id='+uuid,'-destination-timeout','60',
                    '-derivedDataPath',str(derived),'-configuration','Debug','build'],
                'install-control-build',180)
        products=derived/'Build/Products'
        host=bind.exact(products,bind.HOST_REL)
        metadata=bind.plist(bind.exact(products,bind.APP_REL+'/Info.plist'),65536)
        if (metadata.get('CFBundleExecutable'),metadata.get('CFBundleIdentifier'),
            metadata.get('CFBundlePackageType'))!=(hosted.APP,BUNDLE_ID,'APPL'):
            raise failed('install-control-identity')
        if bounded(['xcrun','lipo','-archs',str(host)],'install-control-architecture',30).strip()!='arm64':
            raise failed('install-control-architecture')
        bind.verify_platform(bounded(['xcrun','otool','-l',str(host)],'install-control-platform',30))
        bounded(['/usr/bin/codesign','--verify','--strict',str(host.parent)],'install-control-signature',30)
        names=bounded(['xcrun','nm','-U','-j',str(host)],'install-control-symbols',30).splitlines()
        if any(name.startswith(('_madcrypto_','_madobs_','_imobs_')) for name in names):
            raise failed('install-control-symbols')
        bounded(sim+['boot',uuid],'install-control-boot',90)
        bounded(sim+['bootstatus',uuid,'-b'],'install-control-ready',120)
        if deadline-time.monotonic()<installer.TIMEOUT: raise failed('install-control-deadline')
        print('START: install-control-only',flush=True)
        result=installer.invoke(sim+['install',uuid,str(host.parent)])
        print('RESULT: install-control-only-'+('installed' if result is None else result),flush=True)
        return 'installed' if result is None else result
    finally:
        for action in ('shutdown','delete'):
            try: run(sim+[action,uuid],'install-control-cleanup',timeout=60)
            except failed:
                if action=='delete':
                    print('FAIL: install-control-cleanup',flush=True)
                    raise
