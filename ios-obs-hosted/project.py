"""Offline stage: generate a deliberate, named app-hosted XCTest project."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
APP='MadCryptoObsHost'
TEST='MadCryptoObsHostTests'
APP_ID='org.example.madcrypto.obsqualification'
TEST_ID=APP_ID+'.tests'

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,file)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def ident(n):
    return f'CA{n:022X}'

def serialize(value):
    if isinstance(value,dict):
        return '{\n'+''.join(json.dumps(k)+' = '+serialize(v)+';\n' for k,v in value.items())+'}'
    if isinstance(value,list):
        return '('+', '.join(map(serialize,value))+')'
    return json.dumps(value)

def document():
    objects={}
    def add(n,isa,**kw):
        objects[ident(n)]=dict(isa=isa,**kw)
    r=ident
    app_src={10:('App/main.m','sourcecode.c.objc'),11:('App/Bridge.cpp','sourcecode.cpp.cpp'),
             12:('App/fixture.c','sourcecode.c.c'),13:('App/Entries.c','sourcecode.c.c')}
    test_src={14:('Tests/PackageTests.swift','sourcecode.swift'),15:('Tests/ObserverTests.swift','sourcecode.swift')}
    all_src=app_src|test_src
    add(1,'PBXProject',attributes={'TargetAttributes':{r(31):{'TestTargetID':r(30)}}},
        buildConfigurationList=r(60),compatibilityVersion='Xcode 14.0',
        developmentRegion='en',knownRegions=['en','Base'],mainGroup=r(2),
        productRefGroup=r(3),projectDirPath='',projectRoot='',targets=[r(30),r(31)])
    add(2,'PBXGroup',children=[r(n) for n in all_src]+[r(3)],sourceTree='<group>')
    add(3,'PBXGroup',name='Products',children=[r(4),r(5)],sourceTree='<group>')
    for n,ptype,name in ((4,'wrapper.application',APP+'.app'),(5,'wrapper.cfbundle',TEST+'.xctest')):
        add(n,'PBXFileReference',explicitFileType=ptype,path=name,sourceTree='BUILT_PRODUCTS_DIR')
    for n,(name,ftype) in all_src.items():
        add(n,'PBXFileReference',lastKnownFileType=ftype,path=name,sourceTree='<group>')
        add(n+10,'PBXBuildFile',fileRef=r(n))
    for target,cfg,phases,dependencies,name,typ,prod in (
        (30,61,[40,41],[],APP,'application',4),
        (31,62,[42,43],[50],TEST,'bundle.unit-test',5),
    ):
        add(target,'PBXNativeTarget',buildConfigurationList=r(cfg),buildPhases=list(map(r,phases)),
            buildRules=[],dependencies=list(map(r,dependencies)),name=name,productName=name,
            productType='com.apple.product-type.'+typ,productReference=r(prod))
    for n,kind,files in ((40,'Sources',list(app_src)),(41,'Frameworks',[]),(42,'Sources',list(test_src)),(43,'Frameworks',[])):
        add(n,'PBX'+kind+'BuildPhase',buildActionMask='2147483647',
            files=[r(x+10) for x in files],runOnlyForDeploymentPostprocessing='0')
    add(50,'PBXTargetDependency',target=r(30),targetProxy=r(51))
    add(51,'PBXContainerItemProxy',containerPortal=r(1),proxyType='1',remoteGlobalIDString=r(30),remoteInfo=APP)
    base=dict(SDKROOT='iphonesimulator',SUPPORTED_PLATFORMS='iphonesimulator',TARGETED_DEVICE_FAMILY='1',
              IPHONEOS_DEPLOYMENT_TARGET='16.0',ARCHS='arm64',ONLY_ACTIVE_ARCH='YES',
              CLANG_ENABLE_MODULES='YES',CLANG_ENABLE_OBJC_ARC='YES',SWIFT_VERSION='5.0',
              GENERATE_INFOPLIST_FILE='YES',CODE_SIGNING_ALLOWED='YES',
              CODE_SIGN_IDENTITY='-',CODE_SIGNING_REQUIRED='NO',DEVELOPMENT_TEAM='')
    app=dict(PRODUCT_NAME=APP,PRODUCT_BUNDLE_IDENTIFIER=APP_ID,DEAD_CODE_STRIPPING='NO',
             CLANG_CXX_LANGUAGE_STANDARD='c++17',GCC_PREPROCESSOR_DEFINITIONS=['$(inherited)'],
             OTHER_CFLAGS=['$(inherited)','-UNDEBUG'],
             HEADER_SEARCH_PATHS=['$(PROJECT_DIR)/Inputs/CryptoHeaders','$(PROJECT_DIR)/Inputs/ObsHeaders'],
             EXPORTED_SYMBOLS_FILE='$(PROJECT_DIR)/App/Exports.txt',
             OTHER_LDFLAGS=['$(inherited)','$(PROJECT_DIR)/Inputs/libmadcrypto_ffi.a',
                            '$(PROJECT_DIR)/Inputs/libmadobs_runtime.a','-lresolv','-liconv','-lz','-lc++',
                            '-framework','Security','-framework','UIKit'])
    test=dict(PRODUCT_NAME=TEST,PRODUCT_BUNDLE_IDENTIFIER=TEST_ID,
              TEST_HOST='$(BUILT_PRODUCTS_DIR)/'+APP+'.app/'+APP,
              BUNDLE_LOADER='$(TEST_HOST)',
              SWIFT_OBJC_BRIDGING_HEADER='$(PROJECT_DIR)/Tests/Entries.h',
              LD_RUNPATH_SEARCH_PATHS=['$(inherited)','@executable_path/Frameworks','@loader_path/Frameworks'])
    for owner,config,settings in ((60,70,base),(61,71,app),(62,72,test)):
        add(owner,'XCConfigurationList',buildConfigurations=[r(config)],
            defaultConfigurationIsVisible='0',defaultConfigurationName='Debug')
        add(config,'XCBuildConfiguration',name='Debug',buildSettings=settings)
    return dict(archiveVersion='1',classes={},objectVersion='56',objects=objects,rootObject=r(1))

def scheme():
    def buildable(parent,n,name,product):
        return ET.SubElement(parent,'BuildableReference',BuildableIdentifier='primary',BlueprintIdentifier=ident(n),
                             BuildableName=product,BlueprintName=name,ReferencedContainer='container:'+APP+'.xcodeproj')
    root=ET.Element('Scheme',version='1.7',LastUpgradeVersion='1620')
    build=ET.SubElement(root,'BuildAction',parallelizeBuildables='NO',buildImplicitDependencies='NO')
    entries=ET.SubElement(build,'BuildActionEntries')
    for n,name,product in ((30,APP,APP+'.app'),(31,TEST,TEST+'.xctest')):
        entry=ET.SubElement(entries,'BuildActionEntry',buildForTesting='YES',buildForRunning='NO',
                            buildForProfiling='NO',buildForArchiving='NO',buildForAnalyzing='NO')
        buildable(entry,n,name,product)
    action=ET.SubElement(root,'TestAction',buildConfiguration='Debug',selectedDebuggerIdentifier='Xcode.DebuggerFoundation.Debugger.LLDB',
                         selectedLauncherIdentifier='Xcode.DebuggerFoundation.Launcher.LLDB',shouldUseLaunchSchemeArgsEnv='NO')
    tests=ET.SubElement(action,'Testables')
    buildable(ET.SubElement(tests,'TestableReference',skipped='NO',parallelizable='NO'),31,TEST,TEST+'.xctest')
    return ET.tostring(root,encoding='unicode')+'\n'

def replace_once(text,before,after):
    if text.count(before)!=1: raise ValueError('test-source-shape')
    return text.replace(before,after,1)

def stage_sources(out):
    source=ROOT/'ios-obs-consumer'
    prov=load('public_fixture_prepare',source/'prepare.py')
    app=out/'App';tests=out/'Tests';app.mkdir();tests.mkdir()
    for name in ('Bridge.cpp','Bridge.h','FixtureHook.h'):
        shutil.copyfile(source/name,app/name)
    shutil.copyfile(ROOT/'adapters/obs/madcrypto_obs.h',app/'madcrypto_obs.h')
    (app/'fixture.c').write_text(prov.transform((ROOT/'tests/obs_adapter.c').read_bytes()))
    (app/'main.m').write_text('''#import <UIKit/UIKit.h>
@interface QualificationAppDelegate : UIResponder <UIApplicationDelegate>
@end
@implementation QualificationAppDelegate
@end
int main(int argc, char **argv) {
  @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([QualificationAppDelegate class])); }
}
''')
    (app/'Entries.c').write_text('''#include <madcrypto.h>
uint32_t madcrypto_host_abi(void) { return madcrypto_abi_version(); }
int32_t madcrypto_host_selftest(void) { return madcrypto_selftest(); }
''')
    (app/'Exports.txt').write_text('_madcrypto_host_abi\n_madcrypto_host_selftest\n_madcrypto_test_qualification\n')
    (tests/'Entries.h').write_text('''#include <stdint.h>
uint32_t madcrypto_host_abi(void);
int32_t madcrypto_host_selftest(void);
int madcrypto_test_qualification(const char *directory);
''')
    plain=(ROOT/'ios-package-check/Consumer/Tests/ConsumerTests/PackageTests.swift').read_text()
    plain=replace_once(plain,'import Consumer\n','')
    plain=replace_once(plain,'PackageProbe.abiVersion()','madcrypto_host_abi()')
    plain=replace_once(plain,'PackageProbe.existingSelftest()','madcrypto_host_selftest()')
    (tests/'PackageTests.swift').write_text(plain)
    obs=(source/'Consumer/Tests/ConsumerTests/ObserverTests.swift').read_text()
    (tests/'ObserverTests.swift').write_text(replace_once(obs,'import QualificationBridge\n',''))

def create(out):
    if not sys.flags.isolated: raise ValueError('python-isolation')
    out.mkdir(mode=0o700)
    stage_sources(out)
    project=out/(APP+'.xcodeproj'); schemes=project/'xcshareddata/xcschemes'
    schemes.mkdir(parents=True)
    (project/'project.pbxproj').write_text('// !$*UTF8*$!\n'+serialize(document())+'\n')
    (schemes/(APP+'.xcscheme')).write_text(scheme())
