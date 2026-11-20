"""Bind only project-authored app/test products; keep generated metadata inert."""
import plistlib
from pathlib import Path

APP='MadCryptoObsHost'
TEST='MadCryptoObsHostTests'
APP_ID='org.example.madcrypto.obsqualification'
TEST_ID=APP_ID+'.tests'
CONFIG='Debug-iphonesimulator'
APP_REL=f'{CONFIG}/{APP}.app'
HOST_REL=f'{APP_REL}/{APP}'
APPROVED_BUNDLES=(f'{CONFIG}/{TEST}.xctest',f'{APP_REL}/PlugIns/{TEST}.xctest')
PLAN='MadCryptoObsHost-reviewed.xctestrun'
EXPORTS=frozenset({'_madcrypto_host_abi','_madcrypto_host_selftest','_madcrypto_test_qualification'})

def exact(root,relative,directory=False):
    path=root/relative
    if path.resolve(strict=True)!=path or not (path.is_dir() if directory else path.is_file()):
        raise ValueError('product-path')
    return path

def plist(path,limit=1024*1024):
    with path.open('rb') as stream:
        data=stream.read(limit+1)
    if len(data)>limit: raise ValueError('plist-size')
    doc=plistlib.loads(data)
    if not isinstance(doc,dict): raise ValueError('plist-shape')
    return doc

def products(root):
    root=Path(root).resolve(strict=True)
    app=exact(root,APP_REL,True)
    host=exact(root,HOST_REL)
    matches=[s for s in APPROVED_BUNDLES if (root/s).exists() or (root/s).is_symlink()]
    if len(matches)!=1: raise ValueError('unique-bundle')
    test=exact(root,matches[0],True)
    binary=exact(root,f'{matches[0]}/{TEST}')
    for directory,name,bid,kind in ((app,APP,APP_ID,'APPL'),(test,TEST,TEST_ID,'BNDL')):
        info=plist(exact(root,str(directory.relative_to(root)/'Info.plist')),65536)
        if (info.get('CFBundleExecutable'),info.get('CFBundleIdentifier'),info.get('CFBundlePackageType'))!=(name,bid,kind):
            raise ValueError('product-identity')
    return host,binary,matches[0]

def one_target(doc):
    meta=doc.get('__xctestrun_metadata__',{})
    if not isinstance(meta,dict): raise ValueError('format')
    version=meta.get('FormatVersion',1)
    if type(version) is not int or version not in (1,2): raise ValueError('format')
    if version==2:
        cfg=doc.get('TestConfigurations')
        if not isinstance(cfg,list) or len(cfg)!=1 or not isinstance(cfg[0],dict) or cfg[0].get('IsEnabled',True) is not True:
            raise ValueError('configuration')
        ts=cfg[0].get('TestTargets')
        if not isinstance(ts,list) or len(ts)!=1: raise ValueError('target-set')
        t=ts[0]
    else:
        if set(doc)-{'__xctestrun_metadata__','CodeCoverageBuildableInfos'}!={TEST}:
            raise ValueError('target-set')
        t=doc[TEST]
    if not isinstance(t,dict) or t.get('BlueprintName',TEST)!=TEST: raise ValueError('target-id')
    if any(t.get(x,False) is not False for x in ('IsUITestBundle','UseDestinationArtifacts','IsSkipped','IsAppHostedTestBundleDisabled')):
        raise ValueError('mode')
    if any(t.get(x,[])!=[] for x in ('OnlyTestIdentifiers','SkipTestIdentifiers','CommandLineArguments')):
        raise ValueError('arguments')
    if any(t.get(x,'')!='' for x in ('UITargetAppPath','TestBundleDestinationRelativePath')):
        raise ValueError('alternate-path')
    return t

def authored(receipt,relative):
    if relative not in APPROVED_BUNDLES: raise ValueError('product-path')
    t=one_target(receipt)
    root='__TESTROOT__/'
    host=root+APP_REL
    if t.get('TestHostPath') not in (host,root+HOST_REL): raise ValueError('receipt-host')
    variants={root+relative}
    if relative.startswith(APP_REL+'/'):
        variants.add('__TESTHOST__/'+relative.removeprefix(APP_REL+'/'))
    if t.get('TestBundlePath') not in variants: raise ValueError('receipt-bundle')
    if t.get('TestHostBundleIdentifier',APP_ID)!=APP_ID: raise ValueError('receipt-host-id')
    if t.get('TestBundleIdentifier',TEST_ID)!=TEST_ID: raise ValueError('receipt-test-id')
    paths=t.get('DependentProductPaths',[])
    if not isinstance(paths,list) or any(x not in variants|{host,root+HOST_REL} for x in paths):
        raise ValueError('receipt-products')
    # Stock launch fields are authored, never copied from the receipt.
    # Whether Xcode 26.2 accepts this minimal native plan needs a real run.
    exact_binding=dict(BlueprintName=TEST,TestHostPath=host,TestBundlePath=root+relative,
        TestHostBundleIdentifier=APP_ID,
        DependentProductPaths=[host,root+relative],
        TestingEnvironmentVariables={'DYLD_FRAMEWORK_PATH':root+CONFIG,'DYLD_LIBRARY_PATH':root+CONFIG})
    return plistlib.dumps({'__xctestrun_metadata__':{'FormatVersion':2},
        'TestConfigurations':[{'Name':'Qualification','IsEnabled':True,'TestTargets':[exact_binding]}]})

def verify_linkage(app_defined,test_defined,test_undefined,required):
    app_defined=set(app_defined.splitlines()); test_defined=set(test_defined.splitlines())
    test_undefined=set(test_undefined.splitlines())
    if not (set(required)|EXPORTS)<=app_defined: raise ValueError('app-implementation')
    if any(x.startswith(('_madcrypto_','_madobs_','_imobs_')) for x in test_defined):
        raise ValueError('test-duplicate-implementation')
    if {x for x in test_undefined if x.startswith(('_madcrypto_','_madobs_','_imobs_'))}!=EXPORTS:
        raise ValueError('test-bridge-imports')

def verify_platform(load_commands):
    import re
    platform=re.findall(r'^\s*platform\s+(\S+)\s*$',load_commands,re.M)
    if 'LC_VERSION_MIN_' in load_commands or len(platform)!=1 or platform[0] not in ('7','IOSSIMULATOR'):
        raise ValueError('simulator-platform')
