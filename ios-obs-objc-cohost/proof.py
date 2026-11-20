"""Bound the project/scheme test route to the signed authored products."""
DRIVER='_OBJC_CLASS_$_MadCryptoCohostDriver'
PREFIX=('_madcrypto_','_madobs_','_imobs_')

def symbols(app_defined,test_all,test_undefined,required):
    app=set(app_defined.splitlines())
    test=set(test_all.splitlines())
    unresolved=set(test_undefined.splitlines())
    if not (set(required)|{DRIVER}) <= app:
        raise ValueError('app-linkage')
    if DRIVER not in unresolved or any(x.startswith(PREFIX) for x in test|unresolved):
        raise ValueError('test-driver-only')

def receipt(doc,bind,approved):
    # Trusted output of the pinned local Xcode against our authored project.
    # Reject known launch/selection controls outside the one target.
    known_overrides={'EnvironmentVariables','TestingEnvironmentVariables','CommandLineArguments',
                     'OnlyTestIdentifiers','SkipTestIdentifiers','UseDestinationArtifacts',
                     'UITargetAppPath','TestHostPath','TestBundlePath','DependentProductPaths'}
    meta=doc.get('__xctestrun_metadata__',{})
    if not isinstance(meta,dict) or type(meta.get('FormatVersion',1)) is not int or meta.get('FormatVersion',1) not in (1,2):
        raise ValueError('receipt-format')
    if set(doc)&known_overrides: raise ValueError('root-override')
    if meta.get('FormatVersion')==2:
        configs=doc.get('TestConfigurations')
        if not isinstance(configs,list) or len(configs)!=1 or not isinstance(configs[0],dict):
            raise ValueError('configuration')
        if set(configs[0])&known_overrides: raise ValueError('configuration-override')
    target=bind.one_target(doc)
    if (target.get('IsXCTRunnerHostedTestBundle',False) is not False or
        target.get('UITargetAppCommandLineArguments',[])!=[] or
        target.get('UITargetAppEnvironmentVariables',{})!={} or
        any(target.get(k,'')!='' for k in ('BaselinePath','UITargetAppBundleIdentifier',
                                          'TestLanguage','TestRegion')) or
        any(target.get(k,False) is not False for k in ('UITargetAppMainThreadCheckerEnabled',
                                                       'GatherLocalizableStringsData')) or
        target.get('TestExecutionOrdering','') not in ('','alphabetical')):
        raise ValueError('target-override')
    root='__TESTROOT__/'
    host=root+bind.APP_REL
    if target.get('TestHostPath') not in (host,root+bind.HOST_REL): raise ValueError('receipt-host')
    if target.get('TestHostBundleIdentifier',bind.APP_ID)!=bind.APP_ID: raise ValueError('receipt-host-id')
    if target.get('TestBundleIdentifier',bind.TEST_ID)!=bind.TEST_ID: raise ValueError('receipt-test-id')
    def choices(path):
        names={root+path}
        if path.startswith(bind.APP_REL+'/'):
            names.add('__TESTHOST__/'+path.removeprefix(bind.APP_REL+'/'))
        return names
    if sum(target.get('TestBundlePath') in choices(path) for path in approved)!=1:
        raise ValueError('receipt-test')
    dep_paths=target.get('DependentProductPaths',[])
    paths={host,root+bind.HOST_REL}
    for path in approved: paths.update(choices(path))
    if not isinstance(dep_paths,list) or any(x not in paths for x in dep_paths):
        raise ValueError('receipt-dependencies')
    defaults=target.get('EnvironmentVariables',{})
    if defaults not in ({},{'OS_ACTIVITY_DT_MODE':'YES'}):
        raise ValueError('scheme-environment')
    base='__TESTROOT__/Debug-iphonesimulator'
    xcode='__PLATFORMS__/iPhoneSimulator.platform/Developer'
    fixed={
        'DYLD_FRAMEWORK_PATH':{base,base+':'+xcode+'/Library/Frameworks'},
        'DYLD_LIBRARY_PATH':{base,base+':'+xcode+'/usr/lib'},
        'DYLD_INSERT_LIBRARIES':{xcode+'/usr/lib/libXCTestBundleInject.dylib'},
        'XCInjectBundleInto':{root+bind.HOST_REL,'__TESTHOST__/'+bind.APP},
        'XCInjectBundle':{target['TestBundlePath'],'__TESTBUNDLE__'},
    }
    env=target.get('TestingEnvironmentVariables',{})
    if (not isinstance(env,dict) or any(k not in fixed or not isinstance(v,str) or v not in fixed[k]
                                        for k,v in env.items())):
        raise ValueError('loader-environment')

def products(root,bind):
    if root.resolve(strict=True)!=root: raise ValueError('products-root')
    host=bind.exact(root,bind.HOST_REL)
    approved=[]
    for path in bind.APPROVED_BUNDLES:
        if (root/path).is_symlink() or (root/path).exists(): approved.append(path)
    if not approved: raise ValueError('test-missing')
    def validate(rel,name,bid,kind):
        info=bind.plist(bind.exact(root,rel+'/Info.plist'),65536)
        if (info.get('CFBundleExecutable'),info.get('CFBundleIdentifier'),
            info.get('CFBundlePackageType'))!=(name,bid,kind):
            raise ValueError('product-identity')
    validate(bind.APP_REL,bind.APP,bind.APP_ID,'APPL')
    for path in approved: validate(path,bind.TEST,bind.TEST_ID,'BNDL')
    return host,[bind.exact(root,path+'/'+bind.TEST) for path in approved],approved
