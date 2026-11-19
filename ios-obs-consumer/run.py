"""Isolated job orchestration. Invoke with python3 -I; no package uploads."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
PIN='4af77ffa464a48307e5ff2d95f10b835919d205b'
TREE='3a03801beb18c9601630cc4421b95c2743018dfb'
ORIGIN='https://github.com/changyue1053/MadObs.git'
ROOT=Path(__file__).resolve().parents[1]
HERE=ROOT/'ios-obs-consumer'
class Failed(Exception): pass
def run(args, stage, cwd=None, env=None, timeout=1200):
    with tempfile.TemporaryFile() as output:
        try:
            subprocess.run(args,cwd=cwd,env=env,stdout=output,stderr=output,check=True,timeout=timeout,stdin=subprocess.DEVNULL)
            output.seek(0)
            value=output.read(2*1024*1024+1)
            if len(value)>2*1024*1024: raise Failed(stage)
            return value.decode('utf-8')
        except Exception: raise Failed(stage) from None
def main():
    if not sys.flags.isolated: raise Failed('python-isolation')
    if run(['uname','-m'],'host').strip()!='arm64': raise Failed('host')
    if run(['xcodebuild','-version'],'xcode').strip()!='Xcode 26.2\nBuild version 17C52': raise Failed('xcode')
    # Use runner CMake as in the approved MadObs iOS recipe; no tool provisioner.
    version=run(['cmake','--version'],'cmake').splitlines()[0]
    if not re.fullmatch(r'cmake version \d+\.\d+\.\d+',version): raise Failed('cmake')
    base=Path(os.environ['RUNNER_TEMP'])
    if base.is_symlink() or not base.is_dir(): raise Failed('temporary-root')
    base=base.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='madcrypto-obs-',dir=base) as temporary:
        work=Path(temporary)
        # Preparation only: anonymous exact public Git fetch, no inherited credentials/config.
        home=work/'git-home'; home.mkdir()
        clean={'PATH':os.environ['PATH'],'HOME':str(home),'GIT_CONFIG_NOSYSTEM':'1',
               'GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0'}
        obs=work/'obs-producer'; obs.mkdir()
        git=['git','-c','credential.helper=','-c','core.hooksPath=/dev/null']
        run(git+['init',str(obs)],'obs-init',env=clean)
        run(git+['remote','add','origin',ORIGIN],'obs-origin',cwd=obs,env=clean)
        run(git+['fetch','--depth=1','--no-tags','origin',PIN],'obs-fetch',cwd=obs,env=clean)
        run(git+['checkout','--detach','FETCH_HEAD'],'obs-checkout',cwd=obs,env=clean)
        for args,expected in [(['rev-parse','HEAD'],PIN),(['rev-parse','HEAD^{tree}'],TREE),(['remote','get-url','origin'],ORIGIN)]:
            if run(git+args,'obs-pin',cwd=obs,env=clean).strip()!=expected: raise Failed('obs-pin')
        # All network preparation is complete. Cargo is offline; Swift has only local binaries.
        run(['bash','ios-package-check/build.sh'],'crypto-package',cwd=ROOT)
        consumer=work/'consumer'
        shutil.copytree(ROOT/'ios-package-check/Consumer',consumer)
        shutil.copyfile(HERE/'Consumer/Package.swift',consumer/'Package.swift')
        shutil.copyfile(HERE/'Consumer/Tests/ConsumerTests/ObserverTests.swift',consumer/'Tests/ConsumerTests/ObserverTests.swift')
        artifacts=consumer/'Artifacts'; artifacts.mkdir()
        crypto=ROOT/'build/ios-package-check/MadCrypto.xcframework'
        shutil.move(str(crypto),artifacts/'MadCrypto.xcframework')
        # Remove producer outputs so consumer cannot silently link Rust build artifacts.
        shutil.rmtree(ROOT/'build/ios-package-check/rust')
        sdk=run(['xcrun','--sdk','iphonesimulator','--show-sdk-path'],'sdk').strip()
        if run(['xcrun','--sdk','iphonesimulator','--show-sdk-version'],'sdk').strip()!='26.2': raise Failed('sdk')
        sdk=Path(sdk)
        if not (sdk/'usr/include/zlib.h').is_file() or not (sdk/'usr/lib/libz.tbd').is_file(): raise Failed('sdk-zlib')
        build=work/'obs-build'; stage=work/'obs-stage'
        run(['cmake','-S',str(obs),'-B',str(build),'-G','Xcode',
             '-DCMAKE_SYSTEM_NAME=iOS','-DCMAKE_OSX_SYSROOT='+str(sdk),
             '-DCMAKE_OSX_ARCHITECTURES=arm64','-DCMAKE_OSX_DEPLOYMENT_TARGET=16.0',
             '-DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO','-DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED=NO',
             '-DCMAKE_INSTALL_PREFIX='+str(stage),'-DBUILD_TESTING=OFF','-DMADOBS_BUILD_RUNTIME=ON',
             '-DMADOBS_BUILD_SHARED=OFF','-DMADOBS_BUILD_JNI=OFF','-DMADOBS_PACKAGE_BORINGSSL=OFF',
             '-DIMOBS_SAN=','-DIMOBS_BORINGSSL_ROOT=','-DIMOBS_BORINGSSL_INCLUDE=','-DIMOBS_BORINGSSL_CRYPTO_LIB=',
             '-DZLIB_INCLUDE_DIR='+str(sdk/'usr/include'),'-DZLIB_LIBRARY='+str(sdk/'usr/lib/libz.tbd')],'obs-configure')
        run(['cmake','--build',str(build),'--config','Release','--target','imobs_core','--parallel','3'],'obs-build')
        run(['cmake','--install',str(build),'--config','Release'],'obs-install')
        relocated=work/'relocated-obs'; stage.rename(relocated)
        shutil.rmtree(obs); shutil.rmtree(build)
        archive=relocated/'lib/libmadobs_runtime.a'
        if run(['xcrun','lipo','-archs',str(archive)],'obs-architecture').strip()!='arm64': raise Failed('obs-architecture')
        headers=relocated/'include'
        (headers/'module.modulemap').write_text('module MadObs { header "madobs/runtime.h" export * }\n')
        run(['xcodebuild','-create-xcframework','-library',str(archive),'-headers',str(headers),'-output',str(artifacts/'MadObs.xcframework')],'obs-binary-package')
        shutil.rmtree(relocated)
        bridge=consumer/'Sources/QualificationBridge'; bridge.mkdir()
        inc=bridge/'include'; inc.mkdir()
        shutil.copyfile(HERE/'Bridge.h',inc/'Bridge.h')
        (inc/'module.modulemap').write_text('module QualificationBridge { header "Bridge.h" export * }\n')
        shutil.copyfile(HERE/'Bridge.cpp',bridge/'Bridge.cpp')
        shutil.copyfile(ROOT/'adapters/obs/madcrypto_obs.h',inc/'madcrypto_obs.h')
        run([sys.executable,'-I',str(HERE/'prepare.py'),str(ROOT/'tests/obs_adapter.c'),str(bridge/'fixture.c')],'fixture-prepare')
        # No physical-device action: the optional Obs package is simulator-only.
        runtime='com.apple.CoreSimulator.SimRuntime.iOS-26-2'
        runtimes=json.loads(run(['xcrun','simctl','list','runtimes','available','-j'],'sim-runtime'))
        if not any(r['identifier']==runtime and r['isAvailable'] for r in runtimes['runtimes']): raise Failed('sim-runtime')
        uuid=run(['xcrun','simctl','create','MadCrypto-Obs-Qualification','com.apple.CoreSimulator.SimDeviceType.iPhone-16',runtime],'sim-create').strip()
        if not re.fullmatch(r'[0-9A-Fa-f-]{36}',uuid): raise Failed('sim-id')
        try:
            run(['xcrun','simctl','boot',uuid],'sim-boot',timeout=120)
            run(['xcrun','simctl','bootstatus',uuid,'-b'],'sim-ready',timeout=180)
            derived=work/'derived'; result=work/'tests.xcresult'
            common=['xcodebuild','-scheme','MadCryptoPackageCheck','-destination','platform=iOS Simulator,id='+uuid,
                    '-destination-timeout','120','-derivedDataPath',str(derived),'-parallel-testing-enabled','NO',
                    '-disableAutomaticPackageResolution','ARCHS=arm64','ONLY_ACTIVE_ARCH=YES',
                    'CODE_SIGNING_ALLOWED=YES','CODE_SIGN_IDENTITY=-','CODE_SIGNING_REQUIRED=NO']
            run(common+['build-for-testing'],'consumer-link',cwd=consumer)
            spec=importlib.util.spec_from_file_location('qualified_artifacts',HERE/'artifacts.py')
            audit=importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
            products=derived/'Build/Products'
            try:
                manifest,binary=audit.identify(products)
                before=audit.snapshot(products)
                audit.verify_symbols(run(['xcrun','nm','-U','-j',str(binary)],'implementation-symbols'))
            except Exception: raise Failed('built-artifact-binding') from None
            if run(['xcrun','lipo','-archs',str(binary)],'test-architecture').strip()!='arm64': raise Failed('test-architecture')
            # Execute precisely the manifest built above, not scheme rediscovery.
            run(['xcodebuild','-xctestrun',str(manifest),'-destination','platform=iOS Simulator,id='+uuid,
                 '-destination-timeout','120','-parallel-testing-enabled','NO',
                 '-resultBundlePath',str(result),'test-without-building'],
                'consumer-tests',cwd=consumer)
            try:
                if audit.identify(products)!=(manifest,binary) or audit.snapshot(products)!=before:
                    raise Failed('artifact-changed')
            except Exception: raise Failed('artifact-changed') from None
            run([sys.executable,'-I',str(HERE/'results.py'),str(result)],'named-results')
        finally:
            failed=False
            for action in ['shutdown','delete']:
                try: run(['xcrun','simctl',action,uuid],'sim-cleanup',timeout=60)
                except Failed: failed=True
            if failed: raise Failed('sim-cleanup')
        print('PASS: isolated-ios-obs-three-tests')
if __name__=='__main__':
    try: main()
    except Failed as error:
        print('FAIL: '+str(error)); sys.exit(1)
    except Exception:
        print('FAIL: orchestration-input'); sys.exit(1)
