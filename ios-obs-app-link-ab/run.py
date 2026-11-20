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
HOSTED=ROOT/'ios-obs-hosted'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod
def module(name,file): return load(name,HOSTED/file)
AB=ROOT/'ios-obs-app-link-ab'
baseline=load('frozen_hosted_runner',HOSTED/'run.py')
run=baseline.run
Failed=baseline.Failed

def isolated_build(args,cwd):
    # Deliberately do not read native output. Distinguish a normal nonzero
    # tool exit from timeout/start/signal, all of which are inconclusive.
    result=subprocess.run(args,cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,timeout=1200)
    if result.returncode<0: raise ValueError('build-signal')
    return result.returncode==0

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
        hosted=module('hosted_project','project.py')
        hosted.create(consumer)
        artifacts=consumer/'Inputs'
        artifacts.mkdir()
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
        spec=importlib.util.spec_from_file_location('qualified_preexecution',HERE/'preexecution.py')
        pre=importlib.util.module_from_spec(spec); spec.loader.exec_module(pre)
        obs_archive=artifacts/'libmadobs_runtime.a'
        crypto_archive=artifacts/'libmadcrypto_ffi.a'
        try:
            fingerprints=pre.relocate_obs(relocated,obs_archive,artifacts/'ObsHeaders')
            source=pre.simulator_slice(artifacts/'MadCrypto.xcframework')
            headers=artifacts/'CryptoHeaders'; headers.mkdir()
            for source_file,destination in ((source,crypto_archive),
                    (source.parent/'Headers/madcrypto.h',headers/'madcrypto.h')):
                if source_file.resolve(strict=True)!=source_file or not source_file.is_file():
                    raise ValueError('installed-file')
                fingerprints[destination]=pre.digest(source_file)
                shutil.copyfile(source_file,destination)
            pre.verify_inputs(fingerprints)
        except Exception: raise Failed('installed-simulator-slice') from None
        shutil.rmtree(relocated)
        shutil.rmtree(artifacts/'MadCrypto.xcframework')
        for library in (crypto_archive,obs_archive):
            if run(['xcrun','lipo','-archs',str(library)],'installed-simulator-architecture').strip()!='arm64':
                raise Failed('installed-simulator-architecture')
        print('PASS: installed-simulator-slices')
        # Owned destination is never booted; no test or app is launched.
        runtime='com.apple.CoreSimulator.SimRuntime.iOS-26-2'
        runtimes=json.loads(run(['xcrun','simctl','list','runtimes','available','-j'],'sim-runtime'))
        if not any(r['identifier']==runtime and r['isAvailable'] for r in runtimes['runtimes']): raise Failed('sim-runtime')
        uuid=run(['xcrun','simctl','create','MadCrypto-Obs-Link-AB','com.apple.CoreSimulator.SimDeviceType.iPhone-16',runtime],'sim-create').strip()
        if not re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',uuid): raise Failed('sim-id')
        try:
            control=load('controlled_link',AB/'controlled.py')
            bind=module('hosted_binding','binding.py')
            audit=load('qualification_artifacts',HERE/'artifacts.py')
            derived=work/'derived'
            products=derived/'Build/Products'
            project=['xcodebuild','-project',hosted.APP+'.xcodeproj']
            dest=['-destination','platform=iOS Simulator,id='+uuid,'-destination-timeout','120',
                  '-derivedDataPath',str(derived),'-configuration','Debug']
            def cmd(phase): return project+['-scheme','Diagnostic-'+phase]+dest
            control.install(hosted,consumer,'app')
            try: pre.destination(run(project+['-scheme','Diagnostic-app','-showdestinations'],'ab-destination-query',cwd=consumer),uuid)
            except Exception: raise Failed('ab-destination-eligibility') from None
            try: app_ok=isolated_build(cmd('app')+['build'],consumer)
            except Exception: raise Failed('ab-app-inconclusive') from None
            if not app_ok: raise Failed('ab-app-only-build')
            def app_identity():
                host=bind.exact(products,bind.HOST_REL)
                meta=bind.plist(bind.exact(products,bind.APP_REL+'/Info.plist'),65536)
                if (meta.get('CFBundleExecutable'),meta.get('CFBundleIdentifier'),meta.get('CFBundlePackageType'))!=(bind.APP,bind.APP_ID,'APPL'):
                    raise ValueError('app-plist')
                if run(['xcrun','lipo','-archs',str(host)],'ab-app-architecture').strip()!='arm64':
                    raise ValueError('app-architecture')
                bind.verify_platform(run(['xcrun','otool','-l',str(host)],'ab-app-platform'))
                run(['/usr/bin/codesign','--verify','--strict',str(host.parent)],'ab-app-signature')
                defined=set(run(['xcrun','nm','-U','-j',str(host)],'ab-app-nm').splitlines())
                if not (audit.REQUIRED|bind.EXPORTS)<=defined: raise ValueError('app-symbols')
                return host,audit.fingerprint(host.parent)
            try:
                pre.verify_inputs(fingerprints)
                host,before=app_identity()
            except Exception: raise Failed('ab-app-proof') from None
            print('PASS: ab-app-signed-linked')
            control.install(hosted,consumer,'test')
            try:
                control.test_settings(run(cmd('test')+['-showBuildSettings','-json'],'ab-test-settings',cwd=consumer),
                                      host,bind.TEST)
                test_ok=isolated_build(cmd('test')+['build'],consumer)
                pre.verify_inputs(fingerprints)
                if app_identity()!=(host,before): raise ValueError('app-delta')
            except Exception: raise Failed('ab-test-inconclusive') from None
            if not test_ok: raise Failed('ab-test-only-build')
            try:
                checked,test,relative=bind.products(products)
                if checked!=host or run(['xcrun','lipo','-archs',str(test)],'ab-test-architecture').strip()!='arm64':
                    raise ValueError('test-product')
                bind.verify_platform(run(['xcrun','otool','-l',str(test)],'ab-test-platform'))
                run(['/usr/bin/codesign','--verify','--strict',str(test.parent)],'ab-test-signature')
                bind.verify_linkage(run(['xcrun','nm','-U','-j',str(host)],'ab-app-nm'),
                    run(['xcrun','nm','-U','-j',str(test)],'ab-test-nm-defined'),
                    run(['xcrun','nm','-u','-j',str(test)],'ab-test-nm-undefined'),audit.REQUIRED)
            except Exception: raise Failed('ab-test-inconclusive') from None
            print('PASS: ab-test-only-build-signed-app-unchanged')
        finally:
            run(['xcrun','simctl','delete',uuid],'ab-sim-delete',timeout=60)

if __name__=='__main__':
    try: main()
    except Failed as error:
        print('FAIL: '+str(error)); sys.exit(1)
    except Exception:
        print('FAIL: ab-orchestration'); sys.exit(1)
