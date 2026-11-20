"""Adapt the reviewed binary-consumer project, without a second SDK link."""
from pathlib import Path
import shutil

HERE=Path(__file__).resolve().parent

def create(hosted, out):
    hosted.create(out)
    refs=hosted.document()
    objects=refs['objects']; ref=hosted.ident
    # Reuse the exact same app archive/framework inputs and test loader.
    # Disable the stock Debug dylib redirection to keep code in the executable.
    objects[ref(70)]['buildSettings']['ENABLE_DEBUG_DYLIB']='NO'
    del objects[ref(71)]['buildSettings']['EXPORTED_SYMBOLS_FILE']
    del objects[ref(72)]['buildSettings']['SWIFT_OBJC_BRIDGING_HEADER']
    objects[ref(72)]['buildSettings']['CLANG_CXX_LANGUAGE_STANDARD']='c++17'
    objects[ref(14)].update(path='Tests/CohostTests.mm',lastKnownFileType='sourcecode.cpp.objcpp')
    objects[ref(2)]['children'].remove(ref(15))
    objects[ref(42)]['files'].remove(ref(25))
    del objects[ref(15)]; del objects[ref(25)]
    objects[ref(16)]=dict(isa='PBXFileReference',path='App/Driver.mm',lastKnownFileType='sourcecode.cpp.objcpp',sourceTree='<group>')
    objects[ref(26)]=dict(isa='PBXBuildFile',fileRef=ref(16))
    objects[ref(2)]['children'].append(ref(16))
    objects[ref(40)]['files'].append(ref(26))
    for old in ('PackageTests.swift','ObserverTests.swift','Entries.h'):
        (out/'Tests'/old).unlink()
    (out/'App/Exports.txt').unlink()
    shutil.copyfile(HERE/'Driver.mm',out/'App/Driver.mm')
    shutil.copyfile(HERE/'CohostTests.mm',out/'Tests/CohostTests.mm')
    (out/(hosted.APP+'.xcodeproj')/'project.pbxproj').write_text('// !$*UTF8*$!\n'+hosted.serialize(refs)+'\n')
    return refs
