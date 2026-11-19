"""Category-only Xcode diagnostics. Input bytes never leave this classifier."""
import re
LIMIT=1024*1024
CODES=frozenset({'header-missing','module-definition','module-import','undefined-symbol',
                'duplicate-symbol','library-missing','platform-mismatch','signing',
                'package-resolution','swift-compile','c-compile','other'})
def classify(data):
    if not isinstance(data,bytes) or len(data)>LIMIT: return 'other'
    patterns=(
        ('header-missing',rb"fatal error: [^\r\n]{1,512} file not found"),
        ('module-definition',rb"(?:error: [^\r\n]{0,256}module map|error: redefinition of module)"),
        ('module-import',rb"(?:error: no such module |error: could not build (?:Objective-C |C )?module |error: module [^\r\n]{1,128} not found)"),
        ('undefined-symbol',rb'(?:Undefined symbols for architecture|ld: undefined symbols)'),
        ('duplicate-symbol',rb'(?:duplicate symbol |duplicate symbols for architecture)'),
        ('library-missing',rb'(?:ld: library not found for |ld: framework not found |library [^\r\n]{1,128} not found)'),
        ('platform-mismatch',rb'(?:building for [^\r\n]{1,256}but linking|does not contain the architecture|incompatible architecture)'),
        ('signing',rb'(?:CodeSign [^\r\n]+failed|error: [^\r\n]{0,256}(?:provisioning profile|code signing|signing certificate))'),
        ('package-resolution',rb'(?:Could not resolve package dependencies|error: [^\r\n]{0,128}Package.swift)'),
        ('swift-compile',rb'(?:SwiftCompile[^\r\n]*\n[\s\S]{0,4096}?error:|\.swift:\d+:\d+: error:)'),
        ('c-compile',rb'\.(?:c|cc|cpp|h|hpp):\d+:\d+: (?:fatal )?error:'),
    )
    for code,pattern in patterns:
        if re.search(pattern,data,re.IGNORECASE): return code
    return 'other'
def bounded_read(stream):
    stream.seek(0,2)
    size=stream.tell()
    stream.seek(0)
    if size<=LIMIT: return stream.read(LIMIT)
    head=stream.read(LIMIT//2)
    stream.seek(-LIMIT//2,2)
    return head+stream.read(LIMIT//2)
