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

# Scan bounded records across the log rather than dropping its middle. These
# bounds cap bytes, regex input length and record count; no raw record is returned.
SCAN_BYTES=8*1024*1024
SCAN_RECORDS=20000
LINE_BYTES=8192
PHASES=frozenset({'none','package','prepare','scan','compile-c','compile-swift','link','sign'})
EARLY_CODES=frozenset({'binary-artifact','package-product','package-target','build-lock',
                       'destination-ineligible','sdk-unavailable','test-configuration',
                       'multiple-producers','input-missing','preparation','xcode-error'})
def early(line):
    lower=line.lower()
    if b'error:' not in lower: return None
    # Match diagnostic phrases, never a bare simulator/destination path token.
    patterns=(
        ('multiple-producers', rb'multiple commands produce'),
        ('input-missing', rb'build input files? cannot be found|unable to open (?:input )?file'),
        ('destination-ineligible', rb'unable to find a destination matching|ineligible destinations|destination [^\r\n]{0,128} is not eligible|requested device could not be found'),
        ('sdk-unavailable', rb'\bsdk [^\r\n]{0,128}(?:cannot be located|not found|is not installed)|(?:ios|iphonesimulator) [0-9.]+ is not installed'),
        ('test-configuration', rb'scheme [^\r\n]{0,256}(?:not configured|not currently configured|does not support)[^\r\n]{0,64}test|cannot test target|test host [^\r\n]{0,128}(?:missing|not found)'),
        ('binary-artifact', rb'binary (?:target|artifact) [^\r\n]{0,256}(?:could not|cannot|not found|missing|not supported)|no library for this platform|xcframework [^\r\n]{0,128}(?:invalid|missing|not found)'),
        ('package-product', rb'(?:package )?product [^\r\n]{0,128}(?:not found|missing|not available|requires)'),
        ('package-target', rb'target [^\r\n]{0,128}(?:not found|missing)|invalid manifest|manifest parse error'),
        ('build-lock', rb'build database [^\r\n]{0,128}locked|database is locked|concurrent build|unable to acquire [^\r\n]{0,128}lock'),
        ('preparation', rb'could not create build description|unable to initiate pif transfer|build service [^\r\n]{0,128}(?:failed|unavailable)'),
    )
    for code,pattern in patterns:
        if re.search(pattern,lower): return code
    return 'xcode-error'
def phase(line):
    line=line.lstrip()
    prefixes=((b'Resolve Package Graph','package'),(b'ComputePackage','package'),
              (b'CreateBuildDescription','prepare'),(b'PreparePackages','prepare'),
              (b'ScanDependencies ','scan'),(b'CompileC ','compile-c'),
              (b'SwiftCompile ','compile-swift'),(b'SwiftEmitModule ','compile-swift'),
              (b'Ld ','link'),(b'CodeSign ','sign'))
    for prefix,value in prefixes:
        if line.startswith(prefix): return value
    return None
def scan(stream):
    stream.seek(0,2)
    total=stream.tell()
    stream.seek(0)
    consumed=records=0
    truncated=total>SCAN_BYTES
    current='none'
    reason='other'
    while consumed<min(total,SCAN_BYTES) and records<SCAN_RECORDS:
        budget=min(LINE_BYTES,SCAN_BYTES-consumed)
        line=stream.readline(budget)
        if not line: break
        consumed+=len(line); records+=1
        # A split line is never independently interpreted as a command or error.
        if len(line)==budget and not line.endswith(b'\n') and consumed<total:
            truncated=True
            while consumed<min(total,SCAN_BYTES) and records<SCAN_RECORDS:
                fragment=stream.readline(min(LINE_BYTES,SCAN_BYTES-consumed))
                if not fragment: break
                consumed+=len(fragment); records+=1
                if fragment.endswith(b'\n'): break
            continue
        current=phase(line) or current
        found=classify(line)
        if found=='other': found=early(line) or 'other'
        if reason in ('other','xcode-error') and found!='other': reason=found
    if consumed<total: truncated=True
    if reason not in CODES|EARLY_CODES: reason='other'
    if current not in PHASES: current='none'
    return reason,current,'truncated' if truncated else 'complete'
