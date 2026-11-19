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
                       'destination','preparation','xcode-error'})
def early(line):
    lower=line.lower()
    if b'error:' not in lower: return None
    groups=(
        ('binary-artifact',(b'binary target',b'binary artifact',b'xcframework',b'artifact of downloaded binary')),
        ('package-product',(b'product ',b'package product')),
        ('package-target',(b'target ',b'package manifest',b'package.swift',b'no manifest')),
        ('build-lock',(b'locked',b'lock file',b'concurrent build',b'build database')),
        ('destination',(b'destination',b'simulator',b'eligible devices')),
        ('preparation',(b'build description',b'build service',b'pif transfer',b'workspace',b'scheme')),
    )
    for code,needles in groups:
        if any(needle in lower for needle in needles): return code
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
