"""Bounded, allowlisted diagnostics for the existing owned simulator install."""
import os
import re
import selectors
import subprocess
import time

LIMIT=64*1024
TIMEOUT=90
RECORD=re.compile(rb'^\s*(An error was encountered processing the command|Underlying error) \(domain=([A-Za-z][A-Za-z0-9.]{0,80}), code=(-?[0-9]{1,8})\):?\s*$')
DOMAINS={
    b'IXUserPresentableErrorDomain':('ixui',frozenset({1,4,6})),
    b'IXErrorDomain':('ix',frozenset({1,2,13})),
    b'MIInstallerErrorDomain':('mi',frozenset({4,8,10,13,15,35})),
    b'com.apple.CoreSimulator.SimError':('sim',frozenset({1,2,146})),
    b'NSPOSIXErrorDomain':('posix',frozenset({2,13,22,28,60})),
}
def classify(data):
    if not isinstance(data,bytes) or len(data)>LIMIT: return 'output-limit'
    outer=[]; inner=[]
    for line in data.splitlines():
        if len(line)>512: continue
        match=RECORD.fullmatch(line)
        if not match: continue
        known=DOMAINS.get(match[2])
        if known is None: label='other-domain'
        else:
            name,allowed=known; code=int(match[3])
            label=name+'-'+str(code) if code in allowed else name+'-other-code'
        destination=outer if match[1].startswith(b'An error ') else inner
        destination.append(label)
    if len(outer)!=1: return 'no-domain' if not outer else 'ambiguous-domain'
    underlying='none' if not inner else inner[0] if len(set(inner))==1 else 'mixed'
    return 'outer-'+outer[0]+'-inner-'+underlying

def invoke(args,timeout=TIMEOUT,limit=LIMIT):
    """Return None on success, otherwise a fixed label. No retries or raw logs."""
    try:
        proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    except OSError: return 'start'
    def stop(label):
        try: proc.kill()
        except ProcessLookupError: pass
        return label
    deadline=time.monotonic()+timeout
    try:
        with proc, selectors.DefaultSelector() as poll:
            try:
                poll.register(proc.stdout,selectors.EVENT_READ)
                data=bytearray()
                while True:
                    remaining=deadline-time.monotonic()
                    if remaining<=0 or not poll.select(remaining): return stop('timeout')
                    block=os.read(proc.stdout.fileno(),min(4096,limit-len(data)+1))
                    if not block: break
                    data.extend(block)
                    if len(data)>limit: return stop('output-limit')
                rc=proc.wait(timeout=max(0,deadline-time.monotonic()))
                if rc==0: return None
                if rc<0: return 'signal'
                return classify(bytes(data))
            except subprocess.TimeoutExpired: return stop('timeout')
            except Exception: return stop('capture')
    except Exception: return 'capture'
