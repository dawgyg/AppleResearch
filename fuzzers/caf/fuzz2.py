import subprocess,os,sys,random,signal
base=bytearray(open('out6.caf.kuki','rb').read())
env=dict(os.environ); env['DYLD_INSERT_LIBRARIES']='/usr/lib/libgmalloc.dylib'
env['MALLOC_PROTECT_BEFORE']='0'
random.seed(1234)
crashes=0; runs=0; dos=0
def run(data):
    open('f2.kuki','wb').write(bytes(data))
    try:
        p=subprocess.run(['./harness','f2.kuki','6'],env=env,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        return p.returncode
    except subprocess.TimeoutExpired: return 'TO'
N=int(sys.argv[1]) if len(sys.argv)>1 else 3000
for i in range(N):
    d=bytearray(base)
    k=random.randint(1,6)
    for _ in range(k):
        pos=random.randrange(len(d)); d[pos]=random.randrange(256)
    rc=run(d); runs+=1
    if rc=='TO': dos+=1
    elif rc<0:  # killed by signal => potential OOB crash
        crashes+=1
        open('crash_%d.kuki'%i,'wb').write(bytes(d))
        print("SIGNAL rc=%d i=%d"%(rc,i),flush=True)
    if runs%500==0: print("...%d runs, %d dos(timeout), %d signal-crashes"%(runs,dos,crashes),flush=True)
print("DONE %d runs, %d DoS-timeouts, %d signal-crashes"%(runs,dos,crashes))
