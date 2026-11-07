import subprocess, os, sys, random, signal
base_cookie = open(sys.argv[1],'rb').read()
ch = sys.argv[2]
env = dict(os.environ)
env['DYLD_INSERT_LIBRARIES']='/usr/lib/libgmalloc.dylib'
env['MALLOC_PROTECT_BEFORE']=sys.argv[3] if len(sys.argv)>3 else '0'
env['MALLOC_FILL_SPACE']='1'
env['MallocScribble']='1'
crashes=[]
def run(data):
    open('cur.kuki','wb').write(data)
    try:
        p=subprocess.run(['./harness','cur.kuki',ch],env=env,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        return p.returncode
    except subprocess.TimeoutExpired:
        return 'TIMEOUT'
# 1) single-bit flips
n=0
for byte in range(len(base_cookie)):
    for bit in range(8):
        d=bytearray(base_cookie); d[byte]^=(1<<bit)
        rc=run(bytes(d)); n+=1
        if rc not in (0,1) :  # 0 ok, 1 = clean reject
            print("CRASH/anom bitflip byte=%d bit=%d rc=%r"%(byte,bit,rc)); crashes.append(('bit',byte,bit,rc))
print("single-bit flips done: %d runs, %d anomalies"%(n,len(crashes)))
# 2) byte set to extreme values (targeting count/offset fields)
for byte in range(len(base_cookie)):
    for val in (0xff,0x7f,0x80,0xfe,0xc0):
        d=bytearray(base_cookie); d[byte]=val
        rc=run(bytes(d)); n+=1
        if rc not in (0,1):
            print("CRASH/anom byteset byte=%d val=%#x rc=%r"%(byte,val,rc)); crashes.append(('set',byte,val,rc))
print("byte-set done: total %d runs, %d anomalies"%(n,len(crashes)))
