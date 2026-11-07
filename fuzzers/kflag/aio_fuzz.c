// aio_readv/writev (syscall 246/247, new-in-27) stateful fuzzer: vectored iovec + async-lifecycle UAF.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <aio.h>
#include <sys/uio.h>
#include <sys/event.h>
#include <sys/mman.h>
#define RDV 246
#define WRV 247
// raw 0x50 aiocb: [0x00]fd(int) [0x08]off(s64) [0x10]iov(ptr) [0x18]iovcnt(s64) [0x28]sigev_notify(int)
#define PFD(r)  (*(int*)((r)+0x00))
#define POFF(r) (*(int64_t*)((r)+0x08))
#define PIOV(r) (*(void**)((r)+0x10))
#define PCNT(r) (*(int64_t*)((r)+0x18))
#define PNOT(r) (*(int*)((r)+0x28))
#define PSIG(r) (*(int*)((r)+0x2c))
#define PVAL(r) (*(uint64_t*)((r)+0x30))

static uint32_t s=0xa10a10; static uint32_t xs(){s^=s<<13;s^=s>>17;s^=s<<5;return s;}
#define N 64
static uint8_t recs[N][0x50];
static struct iovec ivs[N][8];
static char bufs[N][512];
static int inflight[N], fds[N], kq;
static uint64_t POOL[]={0,1,2,8,0x200,0x1000,0x7fffffff,0x80000000,0xffffffff,
  0x100000000ULL,0xffffffffffffffffULL,0x7fffffffffffffffULL};
int main(int argc,char**argv){
  long iters=argc>1?atol(argv[1]):20000000; if(argc>2)s=strtoul(argv[2],0,0);
  kq=kqueue();
  for(int i=0;i<N;i++){ fds[i]=open("/etc/hosts",O_RDONLY); inflight[i]=0; }
  void* gb=mmap(NULL,0x2000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  mprotect((char*)gb+0x1000,0x1000,PROT_NONE);
  for(long it=0;it<iters;it++){
    int i=xs()%N; uint8_t* r=recs[i];
    if(inflight[i] && (xs()&3)){
      if(xs()&1){ struct aiocb* a=(struct aiocb*)r; aio_error(a); aio_return(a); }
      else { close(fds[i]); fds[i]=open("/etc/hosts",O_RDONLY); }  // close-while-inflight race
      inflight[i]=0; continue;
    }
    memset(r,0,0x50);
    PFD(r) = (xs()&7)? fds[i] : (int)POOL[xs()%12];
    POFF(r)= (xs()&1)? 0 : (int64_t)POOL[xs()%12];
    int nv=1+(xs()%8);
    for(int v=0;v<nv;v++){
      ivs[i][v].iov_base=(xs()&7)? bufs[i] : (void*)((char*)gb+0x1000-(xs()%64));
      ivs[i][v].iov_len =(xs()&3)? (xs()%256) : POOL[xs()%12];
    }
    PIOV(r)=ivs[i];
    PCNT(r)=(xs()&7)? nv : (int64_t)POOL[xs()%12];
    int mode=xs()%4; PNOT(r)=(mode==0)?0:(mode==1)?1:(mode==2)?3:7;
    if(PNOT(r)==3){ PSIG(r)=kq; PVAL(r)=xs(); }
    long rr=syscall((xs()&1)?WRV:RDV,(uintptr_t)r);
    if(rr==0) inflight[i]=1;
    if((it%1000000)==0){ printf("[*] %ld iters alive (s=0x%x)\n",it,s); fflush(stdout); }
  }
  printf("[*] done %ld, no panic\n",iters); return 0;
}
