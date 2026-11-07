#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#define SC 246
static uint32_t s=0x246246; static uint32_t xs(){s^=s<<13;s^=s>>17;s^=s<<5;return s;}
int main(int argc,char**argv){
  long iters=argc>1?atol(argv[1]):3000000; if(argc>2)s=strtoul(argv[2],0,0);
  uint8_t rec[0x50]; long pass=0;
  uint32_t smallpool[]={0,1,2,3,4,5}; // bias index/mode-ish fields small to satisfy bounded checks
  for(long i=0;i<iters;i++){
    for(int j=0;j<0x50;j+=4)*(uint32_t*)(rec+j)=xs();
    // bias the first few 4-byte fields (likely magic/mode/index) toward small values sometimes
    if(i&1){ rec[0]=xs()&0xff; *(uint32_t*)(rec+4)=smallpool[xs()%6]; *(uint32_t*)(rec+8)=smallpool[xs()%6]; }
    errno=0; long r=syscall(SC,(uintptr_t)rec); int e=errno;
    if(!(r==-1 && e==22)){ pass++; if(pass<=40) printf("PASS i=%ld r=%ld e=%d(%s) rec0=%08x f4=%08x f8=%08x\n",i,r,e,strerror(e),*(uint32_t*)rec,*(uint32_t*)(rec+4),*(uint32_t*)(rec+8)); }
    if((i%500000)==0){printf("[*] %ld iters, pass=%ld (alive)\n",i,pass);fflush(stdout);}
  }
  printf("[*] done %ld iters, pass(non-EINVAL)=%ld\n",iters,pass);
  return 0;
}
