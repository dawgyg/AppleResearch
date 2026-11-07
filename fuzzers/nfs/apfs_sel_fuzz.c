// Empirical -zp fuzz of uid501-open AppleAPFSUserClient selectors on MY container only
// (identified via DeltaCreatePrepare success). Adversarial structIn per selector shape.
#include <IOKit/IOKitLib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
struct S{uint32_t sel;uint32_t insz;uint32_t outsz;};
// uid501-open selectors (VAR->use 0x1000). Delta 36-40,49 excluded (done).
static struct S SS[]={
 {1,4,0},{2,8,16},{3,0,0},{4,0,4},{6,0,1224},{7,4,16},{8,0,0},{9,8,2},
 {13,24,0x1000},{14,8,0x1000},{19,4,2},{20,48,0},{21,48,0},{23,0,4},{25,4,4},
 {28,4,24},{29,0,280},{30,4,272},{31,1,280},{32,20,8},{33,0,0},{34,0,8},
 {41,0x400,16},{42,16,0},{43,8,16},{44,17,0x1000},{45,17,0x1000},{46,8,408},
 {54,24,0},{55,4,8},{56,4,3},{61,0,8},{64,56,8},{65,4,0},{67,4,0},{68,8,1},
 {69,4,144},{70,24,0},{71,16,16},{75,24,0x1000},{76,48,16},{79,8,0}};
enum{NS=sizeof(SS)/sizeof(SS[0])};
static const uint64_t PAT[]={0,0xffffffffffffffffULL,0x4141414141414141ULL,0xffffffffULL,0x80000000ULL,0x100000000ULL,0x1000ULL};
enum{NPAT=sizeof(PAT)/sizeof(PAT[0])};
static int CUR=-1; static void bc(const char*s){if(CUR<0)return;lseek(CUR,0,0);ftruncate(CUR,0);write(CUR,s,strlen(s));fsync(CUR);}
static int prep(io_connect_t c,void*b){unsigned char in[48];memset(in,0,48);*(uint64_t*)in=(uint64_t)b;*(uint32_t*)(in+8)=0x20000;unsigned char o[16];size_t z=16;return IOConnectCallStructMethod(c,36,in,48,o,&z);}
int main(int argc,char**argv){
  long rounds=argc>1?atol(argv[1]):20;
  char cp[256]; snprintf(cp,sizeof cp,"%s/nfs_uaf/apfs_fire_cur.txt",getenv("HOME")); CUR=open(cp,O_WRONLY|O_CREAT|O_TRUNC,0644);
  size_t BS=0x20000; void*pb=mmap(0,BS,3,MAP_ANON|MAP_PRIVATE,-1,0);
  io_service_t mysvc=0; io_iterator_t it=0; IOServiceGetMatchingServices(kIOMainPortDefault,IOServiceMatching("AppleAPFSContainer"),&it);
  io_service_t sv;
  while((sv=IOIteratorNext(it))){io_connect_t c=0;if(IOServiceOpen(sv,mach_task_self(),0,&c)==0){if(prep(c,pb)==0){IOConnectCallStructMethod(c,49,NULL,0,NULL,NULL);IOServiceClose(c);mysvc=sv;break;}IOServiceClose(c);}IOObjectRelease(sv);}
  IOObjectRelease(it);
  if(!mysvc){printf("no container\n");return 1;}
  printf("fuzzing %d uid501 selectors x %ld rounds on MY container\n",NS,rounds);
  unsigned char in[0x1000],out[0x1000];
  for(long r=0;r<rounds;r++){
    for(int s=0;s<NS;s++){
      for(int p=0;p<NPAT;p++){
        io_connect_t c=0; if(IOServiceOpen(mysvc,mach_task_self(),0,&c)!=0) continue;
        uint32_t isz=SS[s].insz; if(isz>sizeof in) isz=sizeof in;
        for(uint32_t j=0;j+8<=isz;j+=8) *(uint64_t*)(in+j)=PAT[p];
        for(uint32_t j=(isz/8)*8;j<isz;j++) in[j]=(unsigned char)PAT[p];
        size_t osz=SS[s].outsz; if(osz>sizeof out) osz=sizeof out;
        char m[96]; snprintf(m,sizeof m,"r=%ld sel=%u pat=%d insz=%u\n",r,SS[s].sel,p,isz); bc(m);
        IOConnectCallStructMethod(c,SS[s].sel, isz?in:NULL, isz, osz?out:NULL, osz?&osz:NULL);
        IOServiceClose(c);
      }
    }
    if((r%5)==0) fprintf(stderr,"round %ld\n",r);
  }
  printf("done (no panic)\n"); return 0;
}
