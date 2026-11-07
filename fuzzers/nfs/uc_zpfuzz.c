// Comprehensive -zp empirical UC fuzz: every uid501-openable UC, every selector,
// shape-varying (scalarInCnt 0..8 x structInSize set) with adversarial values.
// single-process (IOKit survives; fork breaks it) + per-call setitimer timeout+siglongjmp.
// Skips HW-destructive/display/security classes. Breadcrumb before each call (panic-attrib).
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/time.h>
#include <stdint.h>
#define MAXC 160
static char CLS[MAXC][128]; static int OTY[MAXC]; static int NC=0;
static const char* DANGER[]={"SMC","SEP","KeyStore","MobileFileIntegrity","PMU","Battery","Thermal","Charger",
 "Power","AES","Crypto","AppleS8000","PKE","NVRAM","EFI","DCPDP","DCPAV","Framebuffer","CLCD","Display",
 "HIDKeyboard","HIDTransport","Backlight","Wrangler",0};
static int danger(const char*c){for(int i=0;DANGER[i];i++)if(strstr(c,DANGER[i]))return 1;return 0;}
static const uint64_t SC[]={0,1,0xffffffffull,0x7fffffffull,0x80000000ull,0x100000000ull,0x4141414141414141ull,0xfffffff0ull};
enum{NSC=sizeof(SC)/sizeof(SC[0])};
static const size_t SI[]={0,8,16,24,32,0x38,0x48,0x80,0x100,0x400,0x1000};
enum{NSI=sizeof(SI)/sizeof(SI[0])};
static int CURFD=-1;
static void cur(const char*c,int oty,uint32_t sel,uint32_t sc,size_t si){if(CURFD<0)return;char b[400];int n=snprintf(b,sizeof b,"cls=%s oty=%d sel=%u sc=%u si=%zu t=%ld\n",c,oty,sel,sc,si,(long)time(0));lseek(CURFD,0,0);if(ftruncate(CURFD,0)){}if(write(CURFD,b,n)){}fsync(CURFD);}
static sigjmp_buf JB; static volatile sig_atomic_t INCALL=0;
static void onalrm(int s){(void)s;if(INCALL){INCALL=0;siglongjmp(JB,1);}}
static void arm(int ms){struct itimerval t={{0,0},{0,ms*1000}};setitimer(ITIMER_REAL,&t,0);}
static void dis(void){struct itimerval t={{0,0},{0,0}};setitimer(ITIMER_REAL,&t,0);}
#define TC(e) do{if(sigsetjmp(JB,1)==0){INCALL=1;arm(300);e;dis();INCALL=0;}else{INCALL=0;}}while(0)
int main(void){
  char cp[512];snprintf(cp,sizeof cp,"%s/nfs_uaf/uc_zpfuzz_cur.txt",getenv("HOME"));CURFD=open(cp,O_WRONLY|O_CREAT|O_TRUNC,0644);
  char lp[512];snprintf(lp,sizeof lp,"%s/uid501_openable_uc_27.txt",getenv("HOME"));
  FILE*f=fopen(lp,"r");char line[256];
  while(f&&fgets(line,sizeof line,f)&&NC<MAXC){char c[128];int t;if(sscanf(line," OPEN %127s type=%d",c,&t)==2&&!danger(c)){strncpy(CLS[NC],c,127);OTY[NC]=t;NC++;}}
  if(f)fclose(f);
  fprintf(stderr,"uc_zpfuzz: %d classes (after danger-skip)\n",NC);
  signal(SIGALRM,onalrm);
  unsigned char stin[4096],stout[4096];
  for(long rnd=0;;rnd++){
    for(int ci=0;ci<NC;ci++){
      io_iterator_t it=0; if(IOServiceGetMatchingServices(kIOMainPortDefault,IOServiceMatching(CLS[ci]),&it)!=0||!it)continue;
      io_service_t sv;
      while((sv=IOIteratorNext(it))){
        io_connect_t c=0; if(IOServiceOpen(sv,mach_task_self(),OTY[ci],&c)!=0||!c){IOObjectRelease(sv);continue;}
        for(uint32_t sel=0;sel<0x80;sel++){
          for(uint32_t sc=0;sc<=8;sc++){uint64_t si[16];for(uint32_t i=0;i<sc;i++)si[i]=SC[(sel+i+rnd)%NSC];uint64_t so[8];uint32_t oc=8;
            cur(CLS[ci],OTY[ci],sel,sc,0);TC(IOConnectCallMethod(c,sel,sc?si:NULL,sc,NULL,0,so,&oc,NULL,NULL));}
          for(int zi=0;zi<NSI;zi++){size_t s=SI[zi];if(s>sizeof stin)s=sizeof stin;if(s)memset(stin,(int)(0x41+rnd),s);
            uint64_t si2[2]={SC[rnd%NSC],SC[(rnd+1)%NSC]};size_t osz=sizeof stout;
            cur(CLS[ci],OTY[ci],sel,2,s);TC(IOConnectCallMethod(c,sel,si2,2,s?stin:NULL,s,NULL,NULL,stout,&osz));}
        }
        IOServiceClose(c);IOObjectRelease(sv);
      }
      IOObjectRelease(it);
    }
    fprintf(stderr,"uc_zpfuzz: round %ld complete (survived)\n",rnd);
  }
  return 0;
}
