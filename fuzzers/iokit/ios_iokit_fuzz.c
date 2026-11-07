// Runs ON the iPhone (sideloaded). Fuzzes app-sandbox-reachable iOS IOKit user clients from N threads
// (UAF/race/type-confusion — the -fbounds-safety-immune classes). A kernel panic = the signal,
// captured in the device's panic log (Settings>Privacy>Analytics, or via Console.app paired to the Mac).
#include <IOKit/IOKitLib.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
// iOS app-sandbox-reachable clients (NOT on macOS — the fresh surface): GPU(AGX), the ISP/camera, ANE,
// the codec engines, IOSurface, the sensor/HID, AppleKeyStore. Refine on-device with `ioreg`.
static const char* SVCS[]={"IOSurfaceRootUserClient","AGXDeviceUserClient","AppleH13CamIn","AppleH16CamIn",
 "H11ANEInDirectPathClient","IOMobileFramebufferUserClient","AppleJPEGDriverUserClient","AppleAVE2UserClient",
 "AppleM2ScalerCSCDriver","IOAccelContext2","AppleCLCD","AppleKeyStoreUserClient",0};
static volatile io_connect_t sh[16];
static void* w(void* a){ long id=(long)a;
  for(;;){ int n=0; while(SVCS[n])n++; int si=arc4random()%n;
    io_service_t s=IOServiceGetMatchingService(kIOMasterPortDefault,IOServiceMatching(SVCS[si]));
    if(s){ io_connect_t cn; if(IOServiceOpen(s,mach_task_self(),arc4random()%8,&cn)==0){ sh[id%16]=cn;
      for(int r=0;r<16;r++){ io_connect_t v=sh[arc4random()%16]; if(!v)continue;
        unsigned long long in[16],out[16]; unsigned int no=16; char si2[4096],so[4096]; size_t sol=4096;
        for(int k=0;k<16;k++)in[k]=((unsigned long long)arc4random()<<32)|arc4random(); arc4random_buf(si2,sizeof si2);
        IOConnectCallMethod(v,arc4random()%256,in,arc4random()%16,si2,arc4random()%4096,out,&no,so,&sol); }
      if(arc4random()%2){IOServiceClose(cn); sh[id%16]=0;} } IOObjectRelease(s);} } return 0; }
int main(){ pthread_t t[24]; for(long i=0;i<24;i++)pthread_create(&t[i],0,w,(void*)i);
  for(;;){sleep(60);fprintf(stderr,"alive\n");} }
