// image4_struct_fuzz.c — content-fuzz Image4UserClient sel 5 (40B struct in) and sel 7 (24B struct in).
// These reach the handler with structIn-only shapes; fields are likely length/offset/tag -> hunt OOB/panic.
// Build: clang -O2 -framework IOKit -framework CoreFoundation -o image4_struct_fuzz image4_struct_fuzz.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <IOKit/IOKitLib.h>

static io_connect_t openc(void){
    io_service_t s=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("Image4"));
    if(!s){fprintf(stderr,"no svc\n");return 0;}
    io_connect_t c=0; kern_return_t kr=IOServiceOpen(s,mach_task_self(),0,&c);
    IOObjectRelease(s);
    if(kr){fprintf(stderr,"open kr=0x%x\n",kr);return 0;}
    return c;
}

static uint32_t s_state=0x12345678;
static uint32_t xs(void){ s_state^=s_state<<13; s_state^=s_state>>17; s_state^=s_state<<5; return s_state; }

// interesting 64-bit values to slot into fields
static uint64_t POOL[] = {0,1,2,8,0x10,0x40,0x100,0x1000,0x10000,0x100000,
    0x7fffffff,0x80000000,0xffffffff,0x100000000ULL,0xffffffffffffffffULL,
    0xfffffe0000000000ULL,0xdeadbeefdeadbeefULL,0x4141414141414141ULL};
static const int NP=sizeof(POOL)/sizeof(POOL[0]);

static void call(io_connect_t c,uint32_t sel,uint8_t*in,size_t insz){
    uint64_t sout[8]={0}; uint32_t soc=1;
    kern_return_t kr=IOConnectCallMethod(c,sel,NULL,0,in,insz,sout,&soc,NULL,NULL);
    // only print non-routine returns
    if(kr!=0 && kr!=0xe00002bd && kr!=0xe00002c2 && kr!=0xe00002bc){
        printf("sel %u insz %zu kr=0x%x sout0=0x%llx\n",sel,insz,kr,(unsigned long long)sout[0]);
    }
}

int main(int argc,char**argv){
    io_connect_t c=openc(); if(!c)return 1;
    long iters = argc>1?atol(argv[1]):2000000;
    if(argc>2) s_state=(uint32_t)strtoul(argv[2],0,0);

    struct { uint32_t sel; size_t sz; } shapes[]={{5,40},{7,24}};

    // phase 1: single-field extremes (each 8-byte slot = each pool value, rest zero)
    for(int sh=0;sh<2;sh++){
        uint32_t sel=shapes[sh].sel; size_t sz=shapes[sh].sz;
        for(size_t off=0; off+8<=sz; off+=8){
            for(int p=0;p<NP;p++){
                uint8_t in[64]; memset(in,0,sizeof in);
                *(uint64_t*)(in+off)=POOL[p];
                call(c,sel,in,sz);
            }
        }
        // also 4-byte granularity (img4 fields may be 32-bit)
        for(size_t off=0; off+4<=sz; off+=4){
            uint32_t v32[]={0,1,0xffffffff,0x7fffffff,0x80000000,0x10000,0xffff};
            for(int p=0;p<7;p++){ uint8_t in[64]; memset(in,0,sizeof in); *(uint32_t*)(in+off)=v32[p]; call(c,sel,in,sz); }
        }
    }
    printf("[*] phase1 (field-extremes) done, no panic\n");

    // phase 2: random content blast
    for(long i=0;i<iters;i++){
        int sh=i&1; uint32_t sel=shapes[sh].sel; size_t sz=shapes[sh].sz;
        uint8_t in[64];
        for(size_t j=0;j<sz;j+=4)*(uint32_t*)(in+j)=xs();
        // bias some fields to pool extremes
        if((i&7)==0){ size_t off=(xs()% (sz/8))*8; *(uint64_t*)(in+off)=POOL[xs()%NP]; }
        call(c,sel,in,sz);
        if((i%200000)==0){ printf("[*] %ld iters, no panic (seed now 0x%x)\n",i,s_state); fflush(stdout);}
    }
    printf("[*] all %ld iters done, no panic\n",iters);
    IOServiceClose(c);
    return 0;
}
