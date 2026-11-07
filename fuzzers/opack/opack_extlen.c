#include <stdio.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
extern CFDataRef OPACKEncoderCreateData(CFTypeRef, uint32_t, CFErrorRef*) __attribute__((weak_import));
static void dump(const char*l, CFTypeRef o){ CFErrorRef e=NULL; CFDataRef d=OPACKEncoderCreateData(o,0,&e);
  if(!d){printf("%s FAIL\n",l);return;} const uint8_t*b=CFDataGetBytePtr(d); CFIndex n=CFDataGetLength(d);
  printf("%-16s (%ld) first8: ",l,(long)n); for(int i=0;i<8&&i<n;i++)printf("%02x ",b[i]); printf("\n"); CFRelease(d);}
int main(){
  char s40[40]; memset(s40,'A',39); s40[39]=0; dump("str-39", CFStringCreateWithCString(0,s40,kCFStringEncodingASCII));
  char s300[301]; memset(s300,'B',300); s300[300]=0; dump("str-300", CFStringCreateWithCString(0,s300,kCFStringEncodingASCII));
  char s70000[70001]; memset(s70000,'C',70000); s70000[70000]=0; dump("str-70000", CFStringCreateWithCString(0,s70000,kCFStringEncodingASCII));
  static uint8_t db300[300]; memset(db300,7,300); dump("data-300", CFDataCreate(0,db300,300));
  static uint8_t db70000[70000]; memset(db70000,9,70000); dump("data-70000", CFDataCreate(0,db70000,70000));
  return 0;
}
