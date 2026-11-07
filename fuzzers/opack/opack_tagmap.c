#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>
extern CFDataRef OPACKEncoderCreateData(CFTypeRef obj, uint32_t flags, CFErrorRef *err) __attribute__((weak_import));
static void dump(const char*label, CFTypeRef o){
  if(!OPACKEncoderCreateData){printf("no encoder\n");return;}
  CFErrorRef e=NULL; CFDataRef d=OPACKEncoderCreateData(o,0,&e);
  if(!d){printf("%-14s ENC-FAIL\n",label); if(e)CFRelease(e); return;}
  const uint8_t *b=CFDataGetBytePtr(d);
  CFIndex n=CFDataGetLength(d); printf("%-14s (%2ld) ",label,(long)n); for(CFIndex i=0;i<n&&i<24;i++)printf("%02x ",b[i]); printf("\n"); CFRelease(d);
}
int main(){
  int v=5; dump("int-5", CFNumberCreate(0,kCFNumberIntType,&v));
  int v2=1000; dump("int-1000", CFNumberCreate(0,kCFNumberIntType,&v2));
  long long v3=0x1122334455667788LL; dump("int-8byte", CFNumberCreate(0,kCFNumberLongLongType,&v3));
  dump("str-empty", CFSTR(""));
  dump("str-AAAA", CFSTR("AAAA"));
  const uint8_t db[3]={1,2,3}; dump("data-3", CFDataCreate(0,db,3));
  const void*av[2]={CFSTR("x"),CFSTR("y")}; dump("array-2", CFArrayCreate(0,av,2,&kCFTypeArrayCallBacks));
  const void*k[1]={CFSTR("k")},*val[1]={CFSTR("v")};
  dump("dict-1", CFDictionaryCreate(0,k,val,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks));
  return 0;
}
