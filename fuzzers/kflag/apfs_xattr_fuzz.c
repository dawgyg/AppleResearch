// APFS xattr create/remove targeted fuzz (uid501, setxattr/removexattr) -> _alloc_and_set_xattr
// @0xb694e08 / _fs_remove_xattr_with_nstream_inode @0xb74bda0. Hit the inline->named-stream spill
// threshold (~3.7KB) + create/remove churn + length boundaries. Scratch APFS. Watch for panic.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/xattr.h>
static uint32_t s=0x5eed; static uint32_t xs(){s^=s<<13;s^=s>>17;s^=s<<5;return s;}
int main(int argc,char**argv){
  long iters=argc>1?atol(argv[1]):2000000; if(argc>2)s=strtoul(argv[2],0,0);
  const char* dir="/Volumes/SCRATCH";
  // sizes spanning the inline->nstream spill boundary + extremes
  size_t SZ[]={0,1,16,256,3800,3804,3808,4096,8192,16384,65536,131072,0x100000};
  const int NS=sizeof(SZ)/sizeof(SZ[0]);
  char* val=malloc(0x200000);
  char path[256], name[64];
  for(long i=0;i<iters;i++){
    snprintf(path,sizeof path,"%s/x%u.f",dir,xs()%32);
    int fd=open(path,O_CREAT|O_RDWR,0644); if(fd>=0)close(fd);
    int nl=1+(xs()%40); for(int k=0;k<nl;k++)name[k]='a'+(xs()%26); name[nl]=0;
    size_t sz=SZ[xs()%NS]; if(xs()&7) sz=xs()%0x4000; // mix targeted + random-near-threshold
    for(size_t j=0;j<sz && j<0x200000;j++) val[j]=(char)xs();
    int opt=(xs()&1)?XATTR_CREATE:((xs()&2)?XATTR_REPLACE:0);
    setxattr(path,name,val,sz,0,opt);
    if(xs()&3){ // churn: read back / remove / re-set to exercise nstream create+free lifecycle
      static char rb[0x200000]; getxattr(path,name,rb,sizeof rb,0,0);
      if(xs()&1) removexattr(path,name,0);
      if(xs()&1){ size_t s2=SZ[xs()%NS]; for(size_t j=0;j<s2&&j<0x200000;j++)val[j]=(char)xs(); setxattr(path,name,val,s2,0,0);} // resize same xattr (inline<->nstream transition)
    }
    if(xs()%64==0) unlink(path); // free the inode while xattrs/nstream may be live
    if((i%200000)==0){ printf("[*] %ld iters alive (s=0x%x)\n",i,s); fflush(stdout);}
  }
  printf("[*] done %ld, no panic\n",iters); return 0;
}
