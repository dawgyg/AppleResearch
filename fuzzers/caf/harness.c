#include <AudioToolbox/AudioToolbox.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* fourcc(UInt32 v, char*b){ b[0]=v>>24;b[1]=v>>16;b[2]=v>>8;b[3]=v;b[4]=0;return b;}

int main(int argc, char** argv){
    if(argc<3){fprintf(stderr,"usage: %s cookie.bin channels\n",argv[0]);return 2;}
    FILE*f=fopen(argv[1],"rb"); if(!f){perror("open");return 2;}
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char* cookie=malloc(n); fread(cookie,1,n,f); fclose(f);
    int ch=atoi(argv[2]);
    fprintf(stderr,"[*] cookie len=%ld channels=%d\n",n,ch);

    AudioStreamBasicDescription src; memset(&src,0,sizeof(src));
    src.mSampleRate=48000; src.mFormatID='apac';
    src.mFormatFlags=0; src.mBytesPerPacket=0; src.mFramesPerPacket=1024;
    src.mChannelsPerFrame=ch; src.mBitsPerChannel=0;

    AudioStreamBasicDescription dst; memset(&dst,0,sizeof(dst));
    dst.mSampleRate=48000; dst.mFormatID=kAudioFormatLinearPCM;
    dst.mFormatFlags=kAudioFormatFlagIsFloat|kAudioFormatFlagIsPacked;
    dst.mChannelsPerFrame=ch; dst.mBitsPerChannel=32;
    dst.mBytesPerFrame=4*ch; dst.mFramesPerPacket=1; dst.mBytesPerPacket=4*ch;

    AudioConverterRef conv=NULL;
    OSStatus st=AudioConverterNew(&src,&dst,&conv);
    char b[5];
    fprintf(stderr,"[*] AudioConverterNew -> %d (%s)\n",(int)st,fourcc(st,b));
    if(st!=0){ fprintf(stderr,"[!] converter create failed\n"); return 1; }

    st=AudioConverterSetProperty(conv,kAudioConverterDecompressionMagicCookie,(UInt32)n,cookie);
    fprintf(stderr,"[*] SetProperty(DecompressionMagicCookie) -> %d (%s)\n",(int)st,fourcc(st,b));

    // read back the channel layout the decoder produced (surfaces disclosed bytes)
    UInt32 sz=0; Boolean wr=0;
    OSStatus st2=AudioConverterGetPropertyInfo(conv,kAudioConverterOutputChannelLayout,&sz,&wr);
    fprintf(stderr,"[*] OutputChannelLayout info -> %d size=%u\n",(int)st2,sz);
    if(st2==0 && sz>0){
        unsigned char* buf=calloc(1,sz);
        OSStatus st3=AudioConverterGetProperty(conv,kAudioConverterOutputChannelLayout,&sz,buf);
        fprintf(stderr,"[*] OutputChannelLayout get -> %d\n",(int)st3);
        if(st3==0){ fprintf(stderr,"[*] layout bytes: ");
            for(UInt32 i=0;i<sz && i<160;i++) fprintf(stderr,"%02x",buf[i]);
            fprintf(stderr,"\n"); }
        free(buf);
    }
    fprintf(stderr,"[*] done ok\n");
    return 0;
}
