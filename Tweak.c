#import <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>

#define LPREFIX "UnsandboxMe: "

struct Blob {uint32_t magic,length;};
struct BlobIndex {uint32_t type,offset;};
struct SuperBlob {
  struct Blob blob;
  uint32_t count;
  struct BlobIndex index[];
};
struct CodeDirectory {
  struct Blob blob;
  uint32_t version,flags,hashOffset,identOffset,nSpecialSlots,nCodeSlots,codeLimit;
  uint8_t hashSize,hashType,spare1,pageSize;
  uint32_t spare2;
};

static uint32_t $_streamCopy(FILE* dest,FILE* src,size_t size) {
  while(size){
    uint8_t buf[8192];
    size_t len=(size<8192)?size:8192;
    if(fread(buf,1,len,src)!=len || feof(src) || fwrite(buf,1,len,dest)!=len){break;}
    size-=len;
  }
  return size;
}

static __attribute__((constructor)) void init() {
  const uint32_t index=0;
  const char* imgname=_dyld_get_image_name(index);
  syslog(LOG_INFO,LPREFIX"IMAGE=%s",imgname);
  FILE* exe=fopen(imgname,"r");
  if(!exe){syslog(LOG_ERR,LPREFIX"fopen(IMAGE): %s",strerror(errno));return;}
  do {
    const struct mach_header* image=_dyld_get_image_header(index);
    const struct load_command* load=(void*)image+sizeof(struct mach_header);
    const struct linkedit_data_command* lcsig=NULL;
    const void* lcenc=NULL;
    uint32_t fsize=0,tsize=0,i;
    for (i=0;i<image->ncmds;i++){
      if(load->cmd==LC_SEGMENT){
        struct segment_command* lcseg=(void*)load;
        uint32_t end=lcseg->fileoff+lcseg->filesize;
        if(end>fsize){fsize=end;}
        if(strcmp(lcseg->segname,"__TEXT")==0){
          if(lcseg->vmsize!=lcseg->filesize){syslog(LOG_WARNING,LPREFIX"__TEXT.size %u!=%u",lcseg->vmsize,lcseg->filesize);}
          else if(lcseg->fileoff!=0){syslog(LOG_WARNING,LPREFIX"__TEXT.offset %u!=0",lcseg->fileoff);}
          else {tsize=lcseg->vmsize;}
        }
      }
      else if(load->cmd==LC_ENCRYPTION_INFO){lcenc=(void*)load;}
      else if(load->cmd==LC_CODE_SIGNATURE){lcsig=(void*)load;}
      load=(void*)load+load->cmdsize;
    }
    if(!lcenc){syslog(LOG_ERR,LPREFIX"! LC_ENCRYPTION_INFO");}
    if(!lcsig){syslog(LOG_ERR,LPREFIX"! LC_CODE_SIGNATURE");}
    else if(lcsig->dataoff<tsize){
      syslog(LOG_ERR,LPREFIX"LC_CODE_SIGNATURE.offset %u<%u",lcsig->dataoff,tsize);
      lcsig=NULL;
    }
    if(!fsize || !lcenc || !lcsig){break;}
    syslog(LOG_INFO,LPREFIX"IMAGE.cputype=%d,%d",image->cputype,image->cpusubtype);
    uint32_t foff=0;
    struct fat_header fat;
    fread(&fat,sizeof(fat),1,exe);
    if(fat.magic==FAT_CIGAM){
      struct fat_arch arch;
      uint32_t narch=__builtin_bswap32(fat.nfat_arch),i;
      for (i=0;i<narch;i++){
        fread(&arch,sizeof(arch),1,exe);
        cpu_type_t cputype=__builtin_bswap32(arch.cputype);
        cpu_subtype_t cpusubtype=__builtin_bswap32(arch.cpusubtype);
        syslog(LOG_INFO,LPREFIX"FAT_ARCH.cputype=%d,%d",cputype,cpusubtype);
        if(image->cputype==cputype && image->cpusubtype==cpusubtype){
          uint32_t size=__builtin_bswap32(arch.size);
          if(size==fsize){foff=__builtin_bswap32(arch.offset);}
          else {syslog(LOG_NOTICE,LPREFIX"FAT_ARCH.size %u!=%u",size,fsize);}
        }
      }
      if(!foff){syslog(LOG_ERR,LPREFIX"! FAT_ARCH");break;}
    }
    const char* rootdir=getenv("HOME");
    const char* subdir="/Documents";
    const char* outfn=strrchr(imgname,'/');
    size_t prelen=strlen(rootdir),outlen=strlen(outfn);
    const size_t sublen=strlen(subdir);
    char* outpath=memcpy(malloc(prelen+sublen+outlen+1),rootdir,prelen);
    memcpy(memcpy(outpath+prelen,subdir,sublen)+sublen,outfn,outlen+1);
    syslog(LOG_INFO,LPREFIX"OUTPUT=%s",outpath);
    FILE* outfh=fopen(outpath,"w+");
    free(outpath);
    if(!outfh){syslog(LOG_ERR,LPREFIX"fopen(OUTPUT): %s",strerror(errno));break;}
    do {
      size_t len;
      size_t lcenc_prelen=len=lcenc-(void*)image;
      if((len-=fwrite(image,1,len,outfh))){syslog(LOG_ERR,LPREFIX"WRITE(=>LC_ENCRYPTION_INFO).remaining=%lu",len);break;}
      const size_t lcenc_len=len=sizeof(struct encryption_info_command);
      const struct encryption_info_command enc={LC_ENCRYPTION_INFO,lcenc_len,0,0,0};
      if((len-=fwrite(&enc,1,len,outfh))){syslog(LOG_ERR,LPREFIX"WRITE(LC_ENCRYPTION_INFO).remaining=%lu",len);break;}
      len=tsize-lcenc_prelen-lcenc_len;
      if((len-=fwrite(lcenc+lcenc_len,1,len,outfh))){syslog(LOG_ERR,LPREFIX"WRITE(=>end(__TEXT)).remaining=%lu",len);break;}
      fseek(exe,foff+tsize,SEEK_SET);
      if((len=$_streamCopy(outfh,exe,lcsig->dataoff-tsize))){syslog(LOG_ERR,LPREFIX"COPY(=>CODE_SIGNATURE).remaining=%lu",len);break;}
      struct SuperBlob* blob=malloc(len=lcsig->datasize);
      do {
        if((len-=fread(blob,1,len,exe))){syslog(LOG_ERR,LPREFIX"READ(CODE_SIGNATURE).remaining=%lu",len);break;}
        fpos_t pos;
        fgetpos(outfh,&pos);
        uint32_t nblobs=__builtin_bswap32(blob->count),i;
        for (i=0;i<nblobs;i++){
          if(__builtin_bswap32(blob->index[i].type)){continue;}
          struct CodeDirectory* cdir=(void*)blob+__builtin_bswap32(blob->index[i].offset);
          uint8_t* hash=(void*)cdir+__builtin_bswap32(cdir->hashOffset);
          uint32_t npages=__builtin_bswap32(cdir->nCodeSlots);
          if(!npages){continue;}
          rewind(outfh);
          uint32_t j;
          uint8_t buf[0x1000];
          for (j=0;j<npages;j++){
            fread(buf,1,len=(j<npages-1)?0x1000:((lcsig->dataoff-1)%0x1000)+1,outfh);
            CC_SHA1(buf,len,hash+CC_SHA1_DIGEST_LENGTH*j);
          }
        }
        fsetpos(outfh,&pos);
        len=lcsig->datasize;
        if((len-=fwrite(blob,1,len,outfh))){syslog(LOG_ERR,LPREFIX"WRITE(CODE_SIGNATURE).remaining=%lu",len);}
      } while(0);
      free(blob);
      if(len){break;}
      fseek(exe,foff+lcsig->dataoff+lcsig->datasize,SEEK_SET);
      if((len=$_streamCopy(outfh,exe,fsize-lcsig->dataoff-lcsig->datasize))){syslog(LOG_ERR,LPREFIX"COPY(=>end(IMAGE)).remaining=%lu",len);break;}
    } while(0);
    fclose(outfh);
  } while(0);
  fclose(exe);
}
