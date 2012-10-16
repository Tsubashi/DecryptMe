#import <CoreFoundation/CFUserNotification.h>
#import <MobileCoreServices/UTType.h>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include "sha1.h"

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

%ctor {
  NSAutoreleasePool* pool=[[NSAutoreleasePool alloc] init];
  NSFileManager* manager=[NSFileManager defaultManager];
  NSBundle* bundle=[NSBundle mainBundle];
  FILE* logfh=NULL;
  do {
    if([manager isWritableFileAtPath:@"/var/mobile"]){break;}
    CFOptionFlags flags;
    NSString* $home=NSHomeDirectory();
    logfh=fopen([$home stringByAppendingPathComponent:@"decrypt.log"].fileSystemRepresentation,"w");
    if(!logfh){
      CFUserNotificationDisplayAlert(0,0,NULL,NULL,NULL,@"Error",
       @"Cannot open log file. Please check file permissions.",nil,nil,nil,&flags);
      break;
    }
    setvbuf(logfh,NULL,_IONBF,0);
    NSString* $path=bundle.executablePath;
    const uint32_t index=0;
    const char* path=$path.fileSystemRepresentation,*ipath=_dyld_get_image_name(index);
    fprintf(logfh,"TARGET %s\n",path);
    if(strcmp(path,ipath)){fprintf(logfh,"! IMAGE %s\n",ipath);break;}
    FILE* exe=fopen(path,"r");
    if(!exe){fputs("! OPEN(TARGET)\n",logfh);break;}
    BOOL success=NO;
    do {
      const struct mach_header* image=_dyld_get_image_header(index);
      const struct load_command* load=(void*)image+sizeof(struct mach_header);
      const struct linkedit_data_command* lcsig=NULL;
      void* lcenc=NULL;
      uint32_t fsize=0,tsize=0,i;
      for (i=0;i<image->ncmds;i++){
        if(load->cmd==LC_SEGMENT){
          struct segment_command* lcseg=(void*)load;
          uint32_t end=lcseg->fileoff+lcseg->filesize;
          if(end>fsize){fsize=end;}
          if(strcmp(lcseg->segname,"__TEXT")==0){
            if(lcseg->vmsize!=lcseg->filesize){fprintf(logfh,"! __TEXT.size %u!=%u\n",lcseg->vmsize,lcseg->filesize);}
            else if(lcseg->fileoff!=0){fprintf(logfh,"! __TEXT +%u\n",lcseg->fileoff);}
            else {tsize=lcseg->vmsize;}
          }
        }
        else if(load->cmd==LC_ENCRYPTION_INFO){lcenc=(void*)load;}
        else if(load->cmd==LC_CODE_SIGNATURE){lcsig=(void*)load;}
        load=(void*)load+load->cmdsize;
      }
      fprintf(logfh,tsize?"__TEXT.size %u\n":"! __TEXT.size",tsize);
      fprintf(logfh,fsize?"IMAGE.size %u\n":"! IMAGE.size",fsize);
      if(!lcenc){fputs("! LC_ENCRYPTION_INFO\n",logfh);}
      if(!lcsig){fputs("! LC_CODE_SIGNATURE\n",logfh);}
      else if(lcsig->dataoff<tsize){
        fprintf(logfh,"! LC_CODE_SIGNATURE +%u\n",lcsig->dataoff);
        lcsig=NULL;
      }
      if(!fsize || !lcenc || !lcsig){break;}
      fprintf(logfh,"IMAGE.cputype %d.%d\n",image->cputype,image->cpusubtype);
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
          fprintf(logfh,"FAT_ARCH.cputype %d.%d\n",cputype,cpusubtype);
          if(image->cputype==cputype && image->cpusubtype==cpusubtype){
            uint32_t size=__builtin_bswap32(arch.size);
            if(size==fsize){foff=__builtin_bswap32(arch.offset);}
            else {fprintf(logfh,"! FAT_ARCH.size %u\n",size);}
          }
        }
        if(!foff){fputs("! FAT\n",logfh);break;}
      }
      NSString* $outpath=[$home stringByAppendingPathComponent:@"decrypt.out"];
      const char* outpath=$outpath.fileSystemRepresentation;
      FILE* outfh=fopen(outpath,"w+");
      do {
        size_t len;
        fprintf(logfh,"WRITE(LC) %lu > %lu\n",len=lcenc-(void*)image,ftell(outfh));
        if((len-=fwrite(image,1,len,outfh))){fprintf(logfh,"! WRITE(LC).remaining %lu\n",len);break;}
        size_t elen=sizeof(struct encryption_info_command);
        struct encryption_info_command enc={LC_ENCRYPTION_INFO,elen,0,0,0};
        fprintf(logfh,"WRITE(LC_ENCRYPTION_INFO) %lu > %lu\n",len=elen,ftell(outfh));
        if((len-=fwrite(&enc,1,len,outfh))){fprintf(logfh,"! WRITE(LC_ENCRYPTION_INFO).remaining %lu\n",len);break;}
        fprintf(logfh,"WRITE(__TEXT) %lu > %lu\n",len=tsize-(lcenc+elen-(void*)image),ftell(outfh));
        if((len-=fwrite(lcenc+elen,1,len,outfh))){fprintf(logfh,"! WRITE(__TEXT).remaining %lu\n",len);break;}
        fseek(exe,foff+tsize,SEEK_SET);
        fprintf(logfh,"COPY %lu < %lu > %lu\n",len=lcsig->dataoff-tsize,ftell(exe),ftell(outfh));
        if((len=$_streamCopy(outfh,exe,len))){fprintf(logfh,"! COPY.remaining %lu\n",len);break;}
        fprintf(logfh,"READ(CODESIGN) %lu < %lu\n",len=lcsig->datasize,ftell(exe));
        struct SuperBlob* blob=malloc(len);
        if(!blob){fputs("! MALLOC\n",logfh);break;}
        do {
          if((len-=fread(blob,1,len,exe))){fprintf(logfh,"! READ(CODESIGN).remaining %lu\n",len);break;}
          fpos_t pos;
          fgetpos(outfh,&pos);
          uint32_t nblobs=__builtin_bswap32(blob->count),i;
          for (i=0;i<nblobs;i++){
            if(__builtin_bswap32(blob->index[i].type)){continue;}
            struct CodeDirectory* cdir=(void*)blob+__builtin_bswap32(blob->index[i].offset);
            uint8_t* hash=(void*)cdir+__builtin_bswap32(cdir->hashOffset);
            uint32_t npages=__builtin_bswap32(cdir->nCodeSlots);
            if(!npages){continue;}
            fprintf(logfh,"CODESIGN.pages %u\n",npages);
            rewind(outfh);
            uint32_t j;
            uint8_t buf[0x1000];
            for (j=0;j<npages;j++){
              fread(buf,1,len=(j<npages-1)?0x1000:((lcsig->dataoff-1)%0x1000)+1,outfh);
              SHA1Context sha1;
              SHA1Reset(&sha1);
              SHA1Input(&sha1,buf,len);
              SHA1Result(&sha1,hash+20*j);
            }
          }
          fsetpos(outfh,&pos);
          fprintf(logfh,"WRITE(CODESIGN) %lu > %lu\n",len=lcsig->datasize,ftell(outfh));
          if((len-=fwrite(blob,1,len,outfh))){fprintf(logfh,"! WRITE(CODESIGN).remaining %lu\n",len);}
        } while (0);
        free(blob);
        if(len){break;}
        fseek(exe,foff+lcsig->dataoff+lcsig->datasize,SEEK_SET);
        fprintf(logfh,"COPY %lu < %lu > %lu\n",len=fsize-lcsig->dataoff-lcsig->datasize,ftell(exe),ftell(outfh));
        if((len=$_streamCopy(outfh,exe,len))){fprintf(logfh,"! COPY.remaining %lu\n",len);break;}
        fprintf(logfh,"OUTPUT %s\n",outpath);
        success=YES;
      } while(0);
      fclose(outfh);
      if(success){
        success=NO;
        if(chmod(outpath,0755)){fputs("! CHMOD(OUTPUT)\n",logfh);break;}
        NSString* $shpath=[$path stringByAppendingString:@"_"];
        const char* shpath=$shpath.fileSystemRepresentation;
        FILE* shfh=fopen(shpath,"w");
        if(!shfh){fputs("! OPEN(script)\n",logfh);break;}
        NSString* $name=$path.lastPathComponent,*$version=[bundle objectForInfoDictionaryKey:@"CFBundleVersion"];
        fprintf(shfh,"#!/bin/sh\nfn=${HOME%%/*}/%s",$name.fileSystemRepresentation);
        if($version){fprintf(shfh,"-%s",$version.fileSystemRepresentation);}
        fputs("\nmv \"${0%_}\" \"${0%_}~\" && mv -f ~/decrypt.out \"$fn\" && ln -s \"$fn\" \"${0%_}\"\n"
         "fn=~/Documents;if [ \"$(readlink \"$fn/tmp\")\" != ../tmp ];then\n"
         "mv \"$fn\" ~/_;mkdir \"$fn\";mv ~/_ \"$fn/Documents\" && ln -s ../Library ../tmp \"$fn\";fi\n"
         "{ n=0;while read L;do ((n++>$LINENO)) && echo \"$L\";done;}<\"$0\">\"$0~\"\n"
         "mv \"$0~\" \"$0\" && chmod +x \"$0\"\n#!/bin/sh\n"
         "export HOME=~/Documents\nexport CFFIXED_USER_HOME=$HOME\n"
         "export TMPDIR=~/tmp\nexec \"${0%_}\"\n",shfh);
        fclose(shfh);
        if(chmod(shpath,0755)){fputs("! CHMOD(script)\n",logfh);break;}
        NSString* $info=[$home stringByAppendingPathComponent:@"decrypt.info"];
        if(![manager linkItemAtPath:[bundle pathForResource:@"Info" ofType:@"plist"] toPath:$info error:NULL]){
          fputs("! LINK(info)\n",logfh);
          break;
        }
        NSMutableDictionary* $idict=[NSMutableDictionary dictionaryWithContentsOfFile:$info];
        [$idict setObject:[$name stringByAppendingString:@"_"] forKey:@"CFBundleExecutable"];
        NSArray* $doctypes=[$idict objectForKey:@"CFBundleDocumentTypes"];
        NSString* $UTI=@"public.item";
        for (NSDictionary* $doctype in $doctypes){
          for (NSString* $uti in [$doctype objectForKey:@"LSItemContentTypes"]){
            if(UTTypeConformsTo((CFStringRef)$UTI,(CFStringRef)$uti)){goto skipUTI;}
          }
        }
        [$idict setObject:[$doctypes arrayByAddingObject:[NSDictionary dictionaryWithObjectsAndKeys:
         @"OTHER",@"CFBundleTypeName",@"Alternate",@"LSHandlerRank",
         [NSArray arrayWithObject:$UTI],@"LSItemContentTypes",nil]] forKey:@"CFBundleDocumentTypes"];
        skipUTI:
        if(![[NSPropertyListSerialization dataWithPropertyList:$idict format:NSPropertyListBinaryFormat_v1_0
         options:0 error:NULL] writeToFile:$info atomically:NO]){
          fputs("! WRITE(info)\n",logfh);
          break;
        }
        unlink($info.fileSystemRepresentation);
      }
    } while(0);
    fclose(exe);
    if(success){
      CFUserNotificationDisplayAlert(0,0,NULL,NULL,NULL,@"Error",
       @"Something went wrong. Please check [decrypt.log].",nil,nil,nil,&flags);
    }
    else {
      CFUserNotificationDisplayAlert(0,3,NULL,NULL,NULL,@"Success",
       [NSString stringWithFormat:@"Unsandboxing complete. %@ will now close.",
       [bundle objectForInfoDictionaryKey:@"CFBundleDisplayName"]],nil,nil,nil,&flags);
    }
  } while(0);
  [pool drain];
  if(logfh){
    fclose(logfh);
    exit(0);
  }
}  
