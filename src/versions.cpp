#include "versions.h"

using namespace std;

void printshorthash(unsigned char *hash)
{
    int i;
    for (i = 0; i < 4; ++i) {
        printf("%02X", hash[i]);
    }
}

static void show_versions(char * path)
{
    const char *l = strrchr(path,'/');
    
    int n;
    char metadatapath[256];
    memset(metadatapath, 0, 256);
    char targetpath[256];
    memset(targetpath, 0, 256);  
 

    if(l) {
        n = int(l-path) + 1;
        char storepath[256];
        memset(storepath, 0, 256);
        memcpy(storepath, path, n);
        memcpy(&storepath[n], ".store", 6);
        n = (int) (&path[strlen(path)]-l);
        memcpy(targetpath, l+1, n);
        n = strlen(storepath);
        memcpy(metadatapath, storepath, n);
    }
    else {
        memcpy(targetpath, path, strlen(path));
        memcpy(metadatapath, ".store", 6);
        n=6;
    }

    sprintf(&metadatapath[n], "/%s%s","metadata.", targetpath);

#ifdef DEBUG
    fprintf(stderr,"metadata path for %s is %s\n",path, metadatapath);
#endif
   
    struct stat stbuf; int status;
    status = lstat(metadatapath, &stbuf);
    if (status == -1) {
        printf("No versions for %s found: %s!\n",path, strerror(errno));
        return;
    }

    printf("Versions for %s:\n\n",path);
    printf("%s  %s\t\t       %s     %s  %s %s\n\n", "|Revision|", "|Timestamp|", "|Size|", "|Checksum|", "|Compressed|", "|Real Name|");

    /* read versions from metadata file */
    FILE *fp; fp = fopen(metadatapath, "r");
    struct version v;
    n = sizeof(struct version);
    memset(&v,0,n);
    while(fp && !feof(fp)) {
        int result = fread(&v, n, 1, fp);
        if(result == 0) 
            break;
        printf("%08d    ",v.revision);
        char *s = ctime(&v.stbuf.st_mtime);
        int i = strlen(s)-1; s[i]=0;
        printf("%s  ", s);
        printf(" %09d  ", (int)v.stbuf.st_size);
        printshorthash(v.hash);
        v.isCompressed == 0 ? printf("    %-8s", "false") : printf("    %-8s", "true");
        printf("     %s  ", v.vfn);
        printf("\n");
    }
    if(fp) fclose(fp);
    printf("\n");
}


static void usage(char *program)
{
    printf("Usage: %s files(s)\n", program);
}

int main(int argc, char *argv[])
{

    if(argc < 2) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    //printf("executing as uid: %d euid: %d\n",getuid(), geteuid());

    for(int i=1; i < argc; i++) {
        show_versions(argv[i]);
    }
    
    return 0;
}

