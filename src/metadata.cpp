/*
 * http://www.sgi.com/tech/stl/Deque.html
 * http://www.sgi.com/tech/stl/thread_safety.html
*/

#include "metadata.h"
#include "common.h"

using namespace std;

/* this functions returns the actual path where 
 * the particular file's version is stored */
char *lookup_version(const char * path, int version)
{
    /* get last part of path */
    const char *l = strrchr(path,'/');
    
    if(!l) {
        //fprintf(stderr,"$$$$$$$ lookup_version() translation failed!\n");
        return NULL;
    }

    /* form path to store */
    int n = int(l-path) + 1;
    char storepath[256];
    memset(storepath, 0, 256);
    memcpy(storepath, path, n);
    memcpy(&storepath[n], ".store", 6);
    char targetpath[256];
    memset(targetpath, 0, 256);
    n = (int) (&path[strlen(path)]-l);
    memcpy(targetpath, l+1, n);
    char metadatapath[256];
    memset(metadatapath, 0, 256);
    n = strlen(storepath);
    memcpy(metadatapath, storepath, n);
    sprintf(&metadatapath[n], "/%s%s","metadata.", targetpath);
   
    struct stat stbuf; int res;
    res = lstat(metadatapath, &stbuf);
    if (res == -1) {
        return NULL;
    }

    /* read versions from metadata file */
    int index = 0; int found = 0;
    FILE *fp; fp = fopen(metadatapath, "r");
    struct version v;
    n = sizeof(struct version);
    memset(&v,0,n);
    while(fp && !feof(fp)) {
        int result = fread(&v, n, 1, fp);
        if(result == 0) 
            break;
        index++;
        if(index==version) {
            found = 1;
            break;
        }
    }
   
    fclose(fp);

    if(found) {
        char apath[256];
        memset(apath, 0, 256);
        sprintf(apath, "%s/%s", storepath, v.vfn);
        //fprintf(stderr,"$$$$$$$ lookup_version() actual path is %s\n", apath);
        return strdup(apath);
    }
    else
        return NULL;
}


int make_copy(const char *src, const char *dst)
{
    
#ifdef DEBUG
    fprintf(stderr,"!!!!!!! make_copy() from: %s to: %s\n",src, dst);
#endif
    int in, out;
    if((in = r_open2(src, O_RDONLY)) == -1) {
        fprintf(stderr, "make_copy() open-in failed for %s!\n", src);
        return in;
    }
    if((out= creat(dst, S_IRUSR | S_IWUSR)) == -1) {
        fprintf(stderr, "make_copy() open-out failed for %s!\n", dst);
        return out;
    }

    copyfile(in, out);
    r_close(in);
    r_close(out);
    return 0;
}

/* creates a version (copy) for the specified file */
int create_version(const char * path, int opr)
{
#ifndef metadata_DEBUG
#ifndef translate_DEBUG

    if(cache.find(string(path)) == cache.end())
        cache[string(path)]=0;
    int popr = cache.find(string(path))->second; /* fetch */
#ifdef DEBUG
    fprintf(stderr, "!!!!!!! create_version() opr: %d popr: %d\n",opr, popr);
#endif

    if((popr == T && opr == OW)) {
        /* if open() follows truncate() then avoid creating version*/
        cache[string(path)] = opr; /* invalidate cache entry */
        return 0;
    }
 
    if(popr == OW && opr == OW) {
        /* if open() follows open() then avoid creating version, maybe BUGGY */
        cache[string(path)] = opr;
        return 0;
    }

    if(popr == M && opr == OW) {
        cache[string(path)] = -1; /* invalidate cache entry */
        return 0;
    }

    cache[string(path)] = opr; /* store */

#endif
#endif

    /* does ".store" exists in path's parent folder? */
    const char *l = strrchr(path,'/');
    int n = int(l-path+1);
    char storepath[256];
    memset(storepath, 0, 256);
    memcpy(storepath, path, n);
    memcpy(&storepath[n], ".store", 6);
    struct stat stbuf; int res;
    
    res = lstat(path, &stbuf);
    if (res == -1) {
#ifdef DEBUG
        fprintf(stderr, "$$$$$$$ create_version() First Time Detected for %s ... exiting!\n",path);
#endif
        return 0;
    }

    res = lstat(storepath, &stbuf);
    if (res == -1) {
#ifdef DEBUG
        fprintf(stderr, "$$$$$$$ update_metadata() store missing\n");
        fprintf(stderr, "$$$$$$$ update_metadata() creating store\n");
#endif
        mkdir(storepath,  S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }
    else {
#ifdef DEBUG
        fprintf(stderr, "$$$$$$$ update_metadata() existing store %lu found!\n",(unsigned long)stbuf.st_ino);
#endif
    }

    /* does the metadata exists in the ".store"? */
    char targetpath[256];
    memset(targetpath, 0, 256);
    n = (int) (&path[strlen(path)]-l);
    memcpy(targetpath, l+1, n);
    char metadatapath[256];
    memset(metadatapath, 0, 256);
    n = strlen(storepath);
    memcpy(metadatapath, storepath, n);
    sprintf(&metadatapath[n], "/%s%s","metadata.", targetpath);
    res = lstat(metadatapath, &stbuf);
    if (res == -1) {
#ifdef DEBUG
        fprintf(stderr, "$$$$$$$ update_metadata() metadata file missing!\n");
        fprintf(stderr, "$$$$$$$ update_metadata() creating metadata file!\n");
#endif
    }
    else {
#ifdef DEBUG
        fprintf(stderr, "$$$$$$$ update_metadata() existing metadata %lu found!\n",(unsigned long)stbuf.st_ino);
#endif
    }

   /* populate versions */
    deque<struct version> versions; /* structure behind metadata.<filename> */
    struct version cv;
    n = sizeof(struct version);
    memset(&cv,0,n);

    FILE *fp; fp = fopen(metadatapath, "r");
    struct version v;
    int result;

    while(fp && !feof(fp)) {
        result = fread(&v, n, 1, fp);
        if(result == 0) 
            break;
        versions.push_front(v);
    }

    /* get last version/revision */
    if(versions.empty()) {
        cv.revision = 1;
    }
    else {
        cv.revision = versions.front().revision + 1;
    }

    char vfn[256];
    memset(vfn,0,256);
    snprintf(vfn, 9, "%08d", cv.revision);
    sprintf(&vfn[strlen(vfn)], ".%s", l+1);
    char fvfn[256];
    memset(fvfn,0,256);
    sprintf(fvfn, "%s/",storepath);
    sprintf(&fvfn[strlen(fvfn)], "%s", vfn);
 
    /* fill up current version structure */
    memcpy(&cv.vfn,vfn,strlen(vfn));
    unsigned char *hash = gethash(path);
    if(hash) { 
        memcpy(&cv.hash,hash,4);
    }
    lstat(path, &cv.stbuf);
    cv.isCompressed = false;

    /* update metadata */
    if(fp)
        fclose(fp);
    
    fp = fopen(metadatapath, "ab");
    if(fp) {
        fwrite(&cv,n,1,fp);
        fclose(fp);
    }
    else {
        fprintf(stderr, "%s\n", strerror(errno));
        return 0;
    }

    /* copy path to fvfn */
    make_copy(path, fvfn);
    
    return 0;
}


#ifdef metadata_DEBUG

int main()
{
    create_version("./dummy.txt", 0);
    create_version("./dummy.txt#", 0);
    return 0;
}

#endif
