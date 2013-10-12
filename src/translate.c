/* cat file.txt@1 shows last version of the file.txt */

#include "translate.h"

char *get_translated_path(const char *path)
{
    /* try to break (path#version) into (path,version) */ 
    const char *c = strrchr(path, '#');
    if(!c)
        return strdup(path);
    char *simplepath = strndup(path,int(c-path));
    int version=atoi(c+1);
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ Translate Mechanism Results: %s >>> %s %d\n",path, simplepath, version);
#endif    
    
    char *apath = lookup_version(simplepath, version);
    if(simplepath) free(simplepath);
    return apath;
}

#ifdef translate_DEBUG

int main()
{
    char *ptr;
    ptr = get_translated_path("dummy.txt##1");
    if(ptr) free(ptr);
    ptr = get_translated_path("./dummy.txt##1");
    if(ptr) free(ptr);
    return 0;
}

#endif
