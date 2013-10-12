/*
  smaFS: a delightful filesystem!
  Based on fusexmp example from FUSE tarball.

  Copyright (C) 2009-2010  dsk <dkholia@cs.ubc.ca>
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/  

#include "smaFS.h"
#include "common.h"

static int smaFS_getattr(const char *path, struct stat *stbuf)
{
    int res;

    if(strstr(path, ".store") && fuse_get_context()->uid !=0) {
        printf("\nStore Access Denied!\n");
        return -ENOENT;
    }
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ getattr() user: %d file: %s\n",fuse_get_context()->uid, path);
#endif

    char *apath = get_translated_path(path);
    if(!apath)
        return -ENOENT;
    res = lstat(apath, stbuf);
    free(apath);

    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_access(const char *path, int mask)
{
    int res;

#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ access() user: %d file: %s\n",fuse_get_context()->uid, path);
#endif
    char *apath = get_translated_path(path);
    if(!apath) {
#ifdef DEBUG
        fprintf(stderr, "$$$$$$$ access() translation failed for user %d to %s\n",fuse_get_context()->uid, path);
#endif        
        return -ENOENT;
    }
    
    res = access(apath, mask);
    free(apath);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_readlink(const char *path, char *buf, size_t size)
{
    int res;

    res = readlink(path, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int smaFS_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;

    dp = opendir(path);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        if(!strcmp(de->d_name, ".store")) /* hide ".store" hack */
            continue;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int smaFS_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ mknod() user: %d file: %s\n",fuse_get_context()->uid, path);
#endif

    cache[string(path)] = M; /* don't call create_version() */
    
    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(path, mode);
    else
        res = mknod(path, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_mkdir(const char *path, mode_t mode)
{
    int res;

    res = mkdir(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_unlink(const char *path)
{
    int res;

#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ unlink() user: %d file: %s\n",fuse_get_context()->uid, path);
#endif
    create_version(path, U); /* create backup */

    res = unlink(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_rmdir(const char *path)
{
    int res;

    res = rmdir(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_symlink(const char *from, const char *to)
{
    int res;

#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ symlink() user: %d from file: %s to file: %s\n",fuse_get_context()->uid, from,to);
#endif
    res = symlink(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_rename(const char *from, const char *to)
{
    int res;
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ rename() user: %d from file: %s to file: %s\n",fuse_get_context()->uid, from,to);
#endif
    create_version(from, R); /* create backup */

    res = rename(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_link(const char *from, const char *to)
{
    int res;
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ link() user: %d from file: %s to file: %s\n",fuse_get_context()->uid, from,to);
#endif

    res = link(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_chmod(const char *path, mode_t mode)
{
    int res;

    res = chmod(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    res = lchown(path, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}


static int smaFS_truncate(const char *path, off_t size)
{
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ truncate() user: %d file: %s\n",fuse_get_context()->uid, path);
#endif
    int res;
    create_version(path, T); /* create backup */

    res = truncate(path, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    struct timeval tv[2];

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(path, tv);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_open(const char *path, struct fuse_file_info *fi)
{
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ open() user: %d file: %s\n",fuse_get_context()->uid, path);
#endif
    
    int res;
    if((fi->flags & O_WRONLY) || (fi->flags & O_RDWR)) {
#ifdef DEBUG
        fprintf(stderr, "$$$$$$$ open() *write mode* user: %d file: %s\n",fuse_get_context()->uid, path); 
#endif
        create_version(path, OW); /* create backup */
    }

    char * apath = get_translated_path(path);
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ open() got %s\n",apath);
#endif    
    if(!apath) {
#ifdef DEBUG
        fprintf(stderr, "$$$$$$$ open() translation failed for %s\n", path);
#endif        
        return -errno;
    }
    
    res = open(apath, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int smaFS_read(const char *path, char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi)
{
    int fd, res;
    (void) fi;
    
    char *apath = get_translated_path(path);
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ read() for %s\n",apath);
#endif
 
    if(!apath) {
#ifdef DEBUG
        fprintf(stderr, "$$$$$$$ read() translation failed for %s\n", path);
#endif        
        return -errno;
    }
    
    fd = open(apath, O_RDONLY);
    free(apath);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

/* do not hook write() for BOW (backup-on-write) */
static int smaFS_write(const char *path, const char *buf, size_t size,
             off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;

    (void) fi;
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ write() for %s\n",path);
#endif
   
    fd = open(path, O_WRONLY);
    if (fd == -1)
        return -errno;

    res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int smaFS_statfs(const char *path, struct statvfs *stbuf)
{
    int res;

    res = statvfs(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int smaFS_release(const char *path, struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) fi;
    return 0;
}

static int smaFS_fsync(const char *path, int isdatasync,
             struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}


static void * smaFS_init(struct fuse_conn_info *conn)
{
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ init()\n");
#endif
    return NULL;
}

static void smaFS_destroy(void *ptr)
{
#ifdef DEBUG
    fprintf(stderr, "$$$$$$$ destroy()\n");
#endif
}


#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int smaFS_setxattr(const char *path, const char *name, const char *value,
            size_t size, int flags)
{
    int res = lsetxattr(path, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int smaFS_getxattr(const char *path, const char *name, char *value,
            size_t size)
{
    int res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int smaFS_listxattr(const char *path, char *list, size_t size)
{
    int res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int smaFS_removexattr(const char *path, const char *name)
{
    int res = lremovexattr(path, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

int main(int argc, char *argv[])
{
    umask(0);

    static struct fuse_operations smaFS_oper;
    smaFS_oper.init        = smaFS_init;
    smaFS_oper.destroy     = smaFS_destroy;
    smaFS_oper.getattr     = smaFS_getattr;
    smaFS_oper.access      = smaFS_access;
    smaFS_oper.readlink    = smaFS_readlink;
    smaFS_oper.readdir     = smaFS_readdir;
    smaFS_oper.mknod       = smaFS_mknod;
    smaFS_oper.mkdir       = smaFS_mkdir;
    smaFS_oper.symlink     = smaFS_symlink;
    smaFS_oper.unlink      = smaFS_unlink;
    smaFS_oper.rmdir       = smaFS_rmdir;
    smaFS_oper.rename      = smaFS_rename;
    smaFS_oper.link        = smaFS_link;
    smaFS_oper.chmod       = smaFS_chmod;
    smaFS_oper.chown       = smaFS_chown;
    smaFS_oper.truncate    = smaFS_truncate;
    smaFS_oper.utimens     = smaFS_utimens;
    smaFS_oper.open        = smaFS_open;
    smaFS_oper.read        = smaFS_read;
    smaFS_oper.write       = smaFS_write;
    smaFS_oper.statfs      = smaFS_statfs;
    smaFS_oper.release     = smaFS_release;
    smaFS_oper.fsync       = smaFS_fsync;
#ifdef HAVE_SETXATTR
    smaFS_oper.setxattr    = smaFS_setxattr;
    smaFS_oper.getxattr    = smaFS_getxattr;
    smaFS_oper.listxattr   = smaFS_listxattr;
    smaFS_oper.removexattr = smaFS_removexattr;
#endif

    return fuse_main(argc, argv, &smaFS_oper, NULL);
}
