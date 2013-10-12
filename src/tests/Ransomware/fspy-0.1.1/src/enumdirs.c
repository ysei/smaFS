/************************************************************************
 * fspy - experimental POC linux filesystem activity monitor            *
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ *
 * it's based on the new linux kernel inotify interface (merged into    *
 * the 2.6.13 linux kernel)                                             *
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ *
 * this code was tested on 2.6.18.4 and newer kernels                   *
 ************************************************************************
 * Copyright (C) 2007  Richard Sammet (e-axe)                           *
 *                                                                      *
 * This program is free software; you can redistribute it and/or modify *
 * it under the terms of the GNU General Public License as published by *
 * the Free Software Foundation; either version 2 of the License, or    *
 * (at your option) any later version.                                  *
 *                                                                      *
 * This program is distributed in the hope that it will be useful,      *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 * GNU General Public License for more details.                         *
 *                                                                      *
 * http://www.gnu.org/licenses/gpl.txt                                  *
 ************************************************************************
 * Contact, Bugs & Infos:                                               *
 *     richard.sammet@gmail.com                                         *
 ************************************************************************
 * Some infos:                                                          *
 *  - tabstop size:                                                     *
 *    set ts=2                                                          *
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <regex.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "fspy.h"
#include "enumdirs.h"
#include "stating.h"
#include "regmatch.h"
#include "diff.h"

extern char *typestring; /* from fspy.c */
extern char *diffstring; /* from fspy.c */
extern char *filterstring; /* from fspy.c */
extern char *ifilterstring; /* from fspy.c */
extern unsigned int delc_oa; /* from diff.c */
extern struct festat *felsptr; /* from diff.c */

unsigned int max_element_count = 0; /* maximum number of elements */
unsigned int elc_oa = 0; /* over all element counter */

/* ATTENTION: the max num. of elements must not be greater than /proc/sys/fs/inotify/max_user_watches */

int grab_max_element_count(void) {

  int fd;
  char buf[64]={0};

  fd = open("/proc/sys/fs/inotify/max_user_watches", O_RDONLY);
  if(fd >= 0) {
    read(fd, buf, 64);
  }else{
    perror("open()");
    exit(EXIT_FAILURE);
  }

  return atoi(buf);
}

struct felement *init_list(void) {

  struct felement *lsptr;

  if((lsptr = (struct felement *) malloc(ELEMENT_INIT_COUNT * sizeof(struct felement))) == NULL) {
    fprintf(stderr, "ERROR: could not allocate mem for initial dir list!\n");
    exit(EXIT_FAILURE);
  }

#ifdef _DEBUG
  printf("INIT_LIST: %i\n", ELEMENT_INIT_COUNT);
#endif

  return lsptr;
}

struct felement *extend_list(struct felement *lsptr) {

  if((lsptr = (struct felement *) realloc(lsptr, (elc_oa + ELEMENT_INIT_COUNT) * sizeof(struct felement))) == NULL) {
    fprintf(stderr, "ERROR: could not reallocate mem to extend dir list!\n");
    exit(EXIT_FAILURE);
  } 

#ifdef _DEBUG
  printf("EXTEND_LIST: %i (%i)\n", elc_oa + ELEMENT_INIT_COUNT, (elc_oa + ELEMENT_INIT_COUNT) * sizeof(struct felement));
#endif

  return lsptr;
}

int pathlookup(char *lpath, unsigned int wd, struct felement *lsptr) {

  unsigned int cnt = 0;

  /* TODO: optimize this! there should be no need to copy that value - just point to it! */
  while(cnt <= elc_oa) {
    if(lsptr[cnt].wd == wd) {
      memcpy(lpath, lsptr[cnt].path, ELEMENT_SIZE);
      return TRUE;
    }
    cnt++;
  }

  return FALSE;
}

struct felement *grabdirs(const char *initial_path, struct felement *lsptr, struct festat *felsptr) {

  DIR *dirfd;
  struct dirent *dp;
  struct stat tmp_stat;

  char path[ELEMENT_SIZE] = {0};
  char ip_local[ELEMENT_SIZE] = {0};

  memcpy(ip_local, initial_path, strlen(initial_path));

  if((dirfd = (DIR *)opendir(ip_local)) == NULL) {
    perror("opendir()");
    return NULL;
  }

  if(ip_local[strlen(ip_local)-1] != '/')
    strcat(ip_local, "/");

  while(dirfd) {
    if((dp = readdir(dirfd)) != NULL) {
      /* TODO: optimize string handling */
      memset(path, 0, ELEMENT_SIZE);
      if(strlen(ip_local) > ELEMENT_SIZE) {
        fprintf(stderr, "ERROR: grabdirs(): ip_local to long!\n");
        exit(EXIT_FAILURE);
      }else{
        strcat(path, ip_local);
      }
      if((strlen(dp->d_name) + strlen(ip_local)) > ELEMENT_SIZE) {
        fprintf(stderr, "ERROR: grabdirs(): ip_local + dp->d_name to long!\n");
        exit(EXIT_FAILURE);
      }else{
        strcat(path, dp->d_name);
      }
      if(!((strcmp(dp->d_name, "..") == 0) || (strcmp(dp->d_name, ".") == 0))) {
        if(statit(path, &tmp_stat) != TRUE) {
          fprintf(stderr, "ERROR: grabdirs()->statit(): returned != TRUE !\n");
          exit(EXIT_FAILURE);
        }
        /* TODO: !!! add the elements to the diffing list!!! */
        if(diffstring != NULL) {
          memcpy((&felsptr[delc_oa])->path, path, strlen(path));
          memcpy(&felsptr[delc_oa].statdat, &tmp_stat, sizeof(struct stat));
          felsptr[delc_oa].id = delc_oa;
          delc_oa++;
        }
        if(isdir(path, &tmp_stat) == TRUE) {
          if(path[strlen(path)-1] != '/')
            strcat(path, "/");
#ifdef _DEBUG
          printf("DIR: %s\n", path);
#endif
          if(!((filterstring != NULL) ? (reg_match(path) == TRUE):TRUE) && ((ifilterstring != NULL) ? (ireg_match(path) == TRUE):TRUE) && ((typestring != NULL) ? (checktype(path, NULL, typestring, NULL) == TRUE):TRUE))
            continue;
          if((elc_oa > 0) && (elc_oa % ELEMENT_SIZE == 0)) {
            lsptr = (struct felement *) extend_list(lsptr);
          }
          if(++elc_oa > max_element_count) {
            /* TODO: prop. we should just warn the user and stop grabbing dirs...? */
            fprintf(stderr, "ERROR: max_user_watches (%i) reached!\n", max_element_count);
            exit(EXIT_FAILURE);
          }else{
            if(strlen(path) > ELEMENT_SIZE) {
              fprintf(stderr, "ERROR: grabdirs(): path to long!\n");
              exit(EXIT_FAILURE);
            }else{
              memcpy((&lsptr[elc_oa])->path, path, strlen(path));
              //memcpy(&lsptr[elc_oa].festat, &tmp_stat, sizeof(struct stat));
              lsptr[elc_oa].id = elc_oa;
#ifdef _DEBUG
              printf("ADDED DIR: %s AS: %i\n", path, elc_oa);
#endif
            }
          }
        }else{
          continue;
        }
      }else{
        continue;
      }
    }else{
      break;
    }
  }
  closedir(dirfd);

  return lsptr;
}

/* small an nasty recursion wrapper */
struct felement *recwrap(char *initial_path, int recursive_depth, struct stat *statdat) {

  int recnt; /* temp. recusrion counter */
  int base, sticky, elc_oa_sticky; /* helper -> placemark */
  struct felement *lsptr;
  struct festat *felsptr;

  lsptr = init_list();
  if(diffstring != NULL) {
    felsptr = init_diff();
    memcpy((&felsptr[delc_oa])->path, initial_path, strlen(initial_path));
    memcpy(&felsptr[delc_oa].statdat, statdat, sizeof(struct stat));
    lsptr[delc_oa].id = delc_oa;
    delc_oa++;
  }

  /* adding initial path */
  memcpy((&lsptr[elc_oa])->path, initial_path, strlen(initial_path));
  lsptr[elc_oa].id = elc_oa;

  if((recursive_depth == 0) || (isdir((&lsptr[elc_oa])->path, NULL) == FALSE))
    return lsptr;

  for(base = elc_oa, recnt = 0; recnt < recursive_depth; recnt++, base++) {
    for(elc_oa_sticky = elc_oa, sticky = base; sticky <= elc_oa_sticky; sticky++) {
      if((lsptr = grabdirs((&lsptr[sticky])->path, lsptr, felsptr)) == NULL) {
        fprintf(stderr, "ERROR: grabdirs() returned NULL!\n");
        exit(EXIT_FAILURE);
      }
    }
  }

  return lsptr;
}
