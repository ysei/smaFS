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
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "fspy.h"
#include "stating.h"
#include "output.h"

/* little helper variable... do not miss to update when more types are added! */
char twhitelst[] = "fdspcbo";

char *gettype(const char *fpath, char *ptr, struct stat *statdat) {

  char desc[128] = {0};
  
  switch (statdat->st_mode & S_IFMT) {
    case S_IFBLK:
      sprintf(desc, "block device");
      break;
    case S_IFCHR:
      sprintf(desc, "character device");
      break;
    case S_IFDIR:
      sprintf(desc, "directory");
      break;
    case S_IFIFO:
      sprintf(desc, "FIFO/pipe");
      break;
    case S_IFLNK:
      sprintf(desc, "symlink");
      break;
    case S_IFREG:
      sprintf(desc, "regular file");
      break;
    case S_IFSOCK:
      sprintf(desc, "socket");
      break;
    default:
      sprintf(desc, "UNKNOWN: %u", (statdat->st_mode & S_IFMT));
      break;
  }

  return memcpy(ptr, desc, strlen(desc));
}

int checktype(const char *event_fpath, struct inotify_event *event, char *tstring, struct stat *statdat) {

  char mychar;
  char *tstring_tmp, *mystr;
  char *freeme;

  struct stat sb;

  char fpath[ELEMENT_SIZE * 2] = {0};

  /* because we call it from multiple locations... */
  if(event == NULL) {
    snprintf(fpath, (ELEMENT_SIZE * 2), "%s", event_fpath);
  }else{
    snprintf(fpath, (ELEMENT_SIZE * 2), "%s%s", event_fpath, event->name);
  }

  tstring_tmp = strdup(tstring);

  if(statdat == NULL) {
    if(statit(fpath, &sb) != TRUE) {
      fprintf(stderr, "ERROR: checktype()->statit() returned != TRUE!\n");
      exit(EXIT_FAILURE);
    }
  }else{
    memcpy(&sb, statdat, sizeof(struct stat));
  }
  
  while((mystr = strtok(tstring_tmp, DELIM))) {
    if(strlen(mystr) == 1) {
      mychar = mystr[0];

      /* ATTENTION: do not miss to update *twhitelst at the top of this file! */

      switch(mychar) {
        case  'f':  if((sb.st_mode & S_IFMT) == S_IFREG)
                      return TRUE;
                    break;
        case  'd':  if((sb.st_mode & S_IFMT) == S_IFDIR)
                      return TRUE;
                    break;
        case  's':  if((sb.st_mode & S_IFMT) == S_IFLNK)
                      return TRUE;
                    break;
        case  'p':  if((sb.st_mode & S_IFMT) == S_IFIFO)
                      return TRUE;
                    break;
        case  'c':  if((sb.st_mode & S_IFMT) == S_IFCHR)
                      return TRUE;
                    break;
        case  'b':  if((sb.st_mode & S_IFMT) == S_IFBLK)
                      return TRUE;
                    break;
        case  'o':  if((sb.st_mode & S_IFMT) == S_IFSOCK)
                      return TRUE;
                    break;
        default  :  /* TODO: not existant! we should check that at startup! */
                    break;
      }
    }else{
      /* TODO: implement a startup check for this value...
               it should be of a type like this: a,b,c,d,e */
    }

    freeme = tstring_tmp;
    tstring_tmp = NULL;
  }

  free(freeme);

  return FALSE;
}

int isdir(const char *path, struct stat *statdat) {

  struct stat sb;

  if(statdat == NULL) {
#ifdef _DEBUG
  printf("isdir()->STATING: %s\n", path);
#endif
    if(statit(path, &sb) != TRUE) {
      if(errno != 0) {
        perror("isdir()->stat()");
      }
      return FALSE;
    }
    if(S_ISDIR(sb.st_mode))
      return TRUE;
    
    return FALSE;
  }

  if(S_ISDIR(statdat->st_mode))
    return TRUE;

  return FALSE;
}

int statit(const char *path, struct stat *buf) {

#ifdef _DEBUG
  printf("statit()->STATING: %s\n", path);
#endif

  /* TODO: add exception handling for all different types of errno's */
  if(stat(path, buf) != 0) {
    if(errno == ENOENT) {
#ifdef _DEBUG
  printf("WARNING: file \"%s\" does not exist (deleted?)!\n", path);
#endif
    }else{
      perror("statit()->stat()");
      return FALSE;
    }
  }

  return TRUE;
}
