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
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>

#include "fspy.h"
#include "output.h"
#include "fsevents.h"
#include "stating.h"

/* the base of allowed diffable fields */
/* do not forget to modify this list as needed! */
char dbasewhitelist[] = "sAMSOUGID";

/* holds the fields to be printed colored */
struct diffprint dprint;

/* holds all the needed data to perform a diff */
struct festat *felsptr;

/* global diffing element counter */
unsigned int delc_oa = 0;

struct festat *init_diff(void) {

  dprint.s = dprint.A = dprint.M = dprint.S = dprint.O = dprint.U = dprint.G = dprint.G = dprint.I = dprint.D = 0;

  if((felsptr = (struct festat *) malloc(DIFF_ELEMENT_INIT_COUNT * sizeof(struct festat))) == NULL) {
    fprintf(stderr, "ERROR: could not allocate mem for initial festat list!\n");
    exit(EXIT_FAILURE);
  }

#ifdef _DEBUG
  printf("INIT_FESTAT_LIST: %i\n", DIFF_ELEMENT_INIT_COUNT);
#endif

  return felsptr;
}

struct festat *extend_diff_list(struct festat *felsptr) {

  if((felsptr = (struct festat *) realloc(felsptr, (delc_oa + DIFF_ELEMENT_INIT_COUNT) * sizeof(struct festat))) == NULL) {
    fprintf(stderr, "ERROR: could not reallocate mem to extend dir list!\n");
    exit(EXIT_FAILURE);
  } 

#ifdef _DEBUG
  printf("EXTEND_DIFF_LIST: %i (%i)\n", delc_oa + DIFF_ELEMENT_INIT_COUNT, (delc_oa + DIFF_ELEMENT_INIT_COUNT) * sizeof(struct festat));
#endif

  return felsptr;
}

void diffing(char *fpath, struct stat *statdat, struct diffprint *dprintptr, char *diffstring) {

  char *mystrin_tmp;
  char *mystr;
  char mychar;
  char *freeme;

  unsigned int i, id;

#ifdef _DEBUG
  printf("DIFFING: %s\n", fpath);
#endif

  /* getting the element id */
  for(i=0; i <= delc_oa; i++) {
    if(strcmp(felsptr[i].path, fpath) == 0) {
      id = felsptr[i].id;
      break;
    }
  }

  mystrin_tmp = strdup(diffstring);

  while((mystr = strtok(mystrin_tmp, DELIM))) {
    if(strlen(mystr) == 1) {
      mychar = mystr[0];

      switch(mychar) {
        case  's':  if(memcmp(&felsptr[i].statdat.st_size, &statdat->st_size, sizeof(off_t))) {
                      dprintptr->s = 1;
                      memcpy(&felsptr[i].statdat.st_size, &statdat->st_size, sizeof(off_t));
                    }
                    break;
        case  'A':  if(memcmp(&felsptr[i].statdat.st_atime, &statdat->st_atime, sizeof(time_t))) {
                      dprintptr->A = 1;
                      memcpy(&felsptr[i].statdat.st_atime, &statdat->st_atime, sizeof(time_t));
                    }
                    break;
        case  'M':  if(memcmp(&felsptr[i].statdat.st_mtime, &statdat->st_mtime, sizeof(time_t))) {
                      dprintptr->M = 1;
                      memcpy(&felsptr[i].statdat.st_mtime, &statdat->st_mtime, sizeof(time_t));
                    }
                    break;
        case  'S':  if(memcmp(&felsptr[i].statdat.st_ctime, &statdat->st_ctime, sizeof(time_t))) {
                      dprintptr->S = 1;
                      memcpy(&felsptr[i].statdat.st_ctime, &statdat->st_ctime, sizeof(time_t));
                    }
                    break;
        case  'O':  if(memcmp(&felsptr[i].statdat.st_mode, &statdat->st_mode, sizeof(mode_t))) {
                      dprintptr->O = 1;
                      memcpy(&felsptr[i].statdat.st_mode, &statdat->st_mode, sizeof(mode_t));
                    }
                    break;
        case  'U':  if(memcmp(&felsptr[i].statdat.st_uid, &statdat->st_uid, sizeof(uid_t))) {
                      dprintptr->U = 1;
                      memcpy(&felsptr[i].statdat.st_uid, &statdat->st_uid, sizeof(uid_t));
                    }
                    break;
        case  'G':  if(memcmp(&felsptr[i].statdat.st_gid, &statdat->st_gid, sizeof(gid_t))) {
                      dprintptr->G = 1;
                      memcpy(&felsptr[i].statdat.st_gid, &statdat->st_gid, sizeof(gid_t));
                    }
                    break;
        case  'I':  if(memcmp(&felsptr[i].statdat.st_ino, &statdat->st_ino, sizeof(ino_t))) {
                      dprintptr->I = 1;
                      memcpy(&felsptr[i].statdat.st_ino, &statdat->st_ino, sizeof(ino_t));
                    }
                    break;
        case  'D':  if(memcmp(&felsptr[i].statdat.st_dev, &statdat->st_dev, sizeof(dev_t))) {
                      dprintptr->D = 1;
                      memcpy(&felsptr[i].statdat.st_dev, &statdat->st_dev, sizeof(dev_t));
                    }
                    break;
        default  :  printf("diffing()->WARNING: This should never happen!!!\n");
                    break;
      }
    }

    freeme = mystrin_tmp;
    mystrin_tmp = NULL;
  }

  free(freeme);
}
