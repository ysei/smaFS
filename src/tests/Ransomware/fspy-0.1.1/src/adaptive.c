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
#include <limits.h> /* definition of UINT_MAX */
#include <sys/inotify.h>
#include <sys/stat.h> /* struct stat */
#include <errno.h>

#include "fspy.h"
#include "fsevents.h"
#include "adaptive.h"
#include "enumdirs.h" /* needed for max_element_count */
#include "stating.h"

extern unsigned int max_element_count; /* from enumdirs.c */
extern unsigned int elc_oa; /* from enumdirs.c */

unsigned int *free_wds; /* holds the freed wds - faster reuse */
unsigned int fd; /* module global - the inotify file descriptor */

void init_free_wds(unsigned int fdin) {

  unsigned int i;

  fd = fdin;

  if((free_wds = (unsigned int *) malloc(max_element_count * sizeof(unsigned int))) == NULL) {
    fprintf(stderr, "ERROR: could not allocate mem for initial free wds list!\n");
    exit(EXIT_FAILURE);
  }

  for(i=0; i <= max_element_count; i++) {
    free_wds[i] = UINT_MAX;
  }

#ifdef _DEBUG
  printf("INIT_FREE_WDS_LIST: %i\n", max_element_count);
#endif
}

void adaptive_add(const char *path, struct felement *lsptr, struct stat *statdat) {

  unsigned int wd, i, id = UINT_MAX;

  if(isdir(path, statdat) != TRUE)
    return;

  /* searching the empty element list for a reusable entry */
  for(i=0; i <= max_element_count; i++) {
    if(free_wds[i] != UINT_MAX) {
      id = free_wds[i];
      break;
    }
  }

  if(id == UINT_MAX)
    id = ++elc_oa;

#ifdef _DEBUG
  printf("ADDING: %s %i\n", path, elc_oa);
#endif
  
  if((wd = inotify_add_watch(fd, path, IN_ALL_EVENTS)) < 0) {
    perror("inotify_add_watch()");
    exit(EXIT_FAILURE);
  }

  memcpy((&lsptr[id])->path, path, strlen(path));
  //memcpy(&lsptr[id].festat, statdat, sizeof(struct stat));
  lsptr[id].id = id;  
  lsptr[id].wd = wd;  
}

void adaptive_delete(const char *path, struct felement *lsptr, unsigned int wd) {

  if(wd == 1) /* dirty workaround! */
    return;

  unsigned int i, id;

  /* getting the element id */
  for(i=0; i <= elc_oa; i++) {
    if(lsptr[i].wd == wd) {
      id = lsptr[i].id;
      break;
    }
  }

#ifdef _DEBUG
  printf("removing wd -> %i path -> %s\n", wd, path);
#endif
  if(inotify_rm_watch(fd, wd) != 0) {
    if(errno == EBADF) {
      perror("inotify_rm_watch()");
      exit(EXIT_FAILURE);
    }else{
#ifdef _DEBUG
      fprintf(stderr, "WARNING: inotify_rm_watch(): Invalid argument: maybe a symlink issue?\n");
#endif
    }
  }

  /* adding the empty element list entry to the available entries list */
  for(i=0; i <= max_element_count; i++) {
    if(free_wds[i] == UINT_MAX) {
      free_wds[i] = id;
      break;
    }
  }

  //elc_oa--;
  return;
}

int adaptive_action(int event_mask, const char *path, struct felement *lsptr, struct stat *statdat, unsigned int wd) {

  switch(event_mask) {
    case FSPY_IN_DIR_CREATE:
          adaptive_add(path, lsptr, statdat);
          break;
    /*case FSPY_IN_DIR_DELETE:
          adaptive_delete(path, wd);
          break;*/
    case FSPY_IN_DELETE_SELF:
          adaptive_delete(path, lsptr, wd);
          break;
    /*case FSPY_IN_MOVE_SELF:
          break;
    case FSPY_IN_MOVED_FROM:
          adaptive_delete(path, lsptr, statdat);
          break;
    case FSPY_IN_MOVED_TO:
          adaptive_add(path, lsptr, statdat);
          break;*/
    default :
          return FALSE;
          break;
  }

  return TRUE; /* foo */
}

int adaptive_check(int event_mask, const char *path, struct felement *lsptr, struct stat *statdat, unsigned int wd) {

  if(event_mask & FSPY_IN_NEED_ACTION) {
    if(adaptive_action(event_mask, path, lsptr, statdat, wd) == TRUE)
      return TRUE;
  }

  return FALSE;
}
