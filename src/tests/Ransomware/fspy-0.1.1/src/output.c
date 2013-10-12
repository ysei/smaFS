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
#include "diff.h"


void print_data(char *mystrin, struct inotify_event *event, const char *event_fpath, struct stat *statdat, struct diffprint *dprint) {

  char *mystrin_tmp;
  char *mystr;
  char mychar;
  char desc_ptr[128] = {0};
  char *ctp;
  char fpath[ELEMENT_SIZE * 2] = {0};
  char *freeme;

  const char *const normal = "\033[0m";
  const char *const marked = "\033[1;31m";

  time_t currtime;
  
  snprintf(fpath, (ELEMENT_SIZE * 2), "%s%s", event_fpath, event->name);

  mystrin_tmp = strdup(mystrin);

  while((mystr = strtok(mystrin_tmp, DELIM))) {
    if(strlen(mystr) == 1) {
      mychar = mystr[0];

      switch(mychar) {
        case  'f':  printf("%s", event->name);
                    break;
        case  'p':  printf("%s", event_fpath);
                    break;
        case  'd':  memset(desc_ptr, 0, 128 * sizeof(char)); 
                    printf("%s", get_event_desc(event->mask, desc_ptr));
                    break;
        case  'w':  printf("%i", event->wd);
                    break;
        case  'c':  printf("%u", event->cookie);
                    break;
        case  'm':  printf("0x%08x", event->mask);
                    break;
        case  'l':  printf("%u", event->len);
                    break;
        case  't':  memset(desc_ptr, 0, 128 * sizeof(char)); 
                    printf("%s", gettype(fpath, desc_ptr, statdat));
                    break;
                    /* yeah, i know, thats some kind of dirty style ;)
                       but i dont like the additional newline at EOL... */
        case  'A':  ctp = ctime(&statdat->st_atime); ctp[strlen(ctp) - 1] = '\0';
                    (dprint->A == 1)?printf("%s%s%s", marked, ctp, normal):printf("%s", ctp);
                    break;
        case  'M':  ctp = ctime(&statdat->st_mtime); ctp[strlen(ctp) - 1] = '\0';
                    (dprint->M == 1)?printf("%s%s%s", marked, ctp, normal):printf("%s", ctp);
                    break;
        case  'S':  ctp = ctime(&statdat->st_ctime); ctp[strlen(ctp) - 1] = '\0';
                    (dprint->S == 1)?printf("%s%s%s", marked, ctp, normal):printf("%s", ctp);
                    break;
        case  'T':  currtime = time(NULL);
                    ctp = ctime(&currtime); ctp[strlen(ctp) - 1] = '\0';
                    printf("%s", ctp);
                    break;
        case  's':  (dprint->s == 1)?printf("%s%lld%s", marked, (long long int) statdat->st_size, normal):printf("%lld", (long long int) statdat->st_size);
                    break;
        case  'U':  (dprint->U == 1)?printf("%s%ld%s", marked, (long int) statdat->st_uid, normal):printf("%ld", (long int) statdat->st_uid);
                    break;
        case  'G':  (dprint->G == 1)?printf("%s%ld%s", marked, (long int) statdat->st_gid, normal):printf("%ld", (long int) statdat->st_gid);
                    break;
        case  'O':  (dprint->O == 1)?printf("%s%lo%s", marked, (unsigned long int) statdat->st_mode, normal):printf("%lo", (unsigned long int) statdat->st_mode);
                    break;
        case  'I':  (dprint->I == 1)?printf("%s%ld%s", marked, (long int) statdat->st_ino, normal):printf("%ld", (long int) statdat->st_ino);
                    break;
        case  'D':  (dprint->D == 1)?printf("%s%ld%s", marked, (long int) statdat->st_dev, normal):printf("%ld", (long int) statdat->st_dev);
                    break;
        default  :  printf("%c", mychar);
                    break;
      }
    }else{
      printf("%s", mystr);
    }

    freeme = mystrin_tmp;
    mystrin_tmp = NULL;
  }

  printf("\n");

  free(freeme);
}
