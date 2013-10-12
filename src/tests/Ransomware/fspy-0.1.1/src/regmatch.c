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
#include <sys/types.h>
#include <errno.h>
#include <regex.h>

#include "fspy.h"

regex_t re;
regex_t ire;

int reg_comp(char *pattern) {

  if(regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB|REG_EESCAPE) != 0) {
    perror("reg_comp()");
    return FALSE;
  }

  return TRUE;
}

int ireg_comp(char *pattern) {

  if(regcomp(&ire, pattern, REG_EXTENDED|REG_NOSUB|REG_EESCAPE) != 0) {
    perror("ireg_comp()");
    return FALSE;
  }

  return TRUE;
}

int reg_match(const char *string) {

  if(regexec(&re, string, (size_t) 0, NULL, 0) != 0) {
    return FALSE;
  }

  return TRUE;
}

int ireg_match(const char *string) {

  if(!(regexec(&ire, string, (size_t) 0, NULL, 0) != 0)) {
    return FALSE;
  }

  return TRUE;
}

void reg_dest(void) {

  (void) regfree(&re);
}
