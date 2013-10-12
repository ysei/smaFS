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

#ifndef _FSPY_H
#define _FSPY_H

#include <sys/stat.h> /* required -> struct stat */
#include "enumdirs.h" /* needed -> ELEMENT_SIZE */

#define AUTHOR    "Richard Sammet (e-axe) <richard.sammet@gmail.com>"
#define WEBSITE   "http://mytty.org/fspy/"

#define TRUE  1
#define FALSE 0

/* how long could a regex be? */
#define MAXREGEXLEN     128
/* how long could a typestring be? */
#define MAXTYPELEN      128
/* how long could a output string be? */
#define MAXOUTSTRLEN    128
/* how long could a diff string be? */
#define MAXDIFFSTRLEN   MAXOUTSTRLEN 
/* how deep you wanna look into your folder hirachie? */
#define MINRECURDEPTH   1
#define MAXRECURDEPTH   99
/* size of the event structure, not counting name */
#define EVENT_SIZE      (sizeof(struct inotify_event))
/* reasonable guess as to size of 1024 events */
#define BUF_LEN         (1024 * (EVENT_SIZE + 16))

typedef int boolean_t;

struct felement {
  unsigned int id;
  unsigned int wd;
  char path[ELEMENT_SIZE];
};

struct festat {
  unsigned int id;
  char path[ELEMENT_SIZE];
  struct stat statdat;
};

struct diffprint {
  unsigned int s;
  unsigned int A;
  unsigned int M;
  unsigned int S;
  unsigned int O;
  unsigned int U;
  unsigned int G;
  unsigned int I;
  unsigned int D;
};

#endif
