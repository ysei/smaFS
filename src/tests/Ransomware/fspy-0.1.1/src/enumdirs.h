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

#ifndef _ENUMDIRS_H
#define _ENUMDIRS_H

#include "fspy.h"

#define ELEMENT_SIZE              1024
#define ELEMENT_INIT_COUNT        1024
#define DIFF_ELEMENT_INIT_COUNT   2048

#define NO_DIR                    NULL

int grab_max_element_count(void);
int pathlookup();
//struct felement *recwrap();
struct felement *recwrap(char *initial_path, int recursive_depth, struct stat *statdat);

#endif
