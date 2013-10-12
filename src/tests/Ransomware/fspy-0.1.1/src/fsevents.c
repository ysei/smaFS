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

#include "fsevents.h"

char *get_event_desc(int event, char *ptr) {

  char desc[128]={0};

  switch(event) {
    case FSPY_IN_ACCESS:
      sprintf(desc,"file was accessed");
      break;
    case FSPY_IN_MODIFY:
      sprintf(desc, "file was modified");
      break;
    case FSPY_IN_ATTRIB:
      sprintf(desc, "metadata changed");
      break;
    case FSPY_IN_CLOSE_WRITE:
      sprintf(desc, "writeable file was closed");
      break;
    case FSPY_IN_CLOSE_NOWRITE:
      sprintf(desc, "unwriteable file was closed");
      break;
    case FSPY_IN_OPEN:
      sprintf(desc, "file was opened");
      break;
    case FSPY_IN_MOVED_FROM:
      sprintf(desc, "file was moved from X");
      break;
    case FSPY_IN_MOVED_TO:
      sprintf(desc, "file was moved to Y");
      break;
    case FSPY_IN_CREATE:
      sprintf(desc, "file was created");
      break;
    case FSPY_IN_DELETE:
      sprintf(desc, "file was deleted");
      break;
    case FSPY_IN_DELETE_SELF:
      sprintf(desc, "self was deleted");
      break;
    case FSPY_IN_MOVE_SELF:
      sprintf(desc, "self was moved");
      break;
    case FSPY_IN_UNMOUNT:
      sprintf(desc, "backing fs was unmounted");
      break;
    case FSPY_IN_Q_OVERFLOW:
      sprintf(desc, "event queued overflowed");
      break;
    case FSPY_IN_IGNORED:
      sprintf(desc, "file was ignored");
      break;
    case FSPY_IN_DIR_CREATE:
      sprintf(desc, "dir was created");
      break;
    case FSPY_IN_DIR_ATTRIB:
      sprintf(desc, "metadata changed");
      break;
    case FSPY_IN_DIR_ACCESS_1:
      sprintf(desc, "dir access (1)");
      break;
    case FSPY_IN_DIR_ACCESS_2:
      sprintf(desc, "dir access (2)");
      break;
    case FSPY_IN_DIR_DELETE:
      sprintf(desc, "dir was deleted");
      break;
    default :
      sprintf(desc, "UNKNOWN: %x", event);
  }

  return memcpy(ptr, desc, strlen(desc));
}
