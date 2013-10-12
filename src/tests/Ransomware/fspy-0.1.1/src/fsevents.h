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

#ifndef _FSEVENTS_H
#define _FSEVENTS_H

/* most of these are taken from linux/inotify.h */

/* File was accessed */
#define FSPY_IN_ACCESS         0x00000001
/* File was modified */
#define FSPY_IN_MODIFY         0x00000002
/* Metadata changed */
#define FSPY_IN_ATTRIB         0x00000004
/* Writtable file was closed */
#define FSPY_IN_CLOSE_WRITE    0x00000008
/* Unwrittable file closed */
#define FSPY_IN_CLOSE_NOWRITE  0x00000010
/* File was opened */
#define FSPY_IN_OPEN           0x00000020
/* File was moved from X */
#define FSPY_IN_MOVED_FROM     0x00000040
/* File was moved to Y */
#define FSPY_IN_MOVED_TO       0x00000080
/* Subfile was created */
#define FSPY_IN_CREATE         0x00000100
/* Subfile was deleted */
#define FSPY_IN_DELETE         0x00000200
/* Self was deleted */
#define FSPY_IN_DELETE_SELF    0x00000400
/* Self was moved */
#define FSPY_IN_MOVE_SELF      0x00000800
/* Backing fs was unmounted */
#define FSPY_IN_UNMOUNT        0x00002000
/* Event queued overflowed */
#define FSPY_IN_Q_OVERFLOW     0x00004000
/* File was ignored */
#define FSPY_IN_IGNORED        0x00008000
/* Generic close */
#define FSPY_IN_CLOSE          (FSPY_IN_CLOSE_WRITE | FSPY_IN_CLOSE_NOWRITE)
/* Generic move */
#define FSPY_IN_MOVE           (FSPY_IN_MOVED_FROM | FSPY_IN_MOVED_TO)
/* Dir was created */
#define FSPY_IN_DIR_CREATE     0x40000100
/* Metadata changed */
#define FSPY_IN_DIR_ATTRIB     0x40000004
/* Dir was accessed (1) */
#define FSPY_IN_DIR_ACCESS_1   0x40000010
/* Dir was accessed (2) */
#define FSPY_IN_DIR_ACCESS_2   0x40000020
/* Generic dir access */
#define FSPY_IN_DIR_ACCESS     (FSPY_IN_DIR_ACCESS_1 |FSPY_IN_DIR_ACCESS_2)
/* Dir was deleted */
#define FSPY_IN_DIR_DELETE     0x40000200

/* Generic all file events */
#define FSPY_IN_ALL_FILE_EVENTS  (FSPY_IN_ACCESS | FSPY_IN_MODIFY | FSPY_IN_ATTRIB | FSPY_IN_CLOSE | \
                            FSPY_IN_OPEN | FSPY_IN_MOVE | FSPY_IN_CREATE | FSPY_IN_DELETE | \
                            FSPY_IN_DELETE_SELF | FSPY_IN_MOVE_SELF)

/* Generic all dir events */
#define FSPY_IN_ALL_DIR_EVENTS   (FSPY_IN_DIR_CREATE | FSPY_IN_DIR_ACCESS | FSPY_IN_DIR_DELETE | FSPY_IN_DIR_ATTRIB)

/* Generic all special events */
#define FSPY_IN_ALL_SPECIAL      (FSPY_IN_UNMOUNT | FSPY_IN_Q_OVERFLOW | FSPY_IN_IGNORED)

/* Genereic action needed events */
#define FSPY_IN_NEED_ACTION      (FSPY_IN_CREATE | FSPY_IN_DELETE | FSPY_IN_DELETE_SELF | FSPY_IN_MOVE_SELF | FSPY_IN_MOVED_FROM | FSPY_IN_MOVED_TO)

/* Generic all events */
#define FSPY_IN_ALL              (FSPY_IN_ALL_FILE_EVENTS | FSPY_IN_ALL_DIR_EVENTS | FSPY_IN_ALL_SPECIAL)

char *get_event_desc(int event, char *ptr);


#endif
