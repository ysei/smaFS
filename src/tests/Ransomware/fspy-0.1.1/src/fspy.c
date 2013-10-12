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
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/inotify.h>

#include "fspy.h"
#include "enumdirs.h"
#include "fsevents.h"
#include "isnumber.h"
#include "numlen.h"
#include "regmatch.h"
#include "output.h"
#include "stating.h"
#include "adaptive.h"
#include "diff.h"

/* setting the sig_exit check var. */
volatile sig_atomic_t sigint = 1;

extern unsigned int max_element_count; /* from enumdirs.c */
extern unsigned int elc_oa; /* from enumdirs.c */
extern char twhitelst[]; /* from stating.c */
extern char dbasewhitelist[]; /* from diff.c */
extern struct diffprint dprint;

char *typestring = NULL;
char *diffstring = NULL;
char *filterstring = NULL;
char *ifilterstring = NULL;

static void print_help(void) {

  printf(
    "Usage: fspy [options] [file/dir]\n"
    "\n"
    "Options:\n"
    "  -F, --filter STRING/REGEX\ta string or regular expression which will be used to filter the output.\n"
    "                           \t(the regex will be matched against the whole path e.g. [/etc/passwd])\n"
    "  -I, --inverted STRING/REGEX\tits the same like -F/--filter but inverted. you can combine both.\n"
    "                           \te.g. -F '.conf' -I 'wvdial.conf' will filter for files with \".conf\"\n"
    "                           \tin its name but without \"wvdial.conf\" in it.\n"
    "  -R, --recursive NUMBER\tenables the recursive engine to look at a depth of NUMBER.\n"
    "  -A, --adaptive  \t\t(HIGHLY-EXPERIMENTAL) enables the adaptive mode. e.g. if new items will be added\n"
    "                  \t\twithin the path fspy will automatically add those items to the watch list.\n"
    "  -D, --diff VALUE\t\t(EXPERIMENTAL) enables the diffing feature.\n"
    "                  \t\tVALUE may be a comma separated list of:\n"
    "                  \t\ts - element size (byte)\n"
    "                  \t\tA - last access time (e.g. Mon Jul 21 21:32:31 2008)\n"
    "                  \t\tM - last modification time (e.g. Mon Jul 21 21:32:31 2008)\n"
    "                  \t\tS - last status change time (e.g. Mon Jul 21 21:32:31 2008)\n"
    "                  \t\tO - permissions (octal)\n"
    "                  \t\tU - owner (uid)\n"
    "                  \t\tG - group (gid)\n"
    "                  \t\tI - inode number\n"
    "                  \t\tD - device id\n"
    "  -T, --type VALUE\t\tspecifies the type of objects to look for.\n"
    "                  \t\tVALUE may be a comma separated list of:\n"
    "                  \t\tf - regular file\n"
    "                  \t\td - directory\n"
    "                  \t\ts - symlink\n"
    "                  \t\tp - FIFO/pipe\n"
    "                  \t\tc - character device\n"
    "                  \t\tb - block device\n"
    "                  \t\to - socket\n"
    "                  \t\tdefault is any.\n"
    "  -O, --output VALUE\t\tspecifies output format.\n"
    "                  \t\tVALUE may be a comma separated list of:\n"
    "                  \t\tf - filename\n"
    "                  \t\tp - path\n"
    "                  \t\td - access description\n"
    "                  \t\tt - element type\n"
    "                  \t\ts - element size (byte)\n"
    "                  \t\tw - watch descriptor (inotify manpage)\n"
    "                  \t\tc - cookie (inotify manpage)\n"
    "                  \t\tm - access mask (inotify manpage | src/fsevents.h)\n"
    "                  \t\tl - len (inotify manpage)\n"
    "                  \t\tA - last access time (e.g. Mon Jul 21 21:32:31 2008)\n"
    "                  \t\tM - last modification time (e.g. Mon Jul 21 21:32:31 2008)\n"
    "                  \t\tS - last status change time (e.g. Mon Jul 21 21:32:31 2008)\n"
    "                  \t\tO - permissions (octal)\n"
    "                  \t\tU - owner (uid)\n"
    "                  \t\tG - group (gid)\n"
    "                  \t\tI - inode number\n"
    "                  \t\tD - device id\n"
    "                  \t\tT - date and time (for this event) (e.g. Tue Mar 25 09:23:16 CET 2008)\n"
    //"                  \t\ti - timestamp (for this event) (seconds since 1970-01-01 00:00:00 UTC)\n"
    //"                  \t\tu - nanoseconds (for this event) (000000000..999999999)\n"
    "                  \t\te.g.: '[,T,], ,d,:,p,f' would result in:\n"
    "                  \t\t'[Mon Sep  1 12:31:25 2008] file was opened:/etc/passwd'\n"
    "                  \t\t(take a look at the README).\n"
    //"  -v, --verbose\t\t\tactivate verbose mode.\n"
    //"               \t\t\tuse twice (-vv) or more for more verbose output\n"
    "  -h, --help\t\t\tthis short help.\n"
    "      --version\t\t\tversion information.\n"
    "\n"
  );

  exit(EXIT_SUCCESS);
}

static void print_version(void) {

  printf( "version:\t %i.%i.%i\n"
          "build:\t\t %i\n"
          "codename:\t %s\n"
          "author:\t\t %s\n"
          "website:\t %s\n"
          , MAJORVERSION, MINORVERSION, SUBMINORVERSION,
            BUILD, CODENAME, AUTHOR, WEBSITE);

  exit(EXIT_SUCCESS);
}

static void my_sig_handle(int sig) {

#ifdef _DEBUG
  fprintf(stderr, "caught SIGINT - shutting down!\n");
#endif
  sigint = 0;
}

int main(int argc, char **argv) {

  unsigned int fd, wd, cnt = 0, len = 0, i = 0;
  char    buf[BUF_LEN], *path, *lpath = NULL;
  char    pbuf[EVENT_SIZE + 4096];
  char    fpath[ELEMENT_SIZE * 2] = {0};

  struct  inotify_event *event;
  struct  felement      *lsptr;
  struct  stat          *statdat;

  int     co, opt_idx = 0, verbose_lvl = 0, recursive_depth = 0;
  int     adaptive = FALSE;
  char    *tmp_filter_string = NULL, *tmp_ifilter_string = NULL;
  char    *tmp_recursive_depth = NULL, *tmp_output_string = NULL;
  char    *tmp_type_string = NULL, *tmp_diff_string = NULL, *tsp = NULL, *freeme;

  static const char *opt_str="F:R:O:T:I:D:Avh";

  static struct option long_opts[]={
    {"filter",          required_argument, NULL, 'F'},
    {"recursive",       required_argument, NULL, 'R'},
    {"diff",            required_argument, NULL, 'D'},
    {"output",          required_argument, NULL, 'O'},
    {"type",            required_argument, NULL, 'T'},
    {"inverted",        required_argument, NULL, 'I'},
    {"adaptive",        no_argument,       NULL, 'A'},
    {"verbose",         no_argument,       NULL, 'v'},
    {"help",            no_argument,       NULL, 'h'},
    {"version",         no_argument,       NULL,  0 },
    {0,                 0,                 NULL,  0 }
  };

  /* if no arguments are given... */
  if(argc < 2)
    print_help();

  while((co = getopt_long(argc, argv, opt_str, long_opts, &opt_idx)) != -1) {
    switch(co) {
      case 0:
        /* if this option sets a short opt, do nothing else now. */
        if(long_opts[opt_idx].flag != 0)
          break;
        if(strcmp("version", long_opts[opt_idx].name) == 0) {
          print_version();
          break;
        }
      case 'F':
        tmp_filter_string = strdup(optarg);
        break;
      case 'O':
        tmp_output_string = strdup(optarg);
        break;
      case 'D':
        tmp_diff_string = strdup(optarg);
        break;
      case 'T':
        tmp_type_string = strdup(optarg);
        break;
      case 'R':
        tmp_recursive_depth = strdup(optarg);
        break;
      case 'A':
        adaptive = TRUE;
        break;
      case 'I':
        tmp_ifilter_string = strdup(optarg);
        break;
      case 'v':
        verbose_lvl++;
        break;
      case 'h':
      default:
        print_help();
        break;
    }   
  }

  /* check which user calls "us" */
  if(geteuid() != 0) {
    fprintf(stdout, "WARNING: running fspy without root permissions might affect normal operation!\n");
  }

  /* if dir/file is missing */
  if((argc-optind) < 1)
    print_help();

  /* check the given recursive depth */
  if(tmp_recursive_depth != NULL) {
    if(isnumber(tmp_recursive_depth) == TRUE && strlen(tmp_recursive_depth) < (numlen(MAXRECURDEPTH) + 1)) {
      recursive_depth = atoi(tmp_recursive_depth);
      if(recursive_depth < MINRECURDEPTH || recursive_depth > MAXRECURDEPTH) {
        fprintf(stderr, "ERROR: value of argument '-R/--recursive' needs to be a number between %i and %i!\n", MINRECURDEPTH, MAXRECURDEPTH);
        exit(EXIT_FAILURE);
      }
      free(tmp_recursive_depth);
    }else{
      fprintf(stderr, "ERROR: value of argument '-R/--recursive' needs to be a number between %i and %i!\n", MINRECURDEPTH, MAXRECURDEPTH);
      exit(EXIT_FAILURE);
    }
  }

  /* check the given filter string */
  if(tmp_filter_string != NULL) {
    if(strlen(tmp_filter_string) > MAXREGEXLEN) {
      fprintf(stderr, "ERROR: the filter string/regex (-F/--filter) need not to be longer than %i chars!\n", MAXREGEXLEN);
      exit(EXIT_FAILURE);
    }else{
      if(reg_comp(tmp_filter_string) != TRUE) {
        fprintf(stderr, "ERROR: there is a problem with your string/regex (-F/--filter)!\n");
        exit(EXIT_FAILURE);
      }
      filterstring = tmp_filter_string;
    }
  }

  /* check the given inverted filter string */
  if(tmp_ifilter_string != NULL) {
    if(strlen(tmp_ifilter_string) > MAXREGEXLEN) {
      fprintf(stderr, "ERROR: the inverted filter string/regex (-I/--inverted) need not to be longer than %i chars!\n", MAXREGEXLEN);
      exit(EXIT_FAILURE);
    }else{
      if(ireg_comp(tmp_ifilter_string) != TRUE) {
        fprintf(stderr, "ERROR: there is a problem with your string/regex (-I/--inverted)!\n");
        exit(EXIT_FAILURE);
      }
      ifilterstring = tmp_ifilter_string;
    }
  }

  /* check the given type string */
  if(tmp_type_string != NULL) {
    if(strlen(tmp_type_string) > MAXTYPELEN) {
      fprintf(stderr, "ERROR: the type string (-T/--type) need not to be longer than %i chars!\n", MAXTYPELEN);
      exit(EXIT_FAILURE);
    }else{
      freeme = typestring = strdup(tmp_type_string);
      while((tsp = strtok(typestring, DELIM))) {
        if((strstr(twhitelst, tsp) == NULL) || (strlen(tsp) > 1)) {
          fprintf(stderr, "ERROR: invalid type/format in type string (-T/--type)!\n");
          exit(EXIT_FAILURE);
        }
        typestring = NULL;
      }
      free(freeme);
      typestring = NULL;
    }
  }

  /* check the given output string */
  if(tmp_output_string != NULL) {
    if(strlen(tmp_output_string) > MAXOUTSTRLEN) {
      fprintf(stderr, "ERROR: the output string (-O/--output) need not to be longer than %i chars!\n", MAXOUTSTRLEN);
      exit(EXIT_FAILURE);
    }
  }else{
    if((tmp_output_string = malloc(MAXOUTSTRLEN * sizeof(char))) == NULL) {
      fprintf(stderr, "ERROR: could not allocate mem for tmp_output_string (-O/--output)!\n");
      exit(EXIT_FAILURE);
    }
    sprintf(tmp_output_string, "%s", "[,T,], ,d,:,p,f");
  }

  /* check the given diff string */
  if(tmp_diff_string != NULL) {
    if(strlen(tmp_diff_string) > MAXDIFFSTRLEN) {
      fprintf(stderr, "ERROR: the diff string (-D/--diff) need not to be longer than %i chars!\n", MAXDIFFSTRLEN);
      exit(EXIT_FAILURE);
    }else{
      freeme = diffstring = strdup(tmp_diff_string);
      while((tsp = strtok(diffstring, DELIM))) {
        if((strstr(dbasewhitelist, tsp) == NULL) || (strlen(tsp) > 1)) {
          fprintf(stderr, "ERROR: invalid type/format in type string (-D/--diff)!\n");
          exit(EXIT_FAILURE);
        }
        diffstring = NULL;
      }
      free(freeme);
      freeme = diffstring = strdup(tmp_diff_string);
      tsp = NULL;
      while((tsp = strtok(diffstring, DELIM))) {
        if((strstr(tmp_output_string, tsp) == NULL) || (strlen(tsp) > 1)) {
          fprintf(stderr, "ERROR: diff string (-D/--diff) contains fields which are not contained within the output string (-O/--output)!\n");
          exit(EXIT_FAILURE);
        }
        diffstring = NULL;
      }
      free(freeme);
      diffstring = strdup(tmp_diff_string);
      free(tmp_diff_string);
    }
  }

  if((lpath = malloc(ELEMENT_SIZE * sizeof(char))) == NULL) {
    fprintf(stderr, "ERROR: could not allocate mem for lpath (path_lookup)!\n");
    exit(EXIT_FAILURE);
  }

  if((path = malloc(ELEMENT_SIZE * sizeof(char))) == NULL) {
    fprintf(stderr, "ERROR: could not allocate mem for initial path variable!\n");
    exit(EXIT_FAILURE);
  }

  if((statdat = (struct stat *) malloc(sizeof(struct stat))) == NULL) {
    fprintf(stderr, "ERROR: could not allocate mem for statdat (main)!\n");
    exit(EXIT_FAILURE);
  }

  /* setting the signal handler */
  if(signal(SIGINT, my_sig_handle) == SIG_ERR) {
    perror("signal()");
  }

  /* getting an inotify instance */
  if((fd = inotify_init()) < 0) {
    perror("inotify_init()");
    exit(EXIT_FAILURE);
  }

  //TODO: cleanup! error checks! plausibility checks!
  max_element_count = grab_max_element_count();

  init_free_wds(fd); /* init the list which will hold the freed wds */

#ifdef _DEBUG
  printf("MAX_ELEMENTS: %i\n", max_element_count);
#endif

  if(strlen((argv+optind)[0]) > ELEMENT_SIZE) {
    fprintf(stderr, "ERROR: the given path/file string is to long!\n");
    exit(EXIT_FAILURE);
  }else{
    memcpy(path, (argv+optind)[0], strlen((argv+optind)[0]));
    if(statit(path, statdat) != TRUE) {
      fprintf(stderr, "ERROR: main()->statit() returned != TRUE!\n");
      exit(EXIT_FAILURE);
    }
    if(isdir(path, statdat) == TRUE)
      if(path[strlen(path)-1] != '/')
        strcat(path, "/");
  }

#ifdef _DEBUG
  printf("INIT_PATH: %s\n", path);
#endif

  /* at this point we hand the dirty work over to the recursive directory parser */
  lsptr = (struct felement *) recwrap(path, recursive_depth, statdat);
  
  while(cnt <= elc_oa) {

#ifdef _DEBUG
    printf("ADDING: %s %i", (&lsptr[cnt])->path, cnt);
#endif

    /* adding a watch */
    if((wd = inotify_add_watch(fd, (&lsptr[cnt])->path, IN_ALL_EVENTS)) < 0) {
      perror("inotify_add_watch()");
      exit(EXIT_FAILURE);
    }
    lsptr[cnt++].wd = wd;

#ifdef _DEBUG
    printf(" wd: %i\n", lsptr[cnt-1].wd);
#endif

  }

  /* loop unitl SIGINT arrives */
  while(sigint) {
    /* reading inotify_event data from the given inotify instance */
    if((len += read(fd, buf + len, BUF_LEN - len)) < 0) {
      perror("read()");
    }else{
      while(sigint) {
        if(len < EVENT_SIZE) {
          break;
        }else if(len >= EVENT_SIZE) {
          memset(pbuf, 0, EVENT_SIZE + 4096);
          memcpy(pbuf, buf, EVENT_SIZE);
          event = (struct inotify_event *) pbuf;
          if((event->len > 0) && ((EVENT_SIZE + event->len) <= len)) {
            memcpy(pbuf, buf, EVENT_SIZE + event->len);
          }else if((EVENT_SIZE + event->len) > len) {
            break;
          }
        }

        if((event->len == 0) && (elc_oa == 1)) {
          strcat(event->name, path);
        }else{
          memset(lpath, 0, ELEMENT_SIZE);
          /* check if there is a path available for this element */
          if(pathlookup(lpath, event->wd, lsptr) == FALSE)
            strcat(lpath, "|PATH_LOOKUP_ERROR|");
        }

        memset(statdat, 0, sizeof(struct stat));
        memset(fpath, 0, (ELEMENT_SIZE * 2));

        snprintf(fpath, (ELEMENT_SIZE * 2), "%s%s", lpath, event->name);

        if(statit(fpath, statdat) != TRUE) {
          fprintf(stderr, "ERROR: main()->statit() returned != TRUE!\n");
          exit(EXIT_FAILURE);
        }

        if(isdir(fpath, statdat) == TRUE)
          if(fpath[strlen(fpath)-1] != '/')
            strcat(fpath, "/");

        if(((filterstring != NULL) ? (reg_match(fpath) == TRUE):TRUE) && ((ifilterstring != NULL) ? (ireg_match(fpath) == TRUE):TRUE) && ((typestring != NULL) ? (checktype(lpath, (struct inotify_event *) event, typestring, statdat) == TRUE):TRUE)) {
          if(adaptive == TRUE)
            adaptive_check(event->mask, fpath, lsptr, statdat, event->wd);
          if(diffstring != NULL) {
            dprint.s = dprint.A = dprint.M = dprint.S = dprint.O = dprint.U = dprint.G = dprint.G = dprint.I = dprint.D = 0;
            diffing(fpath, statdat, &dprint, diffstring);
          }
          /* TODO: change print_data to use fpath instead of lpath and assembling the fqp on its own */
          print_data(tmp_output_string, (struct inotify_event *) event, lpath, statdat, &dprint);
          if(((len > EVENT_SIZE) && (event->len == 0)) || (len > (EVENT_SIZE + event->len) && (event->len > 0)))
            goto more;
        }

        memset(buf, 0, BUF_LEN);
        len = 0;

        break;

        more:

        memmove(buf, buf + (EVENT_SIZE + event->len), (len - (EVENT_SIZE + event->len)));
        memset(buf + (len - (EVENT_SIZE + event->len)), 0, BUF_LEN - (len - (EVENT_SIZE + event->len)));
        len = (len - (EVENT_SIZE + event->len));
      }
    }
  }

  /* destroying regular expression element */
  reg_dest();

#ifdef _DEBUG
  printf("elc_oa: %i\n", elc_oa);
#endif

  /* destroying wd's */
  for(i = 0 ; i <= elc_oa ; i++) {
#ifdef _DEBUG
  printf("removing number -> %i wd -> %i\n", i ,lsptr[i].wd);
#endif
    if(inotify_rm_watch(fd, lsptr[i].wd) != 0) {
      if(errno == EBADF) {
        perror("inotify_rm_watch()");
        exit(EXIT_FAILURE);
      }else{
#ifdef _DEBUG
        fprintf(stderr, "WARNING: inotify_rm_watch(): Invalid argument: maybe a symlink issue?\n");
#endif
      }
    }
  }

  /* destroying element structure */
  free(lsptr);

  /* freeing helpers */
  free(statdat);
  free(tmp_output_string);
  free(lpath);
  free(path);

#ifdef _DEBUG
  printf("safely shutting down...\n");
#endif

  return 0;
}
