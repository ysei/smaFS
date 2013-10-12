# This file is part of fspy
# #########################

BUILD = $(shell date +%Y%m%d%H)
#DEBUG = -g -D_DEBUG
OPTS = -DMAJORVERSION=0 -DMINORVERSION=1 -DSUBMINORVERSION=1 -DBUILD=$(BUILD) -DCODENAME=\"25c3\"
CFLAGS = -Wall
SDIR = src/
ODIR = obj/
INSTBINDIR = /usr/local/bin
SRCS = $(SDIR)fspy.c $(SDIR)enumdirs.c $(SDIR)fsevents.c $(SDIR)isnumber.c $(SDIR)stating.c $(SDIR)output.c $(SDIR)regmatch.c $(SDIR)numlen.c $(SDIR)adaptive.c $(SDIR)diff.c
OBJS = $(ODIR)fspy.o $(ODIR)enumdirs.o $(ODIR)fsevents.o $(ODIR)isnumber.o $(ODIR)stating.o $(ODIR)output.o $(ODIR)regmatch.o $(ODIR)numlen.o $(ODIR)adaptive.o $(ODIR)diff.o
CC = gcc
LD = gcc
LDFLAGS =
DFLAGS = 
RM = /bin/rm
PROG = fspy

all: $(PROG)

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(DFLAGS) $(DEBUG) $(OPTS) $(OBJS) -o $(PROG)

$(ODIR)%.o: $(SDIR)%.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(DFLAGS) $(DEBUG) $(OPTS) -c $< -o $(ODIR)$*.o

install:
	cp $(PROG) $(INSTBINDIR)/$(PROG)

clean:
	$(RM) $(PROG) $(ODIR)*.o

# DO NOT DELETE THIS LINE -- make depend depends on it.

fspy.o: fspy.h
enumdirs.o: enumdirs.h
fsevents.o: fsevents.h
isnumber.o: isnumber.h
stating.o: stating.h
output.o: output.h
regmatch.o: regmatch.h
numlen.o: numlen.h
adaptive.o: adaptive.h
diff.o: diff.h
