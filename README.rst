smaFS
=====

smaFS is a generic file system overlay implemented using FUSE which is capable
of providing file-level snapshots, transparent versioning and recovery to
any-point-in-time on top of any existing file system.

This is an old project of mine from year 2009.

Limitations & Improvements
--------------------------

1) Calculate hash and perform compression blockwise within with make_copy() function loop.
   The implementation should be straightforward and save on multiple duplicate file read operations.
   The current version of smaFS does extra reads for implementing compression and hashing.

2) Lazy metadata commit: Metadata can be cached in memory and flushed to disk later.
   This should boost the performane on update intensive workload.

3) .store directory where metadata and version history is stored is weakly protected by
   and setuid utitlities. A better security should be researched.

4) reaper requires complete re-write of metadata file.

5) Requires "user_allow_other" option in /etc/fuse.conf

6) Add support for directory versioning.

7) Better security.

BUGS
----

What bugs? This software has no bugs!



