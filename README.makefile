
I included only a simple linux makefile.  The overhead of autotools
seemed too much for this library.

You have to edit the makefile for your install root.

  INSTALL_ROOT=/usr/local
or
  INSTALL_ROOT=/data/local
etc.

$ make 

  compiles everything and stores the library in lib/

$ make install

  installs the library in INSTALL_ROOT/lib
  installs the includes in INSTALL_ROOT/include/iam-messaging


==========================

Note.  The library works from includes in the source. 
But includes are installed in (root)/include/iam-messaging

so your apps must use, e.g.

  #include <iam-messaging/iam_crypt.h>

This is to avoid collisions and keep the install dir cleaner.

Jim

