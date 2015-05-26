
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
  installs the includes in INSTALL_ROOT/include


