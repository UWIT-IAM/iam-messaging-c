# make library, then demos

INSTALL_DEST=/usr/local

all:	library demos

library:	
	(cd messagelib; make)

install:	
	(cd messagelib; make install)

clean:
	(cd messagelib; make clean)
	(cd demo; make clean)

demos:	
	(cd demo; make)
