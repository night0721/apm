.POSIX:
.SUFFIXES:

CC=cc

VERSION=1.0.0
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man

CFLAGS = -O3 -march=native -mtune=native -pipe -s -std=c99 -pedantic -Wall -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600 -lsodium 

SRC = argon.c

argon: argon.c
	${CC} ${SRC} -o $@ ${CFLAGS}

clean:
	rm -rf argon

dist: version argon
	mkdir -p argon-${VERSION}
	cp -R LICENSE README.md argon.1 argon argon-${VERSION}
	tar -cf argon-${VERSION}.tar argon-${VERSION}
	gzip argon-${VERSION}.tar
	rm -rf argon-${VERSION}

install: all
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp -f argon ${DESTDIR}${PREFIX}/bin
	chmod 755 ${DESTDIR}${PREFIX}/bin/argon
	mkdir -p ${DESTDIR}${MANPREFIX}/man1
	cp argon.1 ${DESTDIR}${MANPREFIX}/man1/argon.1
	chmod 644 ${DESTDIR}${MANPREFIX}/man1/argon.1

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/argon\
		${DESTDIR}${MANPREFIX}/man1/argon.1
all: argon

.PHONY: all clean dist install uninstall argon
