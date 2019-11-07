#
#       Copyright (C) 2007 Bill DuPree, All rights reserved
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#

# Linux gcc compiler
CC		= gcc
WARNINGS	= -Wall
COMPILE		= -pipe -O2
#DEBUG		= -ggdb
LD_OPT		= -s

CFLAGS = $(DEBUG) $(WARNINGS) $(COMPILE)
SRCS    = sshutout.c

OBJS  = $(SRCS:.c=.o)

sshutout: $(SRCS) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) $(LD_OPT) -o $@ $(OBJS)

install: sshutout
	cp sshutout /usr/local/sbin/sshutout
	chown root:root /usr/local/sbin/sshutout
	chmod 755 /usr/local/sbin/sshutout
	if [ -r /etc/sshutout.conf ]; then mv /etc/sshutout.conf /etc/sshutout.conf~; fi 
	cp sshutout.conf /etc/sshutout.conf
	chown root:root /etc/sshutout.conf
	chmod 640 /etc/sshutout.conf
	if [ ! -d /usr/man/man8 ]; then mkdir -m 755 /usr/man/man8; fi
	cp sshutout.8 /usr/man/man8/sshutout.8
	chown root:root /usr/man/man8/sshutout.8
	chmod 644 /usr/man/man8/sshutout.8

clean:
	rm -f $(OBJS) sshutout core
