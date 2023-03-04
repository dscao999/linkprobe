CFLAGS = -Wall -g -D_GNU_SOURCE -pthread
LDFLAGS = -pthread

.PHONY:	clean all release

ALL = udpcom capether linkprobe checksum

all: $(ALL)

release: linkprobe capether checksum

release: CFLAGS += -O2 -DNDEBUG -flto

release: LDFLAGS += -Wl,-O2 -flto

udpcom: udpcom.o
	$(LINK.o) $^ -o $@

capether: capether.o enumnet.o ipudp.o
	$(LINK.o) $^ -o $@

linkprobe: linkprobe.o enumnet.o ipudp.o
	$(LINK.o) $^ -lrt -o $@

checksum: checksum.o ipudp.o
	$(LINK.o) $^ -o $@

clean:
	rm -rf *.o
	rm -rf $(ALL)

-include header-dep.mak
