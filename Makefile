CFLAGS = -Wall -g -D_GNU_SOURCE -pthread
LDFLAGS = -pthread

.PHONY:	clean all release

ALL = udpcom capether linkprobe checksum txmmap tcprobe

all: $(ALL)

release: linkprobe capether checksum tcprobe

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

txmmap: txmmap.o
	$(LINK.o) $^ -o $@

tcprobe: tcprobe.o
	$(LINK.o) $^ -lrt -o $@

tstmod: CFLAGS = -Wall -g -D_GNU_SOURCE
tstmod: LDFLAGS =

tstmod:	test_kmod.o kmod.o pktgen.o
	$(LINK.o) $^ -o $@

clean:
	rm -rf *.o
	rm -rf $(ALL) tstmod

-include header-dep.mak
