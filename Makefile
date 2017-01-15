ifeq "$(ARCH)" ""
	override ARCH := $(shell uname -m)
endif

CFLAGS=-Wall -c -I.
AS=$(CC) -c
LIBS=-lresolv
DNSPROXY=dns_proxy.o coroutine-ucontext.o qemu-coroutine.o local_ns_parser.o

LIB=libtask.a
ifeq ($(ARCH),mips)
	ASM=asm.o
	OFILES=$(ASM) context.o
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	CFLAGS += -D_XOPEN_SOURCE
else
	LIBS += -pthread
endif

all: $(LIB) dns_proxy

%.o: %.S
	$(AS) $*.S

%.o: %.c
	$(CC) $(CFLAGS) $*.c

$(LIB): $(OFILES)
ifeq ($(ARCH),mips)
	ar rvc $(LIB) $(OFILES)
endif

dns_proxy: $(DNSPROXY) $(LIB)
ifeq ($(ARCH),mips)
	$(CC) $(LIBS) -o dns_proxy $(DNSPROXY) $(LIB)
else
	$(CC) $(LIBS) -o dns_proxy $(DNSPROXY)
endif

.PHONY: clean

clean:
	-rm -f dns_proxy *.o *.a
