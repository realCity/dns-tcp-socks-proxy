UNAME_S := $(shell uname -s)
FLAGS = -Wall -Wextra

ifeq ($(UNAME_S),Darwin)
	FLAGS += -D_XOPEN_SOURCE
endif

all:
	$(CC) $(FLAGS) -I. -o dns_proxy coroutine-ucontext.c qemu-coroutine.c dns_proxy.c

.PHONY: clean

clean:
	-rm dns_proxy
