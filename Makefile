FLAGS=-Wall -Wextra
all:
	$(CC) $(FLAGS) -o dns_proxy dns_proxy.c
.PHONY : clean
clean :
	-rm dns_proxy

