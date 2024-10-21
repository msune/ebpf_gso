all: compile

CFLAGS = -O2 -Wall -Werror -g
ifeq ($(DEBUG), 1)
    CFLAGS += -DDEBUG=1
endif

compile:
	clang $(CFLAGS) -DPUSH=1 -target bpf -c pushpop.c -o push.o
	clang $(CFLAGS) -DPOP=1 -target bpf -c pushpop.c -o pop.o

clean:
	rm -rf *.o || true
