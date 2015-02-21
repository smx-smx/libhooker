DEBUG=0
ANDROID=0
#CC=/mnt3/android-arm-toolchain/bin/arm-linux-androideabi-gcc
CC=gcc
CFLAGS=-Iinclude -c -Wall -fPIC
LDFLAGS=

BINDIR=bin
SRCDIR=src
MODULESDIR=modules

#################################################################################################

ifeq ($(DEBUG),1)
CFLAGS:=$(CFLAGS) -DDEBUG
endif
ifeq ($(ANDROID),1)
CFLAGS:=$(CFLAGS) -D__android__
endif

OBJ_COMMON=$(patsubst %.c,%.o,$(shell find $(SRCDIR)/common -name '*.c'))
OBJ_MODULES=$(patsubst %.c,%.o,$(shell find $(MODULESDIR) -name '*.c'))
OBJ_BASEMOD=$(patsubst %.c,%.o,$(shell find $(SRCDIR)/basemod -name '*.c'))


all: needle testapp modules

#used to do: -Wl,-init,lh_hook_init
modules: $(OBJ_COMMON) $(OBJ_BASEMOD) $(OBJ_MODULES)
	@ for d in $(shell ls modules) ; do \
          echo "Building module $$d" ;\
          ($(CC) $(LDFLAGS) -shared  $(OBJ_COMMON) $(OBJ_BASEMOD) modules/$$d/*.o -o bin/lhm_$$d.so) ;\
        done

needle: $(OBJ_COMMON) $(patsubst %.c,%.o,$(shell find $(SRCDIR)/needle -name '*.c'))
	$(CC) $(LDFLAGS) $^ -o $(BINDIR)/$@

#might be needed: -Wl,--export-dynamic
testapp: $(OBJ_COMMON) $(patsubst %.c,%.o,$(shell find $(SRCDIR)/testapp -name '*.c'))
	$(CC) $(LDFLAGS) -g $^ -o $(BINDIR)/$@

.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	-rm bin/* src/*/*.o $(OBJ_MODULES)
	exit 0
