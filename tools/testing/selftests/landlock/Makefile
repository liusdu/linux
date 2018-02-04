LIBDIR := ../../../lib
BPFOBJ := $(LIBDIR)/bpf/bpf.o
LOADOBJ := ../../../../samples/bpf/bpf_load.o

CFLAGS += -Wl,-no-as-needed -Wall -O2 -I../../../include/uapi -I$(LIBDIR)
LDFLAGS += -lelf

test_src = $(wildcard test_*.c)

test_objs := $(test_src:.c=)

TEST_PROGS := $(test_objs)

.PHONY: all clean clean_tmp force

all: $(test_objs)

# force a rebuild of BPFOBJ when its dependencies are updated
force:

# rebuild bpf.o as a workaround for the samples/bpf bug
$(BPFOBJ): $(LOADOBJ) force
	$(MAKE) -C $(dir $(BPFOBJ))

$(LOADOBJ): force
	$(MAKE) -C $(dir $(LOADOBJ))

$(test_objs): $(BPFOBJ) $(LOADOBJ) ../kselftest_harness.h

include ../lib.mk

clean_tmp:
	$(RM) -r tmp_*

clean: clean_tmp
	$(RM) $(test_objs)

