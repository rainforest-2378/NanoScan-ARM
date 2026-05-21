CC      ?= cc
CFLAGS  ?= -O3 -Wall -Wextra -Wpedantic
CPPFLAGS = -I./include -I./src

LIB_SRCS = src/compiler.c src/shift_and.c src/multi_scan.c src/serialize.c src/hs_compat.c
LIB_OBJS = $(LIB_SRCS:.c=.o)

NS_LIB = libnanoscan.a
HS_LIB = libhs.a

DEMO_NS   = nanoscan_demo
DEMO_HS   = hs_compat_demo
TEST_BINS = shift_and_test multi_scan_test hs_compat_test hs_diff_test hs_serialize_test hs_stress_test hs_regex_test hs_many_patterns_test

.PHONY: all test clean compat-demo

all: $(NS_LIB) $(HS_LIB) $(DEMO_NS) $(DEMO_HS) $(TEST_BINS)

$(NS_LIB): $(LIB_OBJS)
	ar rcs $@ $^

# libhs.a is the same archive under the Hyperscan-friendly name (-lhs).
$(HS_LIB): $(NS_LIB)
	cp $(NS_LIB) $(HS_LIB)

$(DEMO_NS): examples/main.c $(NS_LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -L. -lnanoscan

$(DEMO_HS): examples/hs_compat_demo.c $(NS_LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -L. -lnanoscan

%_test: tests/%.c $(NS_LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -L. -lnanoscan

test: $(TEST_BINS)
	@set -e; for t in $(TEST_BINS); do echo "==> $$t"; ./$$t; done

compat-demo: $(DEMO_HS)
	./$(DEMO_HS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(LIB_OBJS) $(NS_LIB) $(HS_LIB) \
	      $(DEMO_NS) $(DEMO_HS) $(TEST_BINS)
