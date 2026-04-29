CC      ?= cc
PKG_CONFIG ?= pkg-config

NL_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libnl-genl-3.0)
NL_LIBS   ?= $(shell $(PKG_CONFIG) --libs   libnl-genl-3.0)

CFLAGS  ?= -O2 -g -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -Wmissing-prototypes -Wno-unused-parameter -fno-common \
           -D_GNU_SOURCE -std=c11
CPPFLAGS ?= -Iinclude $(NL_CFLAGS)
LDFLAGS ?=
LDLIBS  ?= $(NL_LIBS)

PREFIX  ?= /usr/local

BUILD   := build
SRCS    := $(wildcard src/*.c)
OBJS    := $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS))
DEPS    := $(OBJS:.o=.d)

BIN     := wificapc

.PHONY: all clean install install-systemd uninstall uninstall-systemd test asan

all: $(BIN)

# Diagnostic build: address + UB sanitizers, no optimisation.
# Re-runs the full link, so use after `make clean`.
asan: CFLAGS  := -O0 -g -Wall -Wextra -Wpedantic -fno-common -D_GNU_SOURCE -std=c11 \
                 -fsanitize=address,undefined -fno-omit-frame-pointer \
                 -Wno-unused-parameter
asan: LDLIBS := $(NL_LIBS) -fsanitize=address,undefined
asan: $(BIN)
	@echo "asan build ready: ./$(BIN)"

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD):
	@mkdir -p $@

-include $(DEPS)

# Default install ships only the binary. Image builds (e.g. pwnagotchi) drop
# in their own systemd units; standalone deployments can opt in via
# `make install install-systemd`.
install: $(BIN)
	install -D -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

install-systemd:
	install -D -m 0644 systemd/wificapc.service $(DESTDIR)/etc/systemd/system/wificapc.service
	install -D -m 0644 systemd/wificapc-prep.service $(DESTDIR)/etc/systemd/system/wificapc-prep.service

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

uninstall-systemd:
	rm -f $(DESTDIR)/etc/systemd/system/wificapc.service
	rm -f $(DESTDIR)/etc/systemd/system/wificapc-prep.service

test: $(BIN) test_parsers test_eapol
	@./test_parsers
	@./test_eapol
	@./test/smoke.sh

test_parsers: test/test_parsers.c $(BUILD)/radiotap.o $(BUILD)/dot11.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

test_eapol: test/test_eapol.c $(BUILD)/eapol.o $(BUILD)/dot11.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(BUILD) $(BIN) test_parsers test_eapol
