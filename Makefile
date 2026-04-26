CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -Wmissing-prototypes -Wno-unused-parameter -fno-common \
           -D_GNU_SOURCE -std=c11
CPPFLAGS ?= -Iinclude
LDFLAGS ?=
LDLIBS  ?=

PREFIX  ?= /usr/local

BUILD   := build
SRCS    := $(wildcard src/*.c)
OBJS    := $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS))
DEPS    := $(OBJS:.o=.d)

BIN     := wificapc

.PHONY: all clean install uninstall test

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD):
	@mkdir -p $@

-include $(DEPS)

install: $(BIN)
	install -D -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	install -D -m 0644 systemd/wificapc.service $(DESTDIR)/etc/systemd/system/wificapc.service

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	rm -f $(DESTDIR)/etc/systemd/system/wificapc.service

test: $(BIN)
	@./test/smoke.sh

clean:
	rm -rf $(BUILD) $(BIN)
