CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c99
LDFLAGS ?=
LDLIBS ?= -lssl -lcrypto

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

TARGET = certwatcher
SRC = certwatcher.c

ifeq ($(OS),Windows_NT)
    LDLIBS += -lws2_32
    TARGET = certwatcher.exe
endif

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
