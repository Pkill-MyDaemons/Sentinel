# Makefile for sentinel_socket.hdll (HashLink native extension)
#
# Prerequisites:
#   brew install hashlink
#
# Usage:
#   cd native && make
#   make install    # copies .hdll to ~/.sentinel/lib/

# HashLink paths (Homebrew M1/M2 Macs use /opt/homebrew, Intel use /usr/local)
HL_PREFIX ?= $(shell brew --prefix hashlink 2>/dev/null || echo /usr/local)
HL_INCLUDE = $(HL_PREFIX)/include
HL_LIB     = $(HL_PREFIX)/lib

CC      = clang
CFLAGS  = -O2 -shared -fPIC -arch arm64 -arch x86_64 \
          -I$(HL_INCLUDE) \
          -mmacosx-version-min=12.0
LDFLAGS = -L$(HL_LIB) -lhl

TARGET  = sentinel_socket.hdll
SOURCES = sentinel_socket.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Built: $(TARGET)"
	@file $(TARGET)

install: $(TARGET)
	mkdir -p ~/.sentinel/lib
	cp $(TARGET) ~/.sentinel/lib/
	# Also copy to HashLink's lib dir so hl can find it automatically
	cp $(TARGET) $(HL_LIB)/$(TARGET) 2>/dev/null || \
	    sudo cp $(TARGET) $(HL_LIB)/$(TARGET)
	@echo "Installed: $(TARGET) → $(HL_LIB)/$(TARGET)"

clean:
	rm -f $(TARGET) *.o

# Debug build
debug: CFLAGS += -g -DDEBUG -fsanitize=address
debug: $(TARGET)

# Verify the .hdll exports the expected symbols
verify: $(TARGET)
	@echo "Checking exports..."
	@nm -g $(TARGET) | grep sentinel_socket | sort