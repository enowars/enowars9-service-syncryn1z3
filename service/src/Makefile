CC = gcc
CFLAGS = -I$(shell pwd) -O0 -MMD -MP -finline-small-functions -freorder-blocks -freorder-functions -fstdarg-opt -g -Wall -Wextra
LDFLAGS =

TARGET = build/ptp-master

SRCS = $(shell find . -name '*.c')
OBJS = $(patsubst ./%.c, build/src/%.o, $(SRCS))
DEPS := $(OBJS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

build/src/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build

-include $(DEPS)

.PHONY: all clean
