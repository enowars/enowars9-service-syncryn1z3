BUILD_DIR = build
SRC_DIR = src

LIB_TARGET = ../service/lib/libjson.so
TEST_TARGET = $(BUILD_DIR)/test

LIB_SRC = $(SRC_DIR)/json.c $(SRC_DIR)/strcpy.c $(SRC_DIR)/strlen.c $(SRC_DIR)/strncmp.c
LIB_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRC))
LIB_LD_SCRIPT = $(SRC_DIR)/link.ld

TEST_SRC = $(SRC_DIR)/json_test.c
TEST_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(TEST_SRC))

CC = gcc
STRIP = strip
CFLAGS = -O0 -Wall -fPIC -fno-plt -I../service/lib/include
LDFLAGS = -shared -nostartfiles -Wl,-T,$(LIB_LD_SCRIPT),-soname,$(notdir ${LIB_TARGET})


.PHONY: all clean

all: $(LIB_TARGET) $(TEST_TARGET)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJ) $(LIB_LD_SCRIPT)
	mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(filter-out $(LIB_LD_SCRIPT), $^)
	$(STRIP) --strip-debug --strip-symbol=loop_start --strip-symbol=injection --strip-symbol=init_injection $@

$(TEST_TARGET): $(TEST_OBJ) $(LIB_TARGET)
	mkdir -p $(dir $@)
	$(CC) -o $@ $(TEST_OBJ) $(LIB_TARGET)

clean:
	rm -rf $(OBJ_DIR) $(LIB_TARGET)
