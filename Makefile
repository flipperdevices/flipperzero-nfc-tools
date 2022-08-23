
TARGET = mfkey
MFKEY_DIR = mfkey32v2
CRAPTO1_DIR = $(MFKEY_DIR)/crapto1

SRC = $(wildcard $(MFKEY_DIR)/*.c)
SRC += $(wildcard $(CRAPTO1_DIR)/*.c)
INC = -I$(MFKEY_DIR) -I$(CRAPTO1_DIR)

CC = gcc
LD = gcc
SIZE = gcc-size

CFLAGS =
LDFLAGS =

ifeq ($(DEBUG), 1)
	CFLAGS += -DDEBUG
endif


all:
	$(CC) $(SRC) $(CFLAGS) -o $(TARGET) 

clean:
	rm $(TARGET)