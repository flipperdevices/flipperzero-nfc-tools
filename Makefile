
TARGET = mfkey
PATH = mfkey32v2
CRAPTO1_PATH = $(PATH)/crapto1

SRC = $(wildcard $(PATH)/*.c)
SRC += $(wildcard $(CRAPTO1_PATH)/*.c)
INC = -I$(PATH) -I$(CRAPTO1_PATH)

CC = gcc
LD = gcc
SIZE = gcc-size

CFLAGS =
LDFLAGS =

all:
	$(CC) $(SRC) $(CFLAGS) -o $(TARGET) 

clean:
	rm $(TARGET)