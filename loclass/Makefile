
TARGET = main
LOCLASS_DIR = loclass
MBEDTLS_DIR = mbedtls

SRC = "loclass.c"
SRC += $(wildcard $(LOCLASS_DIR)/*.c)
SRC += $(wildcard $(MBEDTLS_DIR)/library/*.c)
INC = -I$(LOCLASS_DIR) -I$(MBEDTLS_DIR)/include/

CC = gcc
LD = gcc
SIZE = gcc-size

CFLAGS =
LDFLAGS =

ifeq ($(DEBUG), 1)
	CFLAGS += -DDEBUG
endif


all:
	$(CC) $(INC) $(SRC) $(CFLAGS) -o $(TARGET) 

clean:
	rm $(TARGET)
