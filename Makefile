TARGET = unnpk

CFLAGS += -Wall
LDFLAGS += -lz

.PHONY: all clean

all: $(TARGET)

$(TARGET): unnpk.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f $(TARGET)
