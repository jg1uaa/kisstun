TARGET = kisstun
OBJ = kiss.o sliptun.o
CFLAGS = -O2 -Wall -c

all: $(TARGET)

kiss.o: kiss.c
	$(CC) $(CFLAGS) $< -o $@

sliptun.o: sliptun.c
	$(CC) $(CFLAGS) $< -o $@

$(TARGET): $(OBJ)
	$(CC) -pthread $(OBJ) -o $@

clean:
	rm -f $(TARGET) $(OBJ)
