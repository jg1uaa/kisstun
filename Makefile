TARGET = kisstun
OBJ = ax25.o kiss.o sliptun.o
TARGET2 = call2mac
OBJ2 = ax25.o call2mac.o
CFLAGS = -O2 -Wall -c -fdata-sections -ffunction-sections
LFLAGS = -Wl,--gc-sections

all: $(TARGET) $(TARGET2)

ax25.o: ax25.c
	$(CC) $(CFLAGS) $< -o $@

kiss.o: kiss.c
	$(CC) $(CFLAGS) $< -o $@

sliptun.o: sliptun.c
	$(CC) $(CFLAGS) $< -o $@

call2mac.o: call2mac.c
	$(CC) $(CFLAGS) $< -o $@

$(TARGET): $(OBJ)
	$(CC) $(LFLAGS) -pthread $(OBJ) -o $@

$(TARGET2): $(OBJ2)
	$(CC) $(LFLAGS) $(OBJ2) -o $@

clean:
	rm -f $(TARGET) $(OBJ) $(TARGET2) $(OBJ2)
