SRC = main.c io.c io.h
CFLAGS = -Wall


all: my_route_lookup


my_route_lookup: main.c io.c io.h
	gcc $(CFLAGS) $(SRC) -o my_route_lookup -lm

.PHONY: clean
clean:
	rm -f my_route_lookup

