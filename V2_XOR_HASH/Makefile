CC=gcc
CFLAGS=-Wall -Wextra -Werror -pedantic -Wvla
SRC=src/
EXEC=icmp_program
 
all: $(EXEC)
 
icmp_program: $(SRC)main.o $(SRC)icmp_slave.o $(SRC)icmp_master.o 
	$(CC) -o $@ $^ $(CFLAGS) 
 
$(SRC)%.o : $(SRC)%.c
	$(CC) -o $@ -c $^ $(CFLAGS) 
 
clean:
	rm -rf $(SRC)*.o
