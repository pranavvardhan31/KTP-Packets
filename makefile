# ==========================================================
# Assignment 4 Submission 
# Name: Chiluveru Pranav Vardhan
# Roll number: 22CS10019 

# Commands to execute :-

# 1) Terminal 1
#     $ make clean
#     $ make all
#     $ ./initksocket

# 2) Terminal 2 (Sender)
#     $ ./user1
#     // Should enter a vaild .txt file name in the current folder (input.txt)

# 3) Terminal 3 (Receiver)
#     $ ./user2

# received.txt will be generated in the current folder
# and total transmissions can be seen after clicking (ctrl+c)
# in terminal 1
# ==========================================================


CC = gcc
CFLAGS = -Wall -pthread
LDFLAGS = -pthread

all: initksocket user1 user2

initksocket: initksocket.c ksocket.c ksocket.h
	$(CC) $(CFLAGS) -o $@ initksocket.c ksocket.c $(LDFLAGS)

user1: user1.c ksocket.c ksocket.h
	$(CC) $(CFLAGS) -o $@ user1.c ksocket.c $(LDFLAGS)

user2: user2.c ksocket.c ksocket.h
	$(CC) $(CFLAGS) -o $@ user2.c ksocket.c $(LDFLAGS)

clean:
	rm -f initksocket user1 user2 *.o libksocket.a received.txt

run-init:
	./initksocket

run-sender:
	./user1 

run-receiver:
	./user2 

.PHONY: all clean run-init run-sender run-receiver