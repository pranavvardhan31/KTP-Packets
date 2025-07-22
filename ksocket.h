/*==========================================================
Assignment 4 Submission 
Name: Chiluveru Pranav Vardhan
Roll number: 22CS10019 

Commands to execute :-

1) Terminal 1
    $ make clean
    $ make all
    $ ./initksocket

2) Terminal 2 (Sender)
    $ ./user1
    // Should enter a vaild .txt file name in the current folder (input.txt)

3) Terminal 3 (Receiver)
    $ ./user2

received.txt will be generated in the current folder
and total transmissions can be seen after clicking (ctrl+c)
in terminal 1
==========================================================*/

#ifndef KSOCKET_H
#define KSOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>

// Constants
#define NUM_SOCKETS 10    // Max number of KTP sockets
#define MAX_PAYLOAD 512   // Max payload size
#define N 10              // Window size
#define T 5               // Timeout for retransmission
#define P 0.5             // Packet drop probability
#define SHM_KEY 1         // Shared memory key
#define SOCK_KTP 3        // KTP socket identifier
#define ENOTBOUND 501     // Error: Socket not bound
#define ENOSPACE 502      // Error: No buffer space
#define ENOMESSAGE 503    // Error: No available message
#define ERRORNP 504       // Error: Non-persistent failure
#define SEQ_SPACE 256     // Sequence number space

// Packet structure
typedef struct {
    uint64_t timestamp;     // Packet timestamp
    char data[MAX_PAYLOAD]; // Packet data
    uint8_t seq_num;        // Sequence number
    uint16_t len;           // Payload length
    uint8_t flags;          // Flags for control
} KTP_Packet;

// Sender window structure
typedef struct {
    KTP_Packet window[N]; // Sender window buffer
    int base, buf_size, win_size, next_seq, recv_size; // Window control
} sender_window;

// Receiver window structure
typedef struct {
    KTP_Packet window[N]; // Receiver window buffer
    int exp_seq, buf_size, base; // Window control
} receiver_window;

// KTP socket structure
typedef struct {
    int pid, udp_sock, is_active, is_binded; // Socket status
    receiver_window rwnd;  // Receiver window
    sender_window swnd;    // Sender window
    struct sockaddr_in remote_addr, my_addr; // Address info
    pthread_mutex_t lock;  // Synchronization lock
} KTP_Socket;

// Function declarations
int k_socket();  // Create KTP socket
int k_bind(int ktp_sock, struct sockaddr_in *myaddr, struct sockaddr_in *cliaddr); // Bind socket
int k_close(int ktp_sock);  // Close socket
int k_sendto(int fc, char *buf, int len); // Send data
int k_recvfrom(int fd, char *buf, int len); // Receive data
int dropMessage(float p); // Simulate packet loss

// Global variables
extern KTP_Socket *ktp_sockets; // Array of KTP sockets
extern pthread_t sender_tid, receiver_tid; // Sender & receiver threads
extern int shmid; // Shared memory ID
extern int *total_transmissions; // Shared memory variable
extern int shmid_trans;           // Shared memory ID

// Threads & utilities
void initialize_SM(); // Initialize shared memory
void *thread_S(); // Sender thread
void *thread_R(); // Receiver thread
void send_packet(KTP_Socket *socketno, KTP_Packet *packet); // Send packet function

#endif
