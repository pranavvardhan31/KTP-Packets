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

#include "ksocket.h"
#define LOCAL_PORT 8081
#define DEST_PORT 8080
#define BUFFER_LIMIT 300

int main() {
    int socket_fd = k_socket();
    struct sockaddr_in local_address, remote_address;

    if (socket_fd < 0) {
        perror("Failed to create socket");
        return 1;
    }
    printf("Socket created at %d\n", socket_fd);

    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = INADDR_ANY;
    local_address.sin_port = htons(LOCAL_PORT);

    remote_address.sin_family = AF_INET;
    remote_address.sin_addr.s_addr = INADDR_ANY;
    remote_address.sin_port = htons(DEST_PORT);

    if (k_bind(socket_fd, &local_address, &remote_address) < 0) {
        perror("Binding failed");
        k_close(socket_fd);
        return 1;
    }

    char buffer[BUFFER_LIMIT];
    FILE *output_file = fopen("received.txt", "w");
    if (!output_file) {
        perror("Failed to create output file");
        k_close(socket_fd);
        return EXIT_FAILURE;
    }

    printf("Waiting for data...\n");
    while (1) {
        int bytes_received = k_recvfrom(socket_fd, buffer, sizeof(buffer));
        if (bytes_received < 0) {
            if (errno == ENOMESSAGE) {
                usleep(100000);
                continue;
            }
            perror("Receive error");
            break;
        }

        fwrite(buffer, 1, bytes_received, output_file);
        printf("Received %d bytes\n", bytes_received);
    }

    fclose(output_file);
    k_close(socket_fd);
    printf("Reception complete.\n");
    return 0;
}