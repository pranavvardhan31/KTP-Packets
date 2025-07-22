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
#define LOCAL_PORT 8080
#define DEST_PORT 8081
#define BUF_SIZE 200

int main() {
    srand(time(NULL));
    int socket_fd = k_socket();
    struct sockaddr_in local_addr, remote_addr;

    if (socket_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    printf("Socket created at %d\n", socket_fd);

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(LOCAL_PORT);

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = INADDR_ANY;
    remote_addr.sin_port = htons(DEST_PORT);

    if (k_bind(socket_fd, &local_addr, &remote_addr) < 0) {
        perror("Binding failed");
        k_close(socket_fd);
        return 1;
    }

    char file_name[256];
    FILE *file_ptr = NULL;
    
    while (1) {
        printf("Enter filename: ");
        if (scanf("%255s", file_name) != 1) {
            fprintf(stderr, "Error reading filename\n");
            while (getchar() != '\n'); 
            continue;
        }
        file_ptr = fopen(file_name, "r");
        if (!file_ptr) {
            perror("File open failed. Try again.");
            continue;
        }
        break; 
    }

    sleep(1);

    char send_buffer[BUF_SIZE];
    size_t read_bytes;

    while ((read_bytes = fread(send_buffer, 1, sizeof(send_buffer), file_ptr)) > 0) {
        int send_status = k_sendto(socket_fd, send_buffer, read_bytes);

        while (send_status < 0 && errno == ENOSPACE) {
            printf("Buffer full, retrying...\n");
            sleep(10);
            send_status = k_sendto(socket_fd, send_buffer, read_bytes);
        }

        if (send_status < 0) {
            perror("Transmission error");
            break;
        }
    }

    fclose(file_ptr);
    k_close(socket_fd);
    printf("File transmission completed.\n");
    return 0;
}
