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
KTP_Socket *ktp_sockets = NULL;
int shmid = -1; 
// int total_transmissions = 0;


void initialize_SM() {
    int is_new_segment = 0; // Flag to check if new shared memory is allocated
    shmid = shmget(SHM_KEY, 0, 0);
    if (shmid < 0) {
        // Allocate shared memory if it doesn't exist
        shmid = shmget(SHM_KEY, NUM_SOCKETS * sizeof(KTP_Socket) + sizeof(pthread_mutex_t), IPC_CREAT | 0666);
        printf("Shared Memory ID: %d\n", shmid);
        if (shmid < 0) {
            perror("Failed to allocate shared memory for sockets");
            exit(1);
        }
        is_new_segment = 1;
    }

    printf("Process %d: Obtained shmid %d\n", getpid(), shmid);
    KTP_Socket *shared_sockets = (KTP_Socket *)shmat(shmid, NULL, 0); // Attach shared memory
    if (shared_sockets == (void *)-1) {
        perror("Error attaching to shared memory");
        exit(1);
    }
    else ktp_sockets = shared_sockets;
    
    printf("Process %d: Attached at address %p\n", getpid(), (void *)shared_sockets);

    if (is_new_segment) { // If new memory segment, initialize everything
        memset(shared_sockets, 0, NUM_SOCKETS * sizeof(KTP_Socket));

        pthread_mutexattr_t mutex_attributes;
        pthread_mutexattr_init(&mutex_attributes);
        pthread_mutexattr_setpshared(&mutex_attributes, PTHREAD_PROCESS_SHARED);

        for (int i = 0; i < NUM_SOCKETS; i++) {
            pthread_mutex_init(&shared_sockets[i].lock, &mutex_attributes);
            shared_sockets[i].udp_sock = socket(AF_INET, SOCK_DGRAM, 0);

            if (shared_sockets[i].udp_sock < 0) {
                perror("Socket creation failed");
                exit(1);
            }

            int socket_flags = fcntl(shared_sockets[i].udp_sock, F_GETFL, 0);
            fcntl(shared_sockets[i].udp_sock, F_SETFL, socket_flags | O_NONBLOCK); // Set non-blocking mode
        }

        pthread_mutexattr_destroy(&mutex_attributes);
    }
}



int k_socket(){
    if(!ktp_sockets){ // Initialize shared memory if not already done
        initialize_SM();
        for (int i = 0; i < N; i++){
            pthread_mutex_lock(&ktp_sockets[i].lock);
            close(ktp_sockets[i].udp_sock); // Close UDP sockets
            pthread_mutex_unlock(&ktp_sockets[i].lock);
        }
    }
    if (ktp_sockets == NULL) { // Should never happen
        printf("No initialization of memory has happend\n");
        perror("Error: ktp_sockets is not initialized");
        return -1;
    }

    for (int i = 0; i < NUM_SOCKETS; i++){   
        pthread_mutex_lock(&ktp_sockets[i].lock); 
        if (ktp_sockets[i].is_active == 0){ // Find an inactive socket
            ktp_sockets[i].swnd.recv_size = N;
            ktp_sockets[i].pid = getpid();  
            ktp_sockets[i].swnd.buf_size = 0;
            ktp_sockets[i].swnd.win_size = 0;
            ktp_sockets[i].swnd.next_seq = 1;
            ktp_sockets[i].rwnd.buf_size = 0;
            ktp_sockets[i].rwnd.exp_seq = 1;
            ktp_sockets[i].rwnd.base = 0;
            ktp_sockets[i].swnd.base = 0;
            ktp_sockets[i].is_binded = -1;
            ktp_sockets[i].is_active = 1;
            pthread_mutex_unlock(&ktp_sockets[i].lock);
            return i; // Return allocated socket index
        }
        pthread_mutex_unlock(&ktp_sockets[i].lock);
    }
    return -1;
}

int k_bind(int socket_id, struct sockaddr_in *myaddr, struct sockaddr_in *cliaddr){
    pthread_mutex_t *lock = &ktp_sockets[socket_id].lock;
    pthread_mutex_lock(lock);
    if (ktp_sockets[socket_id].pid != getpid() || !ktp_sockets[socket_id].is_active){
        errno = ERRORNP;
        pthread_mutex_unlock(lock);
        return -1;
    }
    // Store addresses
    ktp_sockets[socket_id].my_addr = *myaddr;
    ktp_sockets[socket_id].remote_addr = *cliaddr;
    ktp_sockets[socket_id].is_binded = 0;
    printf("Binding Successful\n");
    pthread_mutex_unlock(lock);
    return 1;
}

int k_sendto(int socket_id, char *buffer, int length) {
    if (socket_id < 0 || socket_id >= NUM_SOCKETS || !buffer || length <= 0)
        return -1;

    pthread_mutex_t *mutex_handle = &ktp_sockets[socket_id].lock;
    pthread_mutex_lock(mutex_handle);

    if (ktp_sockets[socket_id].pid != getpid() || !ktp_sockets[socket_id].is_active) {
        errno = ERRORNP;
        pthread_mutex_unlock(mutex_handle);
        return -1;
    }

    sender_window *sw = &ktp_sockets[socket_id].swnd;
    if ((sw->buf_size + sw->win_size) >= N) {
        errno = ENOSPACE;
        pthread_mutex_unlock(mutex_handle);
        return -1; // No space in sender window
    }
    int write_pos = (sw->base + sw->win_size + sw->buf_size) % N;
    KTP_Packet *pkt = &sw->window[write_pos];

    memset(pkt, 0, sizeof(KTP_Packet));
    pkt->seq_num = sw->next_seq;
    memcpy(pkt->data, buffer, length);
    pkt->len = length;
    sw->buf_size++;
    sw->next_seq++;

    pthread_mutex_unlock(mutex_handle);
    printf("Packet with seq.no %d added to the sending window\n", pkt->seq_num);
    return length;
}


int k_recvfrom(int socket_id, char *buffer, int length) {
    if (socket_id < 0 || socket_id >= NUM_SOCKETS || !buffer || length <= 0)
        return -1;

    pthread_mutex_t *mutex_handle = &ktp_sockets[socket_id].lock;
    pthread_mutex_lock(mutex_handle);

    if (ktp_sockets[socket_id].pid != getpid() || !ktp_sockets[socket_id].is_active) {
        errno = ERRORNP;
        pthread_mutex_unlock(mutex_handle);
        return -1;
    }

    receiver_window *rw = &ktp_sockets[socket_id].rwnd;
    if (rw->buf_size == 0) {
        errno = ENOMESSAGE;
        pthread_mutex_unlock(mutex_handle);
        return -1; // No messages in buffer
    }
    int read_pos = rw->base;
    int available_data = rw->window[read_pos].len;
    int read_data;
    if(available_data < length){
        read_data = available_data;
    }
    else read_data = length;
    memcpy(buffer, rw->window[read_pos].data, read_data);

    if (read_data < available_data) {
        memmove(rw->window[read_pos].data, rw->window[read_pos].data + read_data, available_data - read_data);
        rw->window[read_pos].len = rw->window[read_pos].len - read_data;
    } 
    else{
        rw->buf_size--;
        rw->base = (rw->base + 1) % N;
        rw->window[read_pos].flags = 0;
    }
    pthread_mutex_unlock(mutex_handle);
    printf("Packet with seq.no %d received\n", rw->window[read_pos].seq_num);
    return read_data;
}


int k_close(int fd) {
    if (fd < 0 || fd >= NUM_SOCKETS) {
        perror("Invalid socket descriptor");
        return -1;
    }

    pthread_mutex_lock(&ktp_sockets[fd].lock);
    if (!ktp_sockets[fd].is_active) {
        pthread_mutex_unlock(&ktp_sockets[fd].lock);
        perror("Socket already closed");
        return -1;
    }

    while (ktp_sockets[fd].swnd.buf_size + ktp_sockets[fd].swnd.win_size > 0 ||
           ktp_sockets[fd].rwnd.buf_size > 0) {
        pthread_mutex_unlock(&ktp_sockets[fd].lock);
        sched_yield(); 
        pthread_mutex_lock(&ktp_sockets[fd].lock);
    }

    printf("Closing socket %d (fd: %d)\n", fd, ktp_sockets[fd].udp_sock);
    ktp_sockets[fd] = (KTP_Socket){0}; // Reset socket

    pthread_mutex_unlock(&ktp_sockets[fd].lock);
    return 1;
}
