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

extern KTP_Socket *ktp_sockets;
static int initialized = 0;
extern int shmid; 
char pkdata[600];
char recv_buf[600];
char data[MAX_PAYLOAD];
int shmid_trans;   // Shared memory ID for total_transmissions
int *total_transmissions; // Pointer to shared memory

void initialize_transmission_counter() {
    shmid_trans = shmget(IPC_PRIVATE, sizeof(int), IPC_CREAT | 0666);
    if (shmid_trans < 0) {
        perror("Failed to create shared memory for transmissions");
        exit(1);
    }

    total_transmissions = (int *)shmat(shmid_trans, NULL, 0);
    if (total_transmissions == (void *)-1) {
        perror("Failed to attach shared memory for transmissions");
        exit(1);
    }

    *total_transmissions = 0; // Initialize to 0
}

void cleanup_handler(int sig) {
    printf("\n[INFO] Caught Ctrl+C (SIGINT). Cleaning up shared memory...\n");
    printf("[DEBUG] Shared Memory ID (shmid) = %d\n", shmid);

    printf("\n\nTotal Transmissions = %d\n",*total_transmissions);
    if (ktp_sockets != NULL) {
        if (shmdt(ktp_sockets) == 0) {
            printf("[SUCCESS] Shared memory detached successfully.\n");
        } else {
            perror("[ERROR] Failed to detach shared memory");
        }
    }

    if (shmid > 0) {
        if (shmctl(shmid, IPC_RMID, NULL) == 0) {
            printf("[SUCCESS] Shared memory (shmid=%d) removed successfully.\n", shmid);
        } else {
            perror("[ERROR] Failed to remove shared memory");
        }
    }
    exit(0);
}

int dropMessage(float p) {
    if (!initialized){
        srand(time(NULL));
        initialized = 1;
    }
    float rand_val = (float)rand() / RAND_MAX;
    return rand_val < p;
}

void attempt_binding(int sock_index) {
    if (!ktp_sockets[sock_index].is_binded && ktp_sockets[sock_index].is_active) {
        if (bind(ktp_sockets[sock_index].udp_sock, 
                 (struct sockaddr *)&ktp_sockets[sock_index].my_addr, 
                 sizeof(ktp_sockets[sock_index].my_addr)) == 0) {
            ktp_sockets[sock_index].is_binded = 1;
            printf("[SUCCESS] Socket %d successfully bound.\n", sock_index);
        }
        else{
            perror("[ERROR] Failed to bind socket");
        }
    }
}

void reset_socket(int sock_index) {
    printf("[INFO] Resetting UDP socket for ksocket %d...\n", sock_index);
    close(ktp_sockets[sock_index].udp_sock);
    
    ktp_sockets[sock_index].udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ktp_sockets[sock_index].udp_sock < 0) {
        perror("[ERROR] Failed to recreate UDP socket");
        return;
    }

    int socket_flags = fcntl(ktp_sockets[sock_index].udp_sock, F_GETFL, 0);
    fcntl(ktp_sockets[sock_index].udp_sock, F_SETFL, socket_flags | O_NONBLOCK);
    printf("[SUCCESS] Recreated UDP socket %d in non-blocking mode.\n", sock_index);
}


void garbage_collector() {
    for (int sock_index = 0; sock_index < NUM_SOCKETS; sock_index++) {
        pthread_mutex_lock(&ktp_sockets[sock_index].lock);

        attempt_binding(sock_index); 
        
        if (ktp_sockets[sock_index].pid != 0 && kill(ktp_sockets[sock_index].pid, 0) == -1) {
            if (errno == ESRCH) {
                printf("[INFO] Stale process detected for socket %d, cleaning up...\n", sock_index);
                pthread_mutex_unlock(&ktp_sockets[sock_index].lock);
                k_close(sock_index);
                pthread_mutex_lock(&ktp_sockets[sock_index].lock);
                reset_socket(sock_index);  
                ktp_sockets[sock_index].pid = 0;
                printf("[SUCCESS] Socket %d successfully reset.\n", sock_index);
            }
        }

        pthread_mutex_unlock(&ktp_sockets[sock_index].lock);
    }
}




void *thread_S(){
    while (1){
        if (shmget(SHM_KEY, 0, 0) == -1){
            printf("[ERROR] Shared memory segment missing. Terminating sender thread.\n");
            pthread_exit(NULL);
        }
        
        garbage_collector(); 

        for (int sock_id = 0; sock_id < N; sock_id++){
            pthread_mutex_lock(&ktp_sockets[sock_id].lock);
            if (!ktp_sockets[sock_id].is_active || ktp_sockets[sock_id].is_binded != 1){
                pthread_mutex_unlock(&ktp_sockets[sock_id].lock);
                continue;
            }

            if ((ktp_sockets[sock_id].swnd.win_size + ktp_sockets[sock_id].swnd.buf_size) == 0){
                pthread_mutex_unlock(&ktp_sockets[sock_id].lock);
                continue;
            }

            int *window_size = &ktp_sockets[sock_id].swnd.win_size;
            int *buf_size = &ktp_sockets[sock_id].swnd.buf_size;
            int receiver_capacity = ktp_sockets[sock_id].swnd.recv_size;

            if (*window_size < receiver_capacity && *buf_size > 0) {
                int difference = receiver_capacity - *window_size;
                *window_size += difference;
                *buf_size -= difference;
                printf("[INFO] Socket %d: Updated window_size=%d, buf_size=%d\n", sock_id, *window_size, *buf_size);
            }
            else if (*window_size > receiver_capacity && *buf_size > 0) {
                int difference = *window_size - receiver_capacity;
                *window_size -= difference;
                *buf_size += difference;
                printf("[INFO] Socket %d: Adjusted window_size=%d, buf_size=%d\n", sock_id, *window_size, *buf_size);
            }

            int base_index = ktp_sockets[sock_id].swnd.base;

            if (ktp_sockets[sock_id].swnd.recv_size == 0 && ktp_sockets[sock_id].swnd.buf_size > 0) {
                struct timeval tv;
                gettimeofday(&tv, NULL);
                int current_time = tv.tv_sec;
                if ((current_time - ktp_sockets[sock_id].swnd.window[base_index].timestamp) > 10) {
                    printf("[INFO] Resending packet due to timeout. Seq: %d\n", 
                           ktp_sockets[sock_id].swnd.window[base_index].seq_num);
                    send_packet(&ktp_sockets[sock_id], &ktp_sockets[sock_id].swnd.window[base_index]);

                    (*total_transmissions)++; 
                    //printf("Total transmissions = %d\n", *total_transmissions);
                }
            }

            for (int pkt_idx = 0; pkt_idx < *window_size; pkt_idx++){
                KTP_Packet *pkt = &ktp_sockets[sock_id].swnd.window[(base_index + pkt_idx) % N];
                send_packet(&ktp_sockets[sock_id], pkt);

                (*total_transmissions)++; 
                //printf("Total transmissions = %d\n", *total_transmissions);
            }
            pthread_mutex_unlock(&ktp_sockets[sock_id].lock);
        }
        usleep(100000); 
    }
}


void send_packet(KTP_Socket *fd, KTP_Packet *pk){   
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int current_time = tv.tv_sec;

    if (pk->timestamp != 0 && (current_time - pk->timestamp) < T) {
        return;
    }
    pk->timestamp = current_time;
    sprintf(pkdata, "%d,%d,%d,%s", 
        pk->flags, pk->seq_num, pk->len, pk->data);
    printf("%s\n", pkdata);
    sendto(fd->udp_sock, pkdata, sizeof(pkdata), 0, (struct sockaddr *)&fd->remote_addr, sizeof(fd->remote_addr));
    printf("[INFO] Sent packet with Seq: %d\n", pk->seq_num);
}



void process_packet(int i, int seqNumber, char *temp_data, int len, pthread_mutex_t *mutex_ptr) {
    int lower_bound = (ktp_sockets[i].rwnd.exp_seq - 20 + SEQ_SPACE) % SEQ_SPACE;
    int upper_bound = (ktp_sockets[i].rwnd.exp_seq - 1 + SEQ_SPACE) % SEQ_SPACE;

    if ((lower_bound <= upper_bound && (seqNumber >= lower_bound && seqNumber <= upper_bound)) ||
        (lower_bound > upper_bound && (seqNumber >= lower_bound || seqNumber <= upper_bound))) {
        
        printf("[WARNING] Duplicate packet received. Resending ACK for Seq: %d\n", seqNumber);
        KTP_Packet ack_pkt;
        memset(&ack_pkt, 0, sizeof(KTP_Packet));
        ack_pkt.seq_num = upper_bound;
        ack_pkt.flags = 2; // ACK
        ack_pkt.len = (N - ktp_sockets[i].rwnd.buf_size);
        send_packet(&ktp_sockets[i], &ack_pkt);
        pthread_mutex_unlock(mutex_ptr);
        return;
    }

    printf("Window details before ACK: base:%d buf_size:%d\n", ktp_sockets[i].rwnd.base, ktp_sockets[i].rwnd.buf_size);
    int index = (ktp_sockets[i].rwnd.base + ktp_sockets[i].rwnd.buf_size + seqNumber - ktp_sockets[i].rwnd.exp_seq) % N;
    KTP_Packet *pkt = &ktp_sockets[i].rwnd.window[index];

    printf("[INFO] Processing received packet Seq: %d\n", seqNumber);
    if (index >= ktp_sockets[i].rwnd.base && index < (ktp_sockets[i].rwnd.base + ktp_sockets[i].rwnd.buf_size) % N) {
        printf("[ERROR] Writing before reading. Dropping packet Seq: %d\n", seqNumber);
        pthread_mutex_unlock(mutex_ptr);
        return;
    }

    memcpy(pkt->data, temp_data, len);
    pkt->flags = 2; 
    pkt->seq_num = seqNumber;
    pkt->len = len;
    int last_seq = seqNumber;

    if (seqNumber == ktp_sockets[i].rwnd.exp_seq) {
        printf("[SUCCESS] Expected sequence packet received. Seq: %d\n", seqNumber);
        while (1) {
            pkt->flags = 1;
            ktp_sockets[i].rwnd.buf_size++;
            ktp_sockets[i].rwnd.exp_seq++;
            index = (index + 1) % N;
            last_seq = pkt->seq_num;
            pkt = &ktp_sockets[i].rwnd.window[index];

            if (pkt->flags != 2) {
                break;
            }
        }

        KTP_Packet ack_pkt;
        memset(&ack_pkt, 0, sizeof(KTP_Packet));
        ack_pkt.seq_num = last_seq;
        ack_pkt.flags = 2;
        ack_pkt.len = (N - ktp_sockets[i].rwnd.buf_size);
        send_packet(&ktp_sockets[i], &ack_pkt);
    }

    printf("[INFO] Window updated: base=%d, buf_size=%d\n", ktp_sockets[i].rwnd.base, ktp_sockets[i].rwnd.buf_size);
}

void process_ack_packet(int i, int seqNumber, int len, pthread_mutex_t *mutex_ptr) {
    printf("[INFO] Received ACK Packet for Sq.No: %d\n", seqNumber);
    printf("[INFO] Before ACK win_size:%d base:%d buf_size:%d\n", ktp_sockets[i].swnd.win_size, ktp_sockets[i].swnd.base, ktp_sockets[i].swnd.buf_size);

    int base = ktp_sockets[i].swnd.base;
    int base_seq = ktp_sockets[i].swnd.window[base].seq_num;
    int lower_bound = (base_seq - 20 + SEQ_SPACE) % SEQ_SPACE;
    int upper_bound = (base_seq - 1 + SEQ_SPACE) % SEQ_SPACE;

    ktp_sockets[i].swnd.recv_size = len;

    if ((lower_bound <= upper_bound && (seqNumber >= lower_bound && seqNumber <= upper_bound)) ||
        (lower_bound > upper_bound && (seqNumber >= lower_bound || seqNumber <= upper_bound))) {
        printf("[WARNING] Duplicate ACK received for seqNumber: %d\n", seqNumber);
        pthread_mutex_unlock(mutex_ptr);
        return;
    }

    if (ktp_sockets[i].swnd.win_size == 0) {
        printf("[WARNING] Window size is zero, ignoring ACK.\n");
        pthread_mutex_unlock(mutex_ptr);
        return;
    }

    while (ktp_sockets[i].swnd.window[base].seq_num != seqNumber) {
        ktp_sockets[i].swnd.win_size--;
        base = (base + 1) % N;
    }
    
    ktp_sockets[i].swnd.win_size--;
    ktp_sockets[i].swnd.base = (base + 1) % N;

    printf("[SUCCESS] Processed ACK. Updated win_size:%d base:%d buf_size:%d\n", ktp_sockets[i].swnd.win_size, ktp_sockets[i].swnd.base, ktp_sockets[i].swnd.buf_size);
}


void *thread_R(){
    fd_set readfds;
    int max_fd;
    struct sockaddr temporary_addr;
    int temporary_len = sizeof(temporary_addr);

    for(;;){
        if (shmget(SHM_KEY, 0, 0) == -1){
            printf("[ERROR] Shared Memory is not available (Removed). Exiting thread.\n");
            pthread_exit(NULL);
        }
        FD_ZERO(&readfds);
        max_fd = 0;

        for (int i = 0; i < NUM_SOCKETS; i++){
            pthread_mutex_t *mutex_ptr = &ktp_sockets[i].lock;
            pthread_mutex_lock(mutex_ptr);

            if (ktp_sockets[i].is_active == 0 || ktp_sockets[i].is_binded != 1){
                pthread_mutex_unlock(mutex_ptr);
                continue;
            }

            FD_SET(ktp_sockets[i].udp_sock, &readfds);
            if (max_fd < ktp_sockets[i].udp_sock) max_fd = ktp_sockets[i].udp_sock;

            pthread_mutex_unlock(mutex_ptr);
        }

        struct timeval timeout = { .tv_sec = 0, .tv_usec = 100000 };
        if (select(max_fd + 1, &readfds, NULL, NULL, &timeout) < 0){
            perror("[ERROR] select failed");
            continue;
        }

        for (int i = 0; i < NUM_SOCKETS; i++){
            pthread_mutex_t *mutex_ptr = &ktp_sockets[i].lock;
            pthread_mutex_lock(mutex_ptr);
            if (ktp_sockets[i].is_active == 0){
                pthread_mutex_unlock(mutex_ptr);
                continue;
            }

            if (FD_ISSET(ktp_sockets[i].udp_sock, &readfds)){
                ssize_t bytes_read = recvfrom(ktp_sockets[i].udp_sock, recv_buf, sizeof(recv_buf), 0, &temporary_addr, (socklen_t *)&temporary_len);
                if (bytes_read < 0){
                    if (errno == EAGAIN){
                        pthread_mutex_unlock(mutex_ptr);
                        continue;
                    }
                    perror("[ERROR] recvfrom error");
                    pthread_mutex_unlock(mutex_ptr);
                    continue;
                }
                if (bytes_read > 0){
                    if (dropMessage(P)){
                        printf("[WARNING] Dropped a message\n");
                        pthread_mutex_unlock(mutex_ptr);
                        continue;
                    }
                    int tempFlags, seqNumber, len;
                    char temp_data[MAX_PAYLOAD];  
                    memset(temp_data, 0, sizeof(temp_data)); 
                    
                    if (sscanf(recv_buf, "%d,%d,%d", &tempFlags, &seqNumber, &len) < 3){
                        printf("[ERROR] Error parsing received packet!\n");
                        pthread_mutex_unlock(mutex_ptr);
                        continue;
                    }
                    printf("[INFO] pid:%d received a packet seq:%d\n", ktp_sockets[i].pid, seqNumber);
                    if (len > MAX_PAYLOAD || len < 0){
                        printf("[ERROR] Invalid packet length: %d\n", len);
                        pthread_mutex_unlock(mutex_ptr);
                        continue;
                    }

                    char *payload_ptr = recv_buf;

                    for (int comma_count = 0; comma_count < 3; comma_count++) {
                        payload_ptr = strchr(payload_ptr, ',');
                        if (!payload_ptr) {
                            break;
                        }
                        payload_ptr++; 
                    }

                    if (payload_ptr) {
                        strncpy(temp_data, payload_ptr, len);
                        temp_data[len] = '\0'; 
                    }

                    if (tempFlags == 0 || tempFlags == 1){
                        process_packet(i, seqNumber, temp_data, len, mutex_ptr);
                    }
                    else if (tempFlags == 2) {
                        process_ack_packet(i, seqNumber, len, mutex_ptr);
                    }
                }
            }
            pthread_mutex_unlock(mutex_ptr);
        }
    }
}



int main() {
    signal(SIGINT, cleanup_handler);

    if (ktp_sockets == NULL) {
        printf("[INFO] Shared memory not initialized. Initializing...\n");
        initialize_SM();
    }
    initialize_transmission_counter();

    pthread_t sender_tid, receiver_tid;

    if (pthread_create(&sender_tid, NULL, thread_S, NULL) != 0) {
        perror("[ERROR] Failed to create sender thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&receiver_tid, NULL, thread_R, NULL) != 0) {
        perror("[ERROR] Failed to create receiver thread");
        exit(EXIT_FAILURE);
    }

    pthread_join(sender_tid, NULL);
    pthread_join(receiver_tid, NULL);
}