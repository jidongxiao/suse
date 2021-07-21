//
// Created by mass on 2/15/21.
//


//#define KEY_LEN 128 // for 1024-bit key
#define KEY_LEN 256


#define AES_KEY_SIZE 16
#define MASTER_KEY_SIZE AES_KEY_SIZE
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE_BITS  (AES_KEY_SIZE<<3)
#define MAX_MPI_IN_BYTE (2048/8)
#define LABEL_SIZE  32

// therad count
#define NUM_OF_THREAD 2


// structure to pass enc_msg & enc_key to the concurrent thread
struct arg_thread{
    unsigned char *from;
    unsigned char *to;
};
