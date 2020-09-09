//
// Created by sourav on 9/4/20.
//
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#define device "/proc/deviceDriver"
#define buff_size 3

void clear_buffer (char *buffer){
    memset(buffer,0,buff_size);
}

int main(){
    int fd;
    char buff[buff_size];
    int count=2; //count should be less then the buff size
    char message[]="Hello";
    //char message[0]="1";
    int rv;

    // Clear Buffer
    clear_buffer(buff);

    fd=open(device, O_RDWR, S_IWUSR | S_IRUSR);
    if(fd==-1){
        // was throwing error. I fixed it by giving permission
       //  sudo chmod 0777/0666 deviceDriver
        fprintf(stderr, "Error Opening device File\n");
        exit(-1);
    }


    //writing to device

    printf("Writing to %s\n", device);
    //strcpy(buff,message);
    strcpy(buff,"1");
    rv=write(fd,buff,1);
    if (rv==-1){
        fprintf(stderr, "Error while writing\n");
        exit(0);
    }


    // reading 12 char from the devied
    clear_buffer(buff);
    printf("Reading from the %s\n", device);
    rv= read(fd, buff,count);
    if (rv==-1){
        fprintf(stderr, "Error while reading\n");
        exit(0);
    }
    printf(" %d char from %s is %s. \n",rv,device, buff);

    for(int i=0;i<sizeof(buff);i++){
        printf("Buff[%d] is %c\n",i,buff[i]);
    }



    rv=close(fd);
    if (rv==-1){
        fprintf(stderr, "Error while closing\n");
        exit(0);
    }

}

