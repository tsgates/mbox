#include <pthread.h>
#include <stdio.h>

#define UNUSED(x) x __attribute__((unused))

pthread_t thread;
pthread_mutex_t mutex;
int global_counter;

void* nothing(void *UNUSED(data))
{
    printf("[thread] exit thread\n");
    pthread_exit(NULL);
}

int main()
{
    global_counter = 1;

    printf("[main] create thread\n");
    pthread_create(&thread, NULL, nothing, NULL);
    printf("[main] join thread\n");
    pthread_join(thread, NULL);
    printf("[main] exit\n");
    pthread_mutex_destroy(&mutex);
    return 0;
}
