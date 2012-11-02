#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <stdlib.h>

int parent_pid;

void parent(pid_t child_pid)
{
    int status;
    int result;

    printf("[parent:%i] wait for child exit\n", parent_pid);
    result = waitpid(child_pid, &status, 0);
    if (result != child_pid) {
        perror("waitpid");
        exit(1);
    }

    printf("[parent:%i] child exited with status %i\n",
        parent_pid, status);
}

void child()
{
    struct utsname buf;
    int err;
    int pid = getpid();

    printf("[child:%i] uname()\n", pid);

    err = uname(&buf);
    if (err) {
        perror("uname");
        exit(1);
    }

    printf("[child:%i] done, exit.\n", pid);
}

int main()
{
    pid_t pid;

    /* fork process */
    parent_pid = getpid();
    printf("[parent:%i] fork\n", parent_pid);
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }

    if (pid) {
        parent(pid);
    } else {
        child();
    }
    return 0;
}
