#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/utsname.h>

int main()
{
    char *arg[]= {"/bin/ls", NULL };
    int pid;

    pid = fork();

    if (pid) {
        waitpid(pid, NULL, 0);
        exit(EXIT_SUCCESS);
    } else {
        (void)uname(NULL);
        execve(arg[0], arg, NULL);
        exit(EXIT_FAILURE);
    }
}

