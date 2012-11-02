#include <sys/socket.h>
#include <unistd.h>       /* close() */
#include <stdio.h>        /* perror() */
#include <netinet/in.h>   /* struct sockaddr_in */

int main()
{
    int fd;
    int val;
    int ret;
    struct sockaddr_in addr;

    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        perror("socket");

    val = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = 0x7f000001;
    ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0)
        perror("connect");

    ret = close(fd);
    if (ret)
        perror("close");
    return 0;
}
