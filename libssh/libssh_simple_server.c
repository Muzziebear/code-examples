/*
    A simple libssh server created to familiarize myself with the
    secure shell protocol and the libssh library. Currently the
    server only implements opening a shell command channel, 
    sending user commands, and receiving the results from the client.
    
    Resources used: 
        http://api.libssh.org/master/index.html
        https://github.com/substack/libssh/blob/master/examples/samplesshd-tty.c
*/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include "libssh_config.h"


// Authenticate libssh client using username and password
int auth_password(const char *user, const char *password)
{
	if(strcmp(user, "libssh_user"))
		return 1;
	if(strcmp(password, "password"))
		return 1;
	return 0;
}

// Authentication loop
int auth_loop(ssh_session session)
{
	ssh_message message;
	int auth = 0;

	do 
    {
        message=ssh_message_get(session);   
        if(!message)
            break;

        switch(ssh_message_type(message))
        {
            case SSH_REQUEST_AUTH:
                switch(ssh_message_subtype(message))
                {
                    case SSH_AUTH_METHOD_PASSWORD:
                        /*
                        printf("User %s wants to auth with pass %s\n",
                               ssh_message_auth_user(message),
                               ssh_message_auth_password(message));
                        */
                        if(auth_password(ssh_message_auth_user(message),
                           ssh_message_auth_password(message)) == 0)
                        {
                            auth=1;
                            ssh_message_auth_reply_success(message,SSH_AUTH_SUCCESS);
                            break;
                        }
                    // not authenticated, send default message
                    default:
                        ssh_message_auth_set_methods(message,SSH_AUTH_METHOD_PASSWORD);
                        ssh_message_reply_default(message);
                }
                break;
            default:
                ssh_message_reply_default(message);
        }

        ssh_message_free(message);
    } while (!auth);

    return auth;
}

// Open ssh channel with client
ssh_channel open_channel(ssh_session session)
{
	ssh_message message;
	ssh_channel channel = 0;

	do 
    {
        message=ssh_message_get(session);

        if(message)
        {
            switch(ssh_message_type(message))
            {
                case SSH_REQUEST_CHANNEL_OPEN:
                    if(ssh_message_subtype(message)==SSH_CHANNEL_SESSION)
                    {
                        channel = ssh_message_channel_request_open_reply_accept(message);
                        break;
                    }
                default:
                	ssh_message_reply_default(message);
            }

            ssh_message_free(message);
        }
    } while(message && !channel);

    return channel;
}

// Open shell channel with client
void start_server_shell(ssh_session session)
{
    ssh_channel shell_channel = open_channel(session);
    if(shell_channel == NULL)
        print_error("Failed creating shell channel", session);

    puts("[*] Opened shell channel!");

    char shell_in[1024];
    char shell_cmd[1024];
    char result_buffer[1024];
    int loop;
    memset(shell_in, 0, sizeof(shell_in));
    memset(shell_cmd, 0, sizeof(shell_cmd));

    // Receive shell command input and send to client
    printf("%s","# ");
    while(fgets(shell_in, sizeof(shell_in), stdin) != NULL)
    {
        memcpy(shell_cmd, shell_in, strcspn(shell_in, "\r\n"));

        if(strcmp(shell_cmd, "exit") == 0)
            break;

        ssh_channel_write(shell_channel, shell_cmd, sizeof(shell_cmd));
        loop = 1;
        
        // Read command result from client until end of data received
        while(loop)
        {
            memset(result_buffer, 0, sizeof(result_buffer));

            if(ssh_channel_read(shell_channel, result_buffer, sizeof(result_buffer), 0) > 0 
                && strcmp(result_buffer, end_of_data))
                write(STDOUT_FILENO, result_buffer, sizeof(result_buffer));
            else
                loop = 0;
        }

        printf("%s","# ");
        memset(shell_in, 0, sizeof(shell_in));
        memset(shell_cmd, 0, sizeof(shell_cmd));
    }

    ssh_channel_free(shell_channel);
}


int main()
{
	int rc;
	int auth = 0;
    int port = 9999;
    char *key_path = "/path/to/key";
    
    ssh_bind sshbind = ssh_bind_new();
    ssh_session session = ssh_new();

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, key_path);

	if(ssh_bind_listen(sshbind) < 0)
		print_error("Failed listening", sshbind);

	printf("[*] Listening on port %d\n", port);


	rc = ssh_bind_accept(sshbind, session);
	if(rc != SSH_OK)
		print_error("Failed accepting connection", sshbind);

	puts("[*] Received connection!");


	if (ssh_handle_key_exchange(session))
		print_error("Failed key exchange", session);

	puts ("[*] Exchanged keys!");
	//print_pubkey(session);


	auth = auth_loop(session);

	if (!auth)
		print_error("Failed authenticating", session);

    puts("[*] User authenticated!");


    ssh_channel command_channel = open_channel(session);
    if(!command_channel)
        print_error("Failed opening command channel", session);

    puts("[*] Opened command channel!");


    int command = CMD_SHELL;

    puts("[*] Starting Command: Shell Channel");

	ssh_channel_write(command_channel, &command, sizeof(command));
    start_server_shell(session);


    puts("[*] Exiting.");

    ssh_channel_free(command_channel);
	ssh_disconnect(session);
	ssh_bind_free(sshbind);
	ssh_free(session);
	ssh_finalize();

	return 0;

} 