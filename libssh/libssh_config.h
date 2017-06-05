#include <stdio.h>
#include <stdlib.h>
#include <libssh/libssh.h>


const char *start_of_data = "\r\n///SOD///\r\n";
const char *end_of_data = "\r\n///EOD///\r\n";


typedef enum hash_type
{
	HASH_SHA1 = 0,
	HASH_MD5 = 1
} Hash_Type;


typedef enum cmd_options
{
	CMD_SHELL = 0
} CMD_OPTIONS;


void print_error(const char *error, void *ssh)
{
    printf("!!! error : %s : %s\n", ssh_get_error(ssh));
    ssh_finalize();
    exit(EXIT_FAILURE);
}


void print_pubkey(ssh_session session)
{
	ssh_key server_key;
	unsigned char *hash;
	size_t hlen;
	ssh_get_publickey(session, &server_key);
	ssh_get_publickey_hash(server_key, HASH_SHA1, &hash, &hlen);
	ssh_print_hexa("Public Key: ", hash, hlen);
}
