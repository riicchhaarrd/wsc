#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include "stream.h"
#include "stream_buffer.h"

#include <openssl/sha.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

static int server_fd;
static struct sockaddr_in sa;
#define HTTP_PORT (8080)

// https://stackoverflow.com/a/16511093
char *base64encode(const void *b64_encode_this, int encode_this_many_bytes)
{
	BIO *b64_bio, *mem_bio;							// Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
	BUF_MEM *mem_bio_mem_ptr;						// Pointer to a "memory BIO" structure holding our base64 data.
	b64_bio = BIO_new(BIO_f_base64());				// Initialize our base64 filter BIO.
	mem_bio = BIO_new(BIO_s_mem());					// Initialize our memory sink BIO.
	BIO_push(b64_bio, mem_bio);						// Link the BIOs by creating a filter-sink BIO chain.
	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL); // No newlines every 64 characters or less.
	BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); // Records base64 encoded data.
	BIO_flush(b64_bio);							// Flush data.  Necessary for b64 encoding, because of pad characters.
	BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr); // Store address of mem_bio's memory structure.
	BIO_set_close(mem_bio, BIO_NOCLOSE);		// Permit access to mem_ptr after BIOs are destroyed.
	BIO_free_all(b64_bio);						// Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
	BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1); // Makes space for end null.
	(*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';	  // Adds null-terminator to tail.
	return (*mem_bio_mem_ptr).data; // Returns base-64 encoded data. (See: "buf_mem_st" struct).
}

#define WEBSOCKET_KEY_MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

void handle_handshake(int client_fd)
{
	char buf[16384];
	ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
	if(n <= 0)
		return;
	printf("received: %s\n", buf);
	Stream s = { 0 };
	StreamBuffer sb = { 0 };
	init_stream_from_buffer(&s, &sb, buf, n);
	while(!stream_read_line(&s, NULL, 0))
	{
		Stream ls = { 0 };
		StreamBuffer lsb = { 0 };
		size_t pos = s.tell(&s);
		/* assert(pos <= n); */
		if(pos > n)
			return;
		init_stream_from_buffer(&ls, &lsb, buf + (size_t)pos, (size_t)n - (size_t)pos);
		uint64_t hash;
		stream_read_string(&ls, NULL, 0, &hash);
		if(hash == 0xe37468ce984f3674) // Sec-WebSocket-Key
		{
			stream_skip_whitespace(&ls);
			/* char nonce[256] = "dGhlIHNhbXBsZSBub25jZQ=="; */
			char nonce[256] = { 0 };
			stream_read_string(&ls, nonce, sizeof(nonce), NULL);
			char concatenated[256];
			snprintf(concatenated, sizeof(concatenated), "%s%s", nonce, WEBSOCKET_KEY_MAGIC_STRING);
			unsigned char obuf[SHA_DIGEST_LENGTH];
			SHA1((unsigned char *)concatenated, strlen(concatenated), obuf);
			/* char sha1hash[SHA_DIGEST_LENGTH * 2] = {0}; */
			/* for(int k = 0; k < SHA_DIGEST_LENGTH; ++k) */
			/* { */
			/* 	snprintf(&sha1hash[k * 2], sizeof(sha1hash), "%02x", obuf[k]); */
			/* } */
			/* printf("sha1: %s\n", sha1hash); */
			char *encoded = base64encode(obuf, SHA_DIGEST_LENGTH);
			char response[2048] = { 0 };
			snprintf(response,
					 sizeof(response),
					 "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: "
					 "Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
					 encoded);
			free(encoded);
			send(client_fd, response, strlen(response), 0);
		}
	}
}

void handle_websocket_frame(int fd, char *buf, size_t n, uint8_t opcode)
{
	printf("handle\n");
	if(opcode == 1)
	{
		printf("%s\n", buf);
	}
	else if(opcode == 2)
	{
		Stream s = { 0 };
		StreamBuffer sb = { 0 };
		init_stream_from_buffer(&s, &sb, buf, n);

		//TODO: read packets
	}
}

void handle_client(int fd)
{
	pid_t p = fork();
	if(p < 0)
	{
		printf("failed to fork\n");
		exit(1);
	}
	handle_handshake(fd);
	while(1)
	{
		char buf[16384];
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		if(n <= 0)
			return;

		Stream s = { 0 };
		StreamBuffer sb = { 0 };
		init_stream_from_buffer(&s, &sb, buf, n);

		uint8_t header[2];
		s.read(&s, header, 1, sizeof(header));
		bool FIN = header[0] & 0x80;
		uint8_t opcode = header[0] & 0xf;
		bool masked = header[1] & 0x80;
		uint64_t payload_length = header[1] & 0x7f;
		if(payload_length == 126)
		{
			payload_length = stream_read_u16be(&s);
		}
		else if(payload_length == 127)
		{
			payload_length = stream_read_u64be(&s);
		}

		uint8_t masking_key[4];
		s.read(&s, masking_key, 1, sizeof(masking_key));

		/* printf("FIN=%d,opcode=%d,masked=%d,length=%d\n", FIN, opcode, masked, payload_length); */
		size_t offset = s.tell(&s);
		if(n > sizeof(buf))
		{
			return;
		}
		for(size_t k = offset; k < (size_t)n; ++k)
		{
			uint8_t *b = &buf[k];
			*b ^= masking_key[(k - offset) % 4];
			/* printf("%02X ", *b); */
		}
		if(payload_length > (size_t)n - offset)
		{
			printf("invalid payload_length\n");
			return;
		}
		handle_websocket_frame(fd, buf + offset, payload_length, opcode);
	}
	shutdown(fd, SHUT_RD);
	close(fd);
	exit(0);
}

int main()
{
	memset(&sa, 0, sizeof(sa));

	sa.sin_family = AF_INET;
	/* sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Place a proxy in front, preferably with SSL/TLS */
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa.sin_port = htons(HTTP_PORT);

	server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(server_fd == -1)
	{
		printf("http_server: Can't create socket\n");
		return 1;
	}
	int const_value_1 = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&const_value_1, sizeof(int));

	if(bind(server_fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
	{
		printf("http_server: Failed to bind\n");
		return 1;
	}

	if(listen(server_fd, 0) == -1)
	{
		printf("http_server: Failed to listen\n");
		return 1;
	}
	/* if(set_non_blocking(server_fd)) */
	/* { */
	/* 	fprintf(stderr, "http_server: Failed to set socket to non-blocking\n"); */
	/* 	exit(-1); */
	/* } */

	printf("HTTP server listening on port %d\n", HTTP_PORT);
	while(1)
	{
		struct sockaddr_in client_addr;
		int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &(socklen_t) { sizeof(client_addr) });
		if(client_fd == -1)
		{
			printf("Failed to accept\n");
			break;
		}
		// https://ndeepak.com/posts/2016-10-21-tcprst/
		struct linger sl;
		sl.l_onoff = 1;	 /* non-zero value enables linger option in kernel */
		sl.l_linger = 0; /* timeout interval in seconds */
		setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
		printf("New connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		handle_client(client_fd);
	}
	return 0;
}
