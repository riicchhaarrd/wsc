#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
/* #include <stdio.h> */
/* #include <string.h> */

enum
{
	STREAM_SEEK_BEG,
	/* STREAM_SEEK_SET, */
	STREAM_SEEK_CUR,
	STREAM_SEEK_END
};

/* enum */
/* { */
/* 	STREAM_RESULT_OK, */
/* 	STREAM_RESULT_ERR, */
/* }; */

/* typedef int32_t StreamResult; */
typedef struct Stream_s
{
	/* char filename[256]; */
	/* unsigned char *buffer; */
	/* unsigned int offset, length; */
	void *ctx;

	int64_t (*tell)(struct Stream_s *s);
	/* This function returns zero if successful, or else it returns a non-zero value. */
	int (*seek)(struct Stream_s *s, int64_t offset, int whence);

	int (*name)(struct Stream_s *stream, char *buffer, size_t size);
	int (*eof)(struct Stream_s *stream);
	size_t (*read)(struct Stream_s *stream, void *ptr, size_t size, size_t nmemb);
	/* void (*close)(struct Stream_s *stream); */
} Stream;

int stream_read_line(Stream *s, char *line, size_t max_line_length)
{
	size_t n = 0;
	if(line)
	{
		line[n] = 0;
	}

	int eol = 0;
	int eof = 0;
	while(!eol)
	{
		uint8_t ch = 0;
		if(0 == s->read(s, &ch, 1, 1) || !ch)
		{
			eof = 1;
			break;
		}
		switch(ch)
		{
			case '\r': break;
			case '\n': eol = 1; break;
			default:
				if(line)
				{
					if(n + 1 < max_line_length) // n + 1 account for \0
					{
						line[n++] = ch;
					}
				}
				break;
		}
	}
	if(line)
	{
		line[n] = 0;
	}
	return eof;
}

int stream_read_string(Stream *s, char *string, size_t max_string_length, uint64_t *hash_result)
{
	if(hash_result)
	{
		*hash_result = 0;
	}

	// https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
	uint64_t prime = 0x00000100000001B3;
	uint64_t offset = 0xcbf29ce484222325;

	uint64_t hash = offset;

	size_t n = 0;
	if(string)
	{
		string[n] = 0;
	}
	int eof = 0;
	while(1)
	{
		int64_t pos = s->tell(s);
		uint8_t ch = 0;
		if(0 == s->read(s, &ch, 1, 1) || !ch)
		{
			// Unexpected EOF or end of string
			eof = 1;
			break;
		}
		if(isspace(ch))
		{
			s->seek(s, pos, STREAM_SEEK_BEG);
			break;
		}
		hash ^= ch;
		hash *= prime;
		if(string)
		{
			if(n + 1 < max_string_length) // n + 1 account for \0
			{
				// Does not give error if string would overflow
				string[n++] = ch;
			}
		}
	}
	if(string)
	{
		string[n] = 0;
	}
	if(hash_result)
	{
		*hash_result = eof ? 0 : hash;
	}
	return eof;
}

// We're assuming we're always running this on a little endian system.

uint16_t stream_read_u16be(Stream *s)
{
	uint8_t bytes[2];
	s->read(s, bytes, 1, sizeof(bytes));
	return (bytes[0] << 8) | bytes[1];
}
uint64_t stream_read_u64be(Stream *s)
{
	uint8_t bytes[8];
	s->read(s, bytes, 1, sizeof(bytes));
	union
	{
		uint64_t i;
		uint8_t b[8];
	} u;
	for(size_t k = 0; k < 8; ++k)
	{
		u.b[k] = bytes[7 - k];
	}
	return u.i;
}

void stream_seek_character(Stream *s, int needle)
{
	while(1)
	{
		int64_t pos = s->tell(s);
		uint8_t ch = 0;
		if(0 == s->read(s, &ch, 1, 1) || !ch)
		{
			break;
		}
		if(needle == ch)
		{
			s->seek(s, pos, STREAM_SEEK_BEG);
			break;
		}
	}
}

void stream_skip_whitespace(Stream *s)
{
	while(1)
	{
		int64_t pos = s->tell(s);
		uint8_t ch = 0;
		if(0 == s->read(s, &ch, 1, 1) || !ch)
		{
			break;
		}
		if(!isspace(ch))
		{
			s->seek(s, pos, STREAM_SEEK_BEG);
			break;
		}
	}
}

/* static size_t stream_read_(struct Stream_s *stream, void *ptr, size_t size, size_t nmemb) */
/* { */
/* 	size_t nb = size * nmemb; */
/* 	if(stream->offset + nb >= stream->length) */
/* 		return 0; // EOF */
/* 	memcpy(ptr, &stream->buffer[stream->offset], nb); */
/* 	stream->offset += nb; */
/* 	return nb; */
/* } */

/* static int stream_from_memory(Stream *stream, void *ptr, size_t size, const char *filename) */
/* { */
/* 	stream->buffer = ptr; */
/* 	stream->length = size; */
/* 	stream->offset = 0; */
/* 	stream->read = stream_read_; */
/* 	if(filename) */
/* 	{ */
/* 		snprintf(stream->filename, sizeof(stream->filename), "%s", filename); */
/* 	} */
/* 	return 0; */
/* } */
#if 0
int stream_open(Stream *stream, const char *filename, const char *mode)
{
	//...
	return 1;
}

void stream_close(Stream *stream)
{
	//...
}
#endif
