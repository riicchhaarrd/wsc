#include "stream.h"
#include <string.h>

typedef struct
{
	size_t offset, length;
	unsigned char *buffer;
} StreamBuffer;

static size_t stream_read_(struct Stream_s *stream, void *ptr, size_t size, size_t nmemb)
{
	StreamBuffer *sd = (StreamBuffer *)stream->ctx;
	size_t nb = size * nmemb;
	if(sd->offset + nb > sd->length)
	{
		/* printf("overflow offset:%d,nb:%d,length:%d,size:%d,nmemb:%d\n",sd->offset,nb,sd->length,size,nmemb); */
		return 0; // EOF
	}
	memcpy(ptr, &sd->buffer[sd->offset], nb);
	/* printf("reading %d (%d/%d)\n", nb, sd->offset, sd->length); */
	sd->offset += nb;
	return nmemb;
}

static size_t stream_write_(struct Stream_s *stream, const void *ptr, size_t size, size_t nmemb)
{
	StreamBuffer *sd = (StreamBuffer *)stream->ctx;
	size_t nb = size * nmemb;
	if(sd->offset + nb > sd->length)
	{
		/* printf("overflow offset:%d,nb:%d,length:%d,size:%d,nmemb:%d\n",sd->offset,nb,sd->length,size,nmemb); */
		return 0; // EOF
	}
	memcpy(&sd->buffer[sd->offset], ptr, nb);
	/* printf("writing %d (%d/%d)\n", nb, sd->offset, sd->length); */
	sd->offset += nb;
	return nmemb;
}

static int stream_eof_(struct Stream_s *stream)
{
	StreamBuffer *sd = (StreamBuffer *)stream->ctx;
	return sd->offset >= sd->length;
}

static int stream_name_(struct Stream_s *s, char *buffer, size_t size)
{
	StreamBuffer *sd = (StreamBuffer *)s->ctx;
	buffer[0] = 0;
	return 0;
}

int64_t stream_tell_(struct Stream_s *s)
{
	StreamBuffer *sd = (StreamBuffer *)s->ctx;
	return sd->offset;
}

int stream_seek_(struct Stream_s *s, int64_t offset, int whence)
{
	StreamBuffer *sd = (StreamBuffer *)s->ctx;
	switch(whence)
	{
		case STREAM_SEEK_BEG:
		{
			sd->offset = offset % sd->length;
		}
		break;
		case STREAM_SEEK_CUR:
		{
			sd->offset = (sd->offset + offset) % sd->length;
		}
		break;
		case STREAM_SEEK_END:
		{
			sd->offset = sd->length;
		}
		break;
	}
	return 0;
}

int init_stream_from_buffer(Stream *s, StreamBuffer *sb, unsigned char *buffer, size_t length)
{
	sb->offset = 0;
	sb->length = length;
	sb->buffer = buffer;
	
	s->ctx = sb;
	s->read = stream_read_;
	s->write = stream_write_;
	s->eof = stream_eof_;
	s->name = stream_name_;
	s->tell = stream_tell_;
	s->seek = stream_seek_;
	return 0;
}
