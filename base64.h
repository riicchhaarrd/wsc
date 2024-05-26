#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

typedef struct
{
	const unsigned char *buffer;
	size_t length;
	size_t bit_offset;
} Bitstream;

// Assuming little-endian

bool bitstream_read_bit(Bitstream *s, uint8_t* result)
{
	size_t byte_offset = s->bit_offset >> 3;
	size_t bit_index = s->bit_offset & 7; // Bit index in byte boundary

	if(byte_offset >= s->length)
	{
		return false;
	}
	/* uint8_t mask = (1 << bit_count) - 1; */
	*result = (s->buffer[byte_offset] & (1 << (7 - bit_index))) != 0;
	++s->bit_offset;
	return true;
}

bool bitstream_read_bits(Bitstream *s, size_t bit_count, uint8_t* result)
{
	assert(bit_count <= 8);
	*result = 0;
	for(size_t i = 0; i < bit_count; ++i)
	{
		uint8_t bit;
		if(!bitstream_read_bit(s, &bit))
			return false;
		*result |= (bit << (bit_count - 1 - i));
	}
	return true;
}

int base64_encode(const unsigned char *input, size_t max_input_length, char *output, size_t max_output_length)
{
	static const char *base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	Bitstream bs = { .buffer = input, .length = max_input_length, .bit_offset = 0 };
	size_t output_index = 0;
	output[output_index] = 0;

	while(1)
	{
		uint8_t code = 0;
		bool eof = !bitstream_read_bits(&bs, 6, &code);
		/* printf("%c", base64_table[code]); */
		if(output_index + 1 >= max_output_length)
			return 1;
		output[output_index++] = base64_table[code];
		if(eof)
			break;
	}
	size_t pad = max_input_length * 8 % 3;
	if(pad != 0)
	{
		for(size_t k = 0; k < pad; ++k)
		{
			/* printf("="); */
			if(output_index + 1 >= max_output_length)
				return 1;
			output[output_index++] = '=';
		}
	}
	output[output_index] = 0;
	return 0;
}

/* int main() */
/* { */
/* 	const char *test = "Hello world!"; */
/* 	char encoded[256]; */
/* 	base64_encode(test, strlen(test), encoded, sizeof(encoded)); */
/* 	printf("encoded = %s\n", encoded); */
/* 	return 0; */
/* } */
