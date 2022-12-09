#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void decrypter(unsigned char *buffer, int size)
{
	int i;
	unsigned char ch;

	for (i = 0; i < size; i += 2) {
		ch = buffer[i];
		buffer[i] = buffer[i + 1];
		buffer[i + 1] = ch;
	}

	for (i = 0; i < size; ++i) {
		buffer[i] -= 0x0f;
		buffer[i] ^= 0x2b;
	}

	int aux = size;

	for (i = size - 1; i >= 0; --i)
		buffer[i] ^= buffer[(aux--) % size];

	for (i = 0; i < size; ++i)
		buffer[i] ^= 5;

	for (i = 0; i < size; ++i)
		printf("%c", buffer[i]);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Modo de Uso: ./%s arquivo_cifrado\n", argv[0]);
		exit(EXIT_FAILURE);
	};

	FILE *fptr = fopen(argv[1], "r");
	unsigned char ch;

	fseek(fptr, 0, SEEK_END);
	int size = ftell(fptr), i = 0;

	unsigned char *buffer = (unsigned char *) malloc(size * sizeof(unsigned char));

	rewind(fptr);

	while ((ch = fgetc(fptr), (char) ch != EOF)) {
		buffer[i] = ch;
		i++;
	}

	decrypter(buffer, size);

	fclose(fptr);
	free(buffer);

	return 0;
}
