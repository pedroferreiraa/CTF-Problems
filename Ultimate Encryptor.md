<h1>Desafio Ultimate Encryptor BHACK 2022.</h1>

<h3>tl;dr Caso não queira saber a explicação o código está no final da página e no repositório como ultimate_encryptor.c.</h3>

Nos é dado dois arquivos, o main e o out.txt.

<p>Usando o comando file no arquivo main podemos ver que é um executável ELF, e podemos usar o Ghidra para analisar melhor o executável.</p>

```
main: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1b22dbd62be7556599f6595996b197d5ad0fd11f, for GNU/Linux 3.2.0, with debug_info, not stripped
```
A função main recebe dois arquivos como parâmetros, chama uma função read_file, e depois chama a função UltimateEncryption. A função read_file irá copiar o conteúdo do arquivo passado no primeiro parâmetro para uma string, depois essa string é passada para a função UltimateEncryption que faz algumas operações com o objetivo de criptografar a string recebida. Irei mostrar a função completa e depois dissecar alguns pontos dela.
```c
char *UltimateEncryption(char *str)
{
	size_t size1;
	char aux;
	int i, l, l, k;
	int size;
	char ch;

	size1 = strlen(str);
	size = (int)size1;

	if ((size1 & 1) != 0) {
		aux = 0x30;
		strncat(str,(char *)&aux,2);
		size = size + 1;
	}

	for (i = 0; i < size; i = i + 1) {
		str[i] = str[(i + 1) % size] ^ str[i];
	}

	for (j = 0; j < size; j = j + 1) {
		str[j] = str[j] ^ 0x2b;
	}

	for (k = 0; k < size; k = k + 1) {
		str[k] = str[k] + '\x0f';
	}

	for (l = 0; l < size; l = l + 2) {
		ch = str[l];
		str[l] = str[l + 1];
		str[l + 1] = ch;
	}
        
	return str;
}

```
A primeira parte verifica se o tamanho (size1) é ímpar, se for o caso de size1 ser ímpar então adiciona o valor 0x30 (0 na tabela ascii) na string. Isso é conhecido como preenchimento (padding).

```c
if ((size1 & 1) != 0) {
          aux = 0x30;
          strncat(str,(char *)&aux,2);
          size = size + 1;
}
```
Na segunda parte temos um XOR no próprio array. Devemos nos atentar ao comportamento do módulo que irá gerar uma sequência numérica de posições.

Tabela 1:
```
/*
 * A sequência sempre será as posições:
 * Exemplo: 
 * str[0] = str[0] ^ str[1]
 * str[1] = str[1] ^ str[2]
 * str[2] = str[2] ^ str[3]
 * 		.
 * 		.
 * 		.
 * str[size - 1] = str[size - 1] ^ str[0]
*/
``` 
OBS: O módulo sempre irá aumentar até que chegue em `(size - 1 + 1) % size` que resulta em 0.
Na terceira parte temos um simples XOR com o valor 0x2b (43 em decimal) e na quarta parte temos uma subtração do valor 0x0f (15 em decimal).

Na quinta e última parte temos uma substituição de valores (e.g, str[0] recebe str[1]).

Tabela 2:
```
/*
 * A troca irá respeitar essa sequência.
 * 0 e 1
 * 2 e 3
 * 4 e 5
 *   .
 *   .
 *   .
 * size - 2 e size - 1
*/
```
Todos os procedimentos da função UltimateEncryption são reversíveis, isso é importante para reverter o processo de criptografia. Foram usados soma, troca de posição e XOR, que são operações reversíveis. Temos aqui a tabela do XOR.

Tabela 3:
```
/*
 * A | B | XOR
 * 0 | 0 |  0
 * 0 | 1 |  1
 * 1 | 0 |  1
 * 1 | 1 |  0
*/
```
Tabela 4: Exemplo de operações XOR.
```
/*
 * 0x30 | 0x65 |  0x55
 * 0x30 | 0x55 |  0x65
 * 0x55 | 0x65 |  0x30
*/
```
A tabela nos mostra a reversibilidade da operação XOR, podemos obter os valores anteriores a partir dos novos. No caso do 0x30 que foi "xortado" com 0x65, resultando em 0x55, se tivermos o valor do 0x65 e 0x55 conseguimos voltar para o valor anterior, o 0x30, fazendo um XOR. O processo de descriptografia será feito do último procedimento até o primeiro, de forma reversa.

Primeiramente, faremos a troca de posições que segue a tabela 2.

```c
for (i = 0; i < size; i += 2) {
        ch = buffer[i];
        buffer[i] = buffer[i + 1];
        buffer[i + 1] = ch;
}
```
Depois revertemos as operações de soma e XOR. A operação de soma será revertida fazendo a diminuição, e a operação de XOR fazendo um próprio XOR,
como podemos ver na tabela 4.

```c
for (i = 0; i < size; ++i) {
	buffer[i] -= 0x0f;
	buffer[i] ^= 0x2b;
}
```

Agora vem a parte mais importante, que é reverter o XOR respeitando a sequência da tabela 1. Revertendo a sequência, temos:

Tabela 5:
```
/*
 * A sequência inversa:
 * Exemplo:
 * str[size - 1] = str[size - 1] ^ str[0]
 * str[size - 2] = str[size - 2] ^ str[size - 1]
 * str[size - 3] = str[size - 3] ^ str[size - 2]
 * 		.
 * 		.
 * 		.
 *
 * str[0] = str[0] ^ str[1]
*/
```
Segue abaixo um exemplo para clarificar a ideia.

```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	int size = 5;
	int aux = size;

	printf("Ordem Direta\n");
	for (int i = 0; i < size; i = i + 1)
		printf("str[%d] = str[%d] ^ str[%d]\n", i, i, (i + 1) % size);

	printf("Ordem Inversa\n");
	for (int i = size - 1; i >= 0; --i)
		printf("str[%d] = str[%d] ^ str[%d]\n", i, i, (aux--) % size);


	return 0;
}

```
O resultado do código anterior é:

```
Ordem Direta
str[0] = str[0] ^ str[1]
str[1] = str[1] ^ str[2]
str[2] = str[2] ^ str[3]
str[3] = str[3] ^ str[4]
str[4] = str[4] ^ str[0]
Ordem Inversa
str[4] = str[4] ^ str[0]
str[3] = str[3] ^ str[4]
str[2] = str[2] ^ str[3]
str[1] = str[1] ^ str[2]
str[0] = str[0] ^ str[1]
```

```c
for (i = size - 1; i >= 0; --i)
	buffer[i] ^= buffer[(aux--) % size];
```
Depois desses passos conseguimos extrair uma string de bytes, olhando o hexadecimal, temos:

```
00000000: 474d 4446 4e7e 4a6e 5a5c 6a70 5a64 7760  GMDFN~JnZ\jpZdw`
00000010: 5a51 6d60 5a50 6971 6c68 6471 605a 406b  ZQm`ZPiqlhdq`Z@k
00000020: 6677 7c75 716a 7778 0f35 0fdf            fw|uqjwx.5..
```

Pelo formato da flag, podemos ver que `GMDFN` é um candidato a palavra `BHACK`, então com a ajuda da operação magic no CyberChef, temos a flag.
![image](https://user-images.githubusercontent.com/115036346/205911575-f31fbc20-e45b-49a8-9cae-734f11b75290.png)

Segue o código completo da implementação da descriptografia, ele já vem com o passo do CyberChef, então não é preciso ir lá e usar o magic.

```c
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

```
