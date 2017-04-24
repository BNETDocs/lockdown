#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef enum { FALSE = 0, TRUE = 1 } BOOL;

unsigned char *values = "\x81\xf1\xFF\xFF\xFF\xFF\x35\xFF\xFF\xFF\xFF\x89\x4d\x0c\x89\x45\x10\x6a\x08";	
unsigned char *check  = "\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01";
size_t length = 19;
unsigned int offset1 = 2;
unsigned int offset2 = 7;

void find_seeds(char *filename, int *seed1, int *seed2)
{
	struct stat filestat;
	FILE *f;
	unsigned char *data;
	size_t i, j;
	size_t actual;
	BOOL found;

	if(stat(filename, &filestat) < 0 )
	{
		fprintf(stderr, "Error: couldn't stat file %s\n", filename);
		return;
	}

	fopen_s(&f, filename, "rb");

	if(!f)
	{
		fprintf(stderr, "Error: couldn't open file %s\n", filename);
		return;
	}

	data = malloc(filestat.st_size);
	actual = fread(data, 1, filestat.st_size, f);

	for(i = 0; i < actual - 0x1c; i++)
	{
		found = TRUE;

		for(j = 0; j < length && found; j++)
		{
			if(check[j] && (data[i + j] != values[j]))
				found = FALSE;
		}

		if(found)
		{
			*seed1 = *((int*)(data + i + offset1));
			*seed2 = *((int*)(data + i + offset2));

			printf("%s: %08x, %08x\n", filename, *seed1, *seed2);

//			break;
		}
	}

	free(data);
	fclose(f);
}

int main(int argc, char *argv[])
{
	int i;
	int seed1, seed2;

	if(argc < 2)
	{
		fprintf(stderr, "Error: please specify files on the commandline (%s file1 file2 ...)\n", argv[0]);
		find_seeds("c:\\temp\\lockdown-IX86-00.dll", &seed1, &seed2);
	}
	else
	{
		for(i = 1; i < argc; i++)
			find_seeds(argv[i], &seed1, &seed2);
	}

	system("pause");

	return 0;
}


