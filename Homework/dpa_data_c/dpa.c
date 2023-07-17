#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#define PT_LENGTH 100
#define NUM_PTS 20000
#define NUM_BYTES_BLOCK 16

#define MIN_KEYBITS 0
#define MAX_KEYBITS 8
#define NUM_KEYBITS 8
#define NUM_KEYS 256

#define FILE_CIPHER "cipher.txt"
#define FILE_PTS "pts.txt"

double pts[NUM_PTS][PT_LENGTH];
unsigned char cipher[NUM_PTS][NUM_BYTES_BLOCK];

/* varables for DPA */
double pts0[NUM_KEYS][NUM_KEYBITS][PT_LENGTH];
double pts1[NUM_KEYS][NUM_KEYBITS][PT_LENGTH];

int num_pts0[NUM_KEYS][NUM_KEYBITS];
int num_pts1[NUM_KEYS][NUM_KEYBITS];

double pt_delta[NUM_KEYS][PT_LENGTH];
double pt_delta_max[NUM_KEYS];
int pt_delta_max_idx[NUM_KEYS];
/* END of varables for DPA */

char buffer[10240];

void load_cipher()
{
	int i;
	FILE *fp;

	fp = fopen(FILE_CIPHER, "r");

	if (fp == NULL)
	{
		printf("Cannot open cipher file.\n");
		exit(0);
	}

	for (i = 0; i < NUM_PTS; i++)
	{
		int j;
		char *p;

		if (!fgets(buffer, 100, fp))
		{
			printf("Error: reading cipher %d\n", i);
			exit(0);
		}
		p = buffer;
		for (j = 0; j < NUM_BYTES_BLOCK; j++)
		{
			int v;
			int c;

			c = *p++;
			v = (c >= 'a') ? (c - 'a' + 10) : (c - '0');

			c = *p++;
			v = (v << 4) | ((c >= 'a') ? (c - 'a' + 10) : (c - '0'));

			cipher[i][j] = v;
		}
	}
	fclose(fp);
}

void print_char(unsigned char *p, int n)
{
	const int w = 16;
	int i = 0;

	while (i < n)
	{
		int j;
		printf("%04X(%5d):\t", i, i);
		for (j = 0; j < w && i < n; j++)
		{
			printf("%02X ", *p++);
			i++;
		}
		printf("\n");
	}
	puts("");
}

void print_int(int *p, int n)
{

	const int w = 16;
	int i = 0;

	while (i < n)
	{
		int j;
		printf("%04X(%5d):\t", i, i);
		for (j = 0; j < w && i < n; j++)
		{
			printf("%6d ", *p++);
			i++;
		}
		printf("\n");
	}
	puts("");
}

void print_double(double *p, int n)
{
	const int w = 8;
	int i = 0;

	while (i < n)
	{
		int j;
		printf("%04X(%5d):\t", i, i);
		for (j = 0; j < w && i < n; j++)
		{
			printf("%10.3f,", *p++);
			i++;
		}
		printf("\n");
	}
	puts("");
}

void load_pts()
{
	FILE *fp;
	int i;

	fp = fopen(FILE_PTS, "r");
	if (fp == NULL)
	{
		printf("Cannot open the power trace file.\n");
		exit(0);
	}

	for (i = 0; i < NUM_PTS; i++)
	{
		int j;
		char *p;
		double *pf = pts[i];

		if (!fgets(buffer, 10240, fp))
		{
			printf("Error: reading pt %d\n", i);
			exit(0);
		}
		p = buffer;
		for (j = 0; j < PT_LENGTH; j++)
		{
			int iv;
			char *curp = p;

			while (*p && *p != ',')
				p++;
			*p++ = 0;

			iv = atoi(curp);
			*pf++ = (double)iv;
		}
	}
	fclose(fp);
}

static unsigned char inv_S[256] =
	{
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

#ifdef GET_MASTER_KEY
static int Rcon[10] =
	{0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000}; // Round Constant
static unsigned char s_box[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

int inv_R(int num)
{
	unsigned char *p = (unsigned char *)&num; // 将 x 转换为指向字符的指针
	unsigned char temp = p[0];				  // 记录第一个字节的值
	for (int i = 0; i < 3; ++i)
	{
		p[i] = p[i + 1]; // 循环左移
	}
	p[3] = temp; // 将第一个字节放到最后
	return num;
}

int inv_sub(int num)
{
	unsigned char *p = (unsigned char *)&num; // 将 x 转换为指向字符的指针
	for (int i = 0; i < 4; ++i)
	{
		p[i] = s_box[p[i]]; // 使用 s-box 表格替换每个字节
	}
	return num;
}
#endif
void PT_scale(double *pd, double *ps, double c, int len)
{
	if (pd == NULL)
	{
		pd = ps;
	}
	while (len--)
	{
		*pd++ = (*ps++) * c;
	}
}

void PT_add(double *sum, double *p1, double *p2, int n)
{
	int i;
	if (!sum)
		sum = p1;
	for (i = 0; i < n; i++)
	{
		sum[i] = p1[i] + p2[i];
	}
}

void PT_mac(double *sum, double *p1, double *p2, int n)
{
	int i;
	for (i = 0; i < n; i++)
	{
		sum[i] += p1[i] * p2[i];
	}
}

void PT_mac_scale(double *sum, double *p1, double p2, int n)
{
	int i;
	for (i = 0; i < n; i++)
	{
		sum[i] += p1[i] * p2;
	}
}

void PT_mac_sub(double *sum, double *p1, double *p2, int n)
{
	int i;
	for (i = 0; i < n; i++)
	{
		sum[i] -= p1[i] * p2[i];
	}
}

void PT_zero(double *p, int n)
{
	while (n--)
	{
		*p++ = 0.0;
	}
}

void PT_diff(double *res, double *p1, double *p2, int n)
{
	int i;
	if (!res)
		res = p1;
	for (i = 0; i < n; i++)
	{
		res[i] = fabs(p1[i] - p2[i]);
	}
}

void PT_sub(double *res, double *p1, double *p2, int n)
{
	int i;
	if (!res)
		res = p1;
	for (i = 0; i < n; i++)
	{
		res[i] = (p1[i] - p2[i]);
	}
}

void PT_abs(double *p1, int n)
{
	int i;
	for (i = 0; i < n; i++)
	{
		p1[i] = abs(p1[i]);
	}
}

double max_dp(double *p, int n, int *idx)
{
	double max = *p++;
	int ri = 0;
	int i;

	for (i = 1; i < n; i++)
	{
		double t = *p++;
		if (t > max)
		{
			max = t;
			ri = i;
		}
	}
	if (idx)
		*idx = ri;
	return max;
}

/** Get the difference of a cipher text byte and the S_box input at the same location.
 */
unsigned char get_difference(unsigned char *cipher, int n, int key)
{
	static unsigned char shift_row[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
	/* put your code here */
	// calculate the shiftrow byte
	unsigned char shiftrow_output = (unsigned char)(cipher[n] ^ (unsigned char)key);
	unsigned char idx = shift_row[n];
	// apply inverse ShiftRows operation to find idx that key byte influence
	// get the input of S-box at this location
	unsigned char sbox_input = inv_S[shiftrow_output];
	// compute the difference between cipher[idx] and sbox_input
	// int distance = 0;
	unsigned char xor = sbox_input ^ cipher[idx]; // XOR to get changed bit
	// while (xor != 0)
	// {
	// 	if (xor&1)
	// 	{
	// 		distance++;
	// 	}
	// 	xor = xor >> 1;
	// }
	// return distance;
	return xor;
	// return the haimingdistance
	// the last statement should be return
}
// return the key byte at location bytenum
int dpa_aes(int bytenum)
{
	int i_pt, i, nbits;
	int kv = 0;
	double temp[NUM_KEYS][PT_LENGTH];

	// Initialization
	for (i = 0; i < NUM_KEYS; i++)
	{
		for (nbits = MIN_KEYBITS; nbits < MAX_KEYBITS; nbits++)
		{
			PT_zero(pts0[i][nbits], PT_LENGTH);
			PT_zero(pts1[i][nbits], PT_LENGTH);
			num_pts0[i][nbits] = num_pts1[i][nbits] = 0;
		}
		PT_zero(pt_delta[i], PT_LENGTH);
		PT_zero(temp[i], PT_LENGTH);
	}

	// Put your code here
	for (i = 0; i < NUM_KEYS; i++)
	{
		for (i_pt = 0; i_pt < NUM_PTS; i_pt++)
		{
			unsigned char distance = get_difference(cipher[i_pt], bytenum, i);
			// printf("i:%d distance:%d\n", i, distance);
			for (int j = 0; j < NUM_KEYBITS; j++) // 将数据集扩充，每一个bit变化与否都分两类
			{
				if (distance & 1)
				{
					PT_add(pts1[i][j], pts1[i][j], pts[i_pt], PT_LENGTH);
					num_pts1[i][j]++;
				}
				else
				{
					PT_add(pts0[i][j], pts0[i][j], pts[i_pt], PT_LENGTH);
					num_pts0[i][j]++;
				}
				distance = distance >> 1;
			}
			// if (distance < 4)
			// {
			// 	PT_add(pts0[i][0], pts0[i][0], pts[i_pt], PT_LENGTH);
			// 	num_pts0[i][0]++;
			// }
			// else
			// {
			// 	PT_add(pts1[i][0], pts1[i][0], pts[i_pt], PT_LENGTH);
			// 	num_pts1[i][0]++;
			// }
		}
		for (int j = 0; j < NUM_KEYBITS; j++) // 每个bit都进行差分计算最后计算差分绝对值的累加曲线
		{
			// printf("num_pts0:%d num_pts1:%d\n", num_pts0[i][0], num_pts1[i][0]);
			if (num_pts0[i][j] != 0)
				PT_scale(pts0[i][j], pts0[i][j], (double)(1.0 / num_pts0[i][j]), PT_LENGTH);
			// print_double(pts0[i][0], PT_LENGTH);
			if (num_pts1[i][j] != 0)
				PT_scale(pts1[i][j], pts1[i][j], (double)(1.0 / num_pts1[i][j]), PT_LENGTH);
			// print_double(pts1[i][0], PT_LENGTH);
			PT_diff(temp[i], pts1[i][j], pts0[i][j], PT_LENGTH);
			PT_add(pt_delta[i], pt_delta[i], temp[i], PT_LENGTH);
			// printf("1\n");
		}
		// for (int j = 1; j < NUM_KEYBITS; j++)
		// {
		// 	PT_add(pts0[i][0], pts0[i][0], pts0[i][j], PT_LENGTH);
		// 	PT_add(pts1[i][0], pts1[i][0], pts1[i][j], PT_LENGTH);
		// }
		// PT_diff(pt_delta[i], pts1[i][0], pts0[i][0], PT_LENGTH);
		// print_double(pt_delta[i], PT_LENGTH);
		pt_delta_max[i] = max_dp(pt_delta[i], PT_LENGTH, &(pt_delta_max_idx[i])); // 获得最尖峰的值
	}
	// printf("max:%f\n", pt_delta_max[i]);
	// print_double(pt_delta_max, NUM_KEYS);
	// print_int(pt_delta_max_idx, NUM_KEYS);
	double maxma = max_dp(pt_delta_max, NUM_KEYS, &kv); // 计算所有可能key中最大尖峰所在的index作为密钥返回
	return kv;
}

int main(int argc, char **argv)
{
	int i, start, end;
	time_t t0;

	start = end = 0;
	switch (argc)
	{
	case 2:
		start = end = atoi(argv[1]);
		;
		break;
	case 3:
		start = atoi(argv[1]);
		;
		end = atoi(argv[2]);
		;
		break;
	}
	start &= 0xF;
	end &= 0xF;

	time(&t0);
	load_cipher();
	// print_char(&cipher[0][0], 16 * 10);
	// print_char(&cipher[19990][0], 16 * 10);
	load_pts();
	// print_double(pts[NUM_PTS - 1], 700);
	printf("Time_load_data: %.2fs\n", difftime(time(NULL), t0));

	unsigned int roundkey[16];
	for (i = start; i <= end; i++)
	{
		int k;
		time(&t0);
		// printf("Working on key %d\n", i);
		k = dpa_aes(i);
		roundkey[i] = (unsigned int)k;
		printf("KEY%d=%02X(%d) %.2fs\n", i, k, k, difftime(time(NULL), t0));
	}
// Calculate Masterkey
#ifdef GET_MASTER_KEY
	unsigned int key[4 * 11];		   // Keymatrix
	for (int i = 0; i < 16; i = i + 4) // Fill in the round key for the tenth round
	{
		key[40 + i / 4] = ((roundkey[i] << 24) | (roundkey[i + 1] << 16) | (roundkey[i + 2] << 8) | (roundkey[i + 3]));
	}
	// printf("10th roundkey:\n");
	// for (int i = 0; i < 16; i = i + 4)
	// {
	// 	printf("KEY%d=%02X(%d)\n", i, ((key[40 + i / 4] >> 24) & 0xFF), ((key[40 + i / 4] >> 24) & 0xFF));
	// 	printf("KEY%d=%02X(%d)\n", i + 1, ((key[40 + i / 4] >> 16) & 0xFF), ((key[40 + i / 4] >> 16) & 0xFF));
	// 	printf("KEY%d=%02X(%d)\n", i + 2, ((key[40 + i / 4] >> 8) & 0xFF), ((key[40 + i / 4] >> 8) & 0xFF));
	// 	printf("KEY%d=%02X(%d)\n", i + 3, (key[40 + i / 4] & 0xFF), (key[40 + i / 4] & 0xFF));
	// }
	for (int i = 39; i >= 0; i--) // Reverse engineering the Round Key Generation Algorithm.
	{
		unsigned int temp = key[i + 3];
		if (i % 4 == 0)
		{
			temp = inv_R(temp);		   // Calculate of the rotate
			temp = inv_sub(temp);	   // Apply of substitution
			temp = temp ^ Rcon[i / 4]; // XOR Round Constant
		}
		key[i] = key[i + 4] ^ temp;
	}
	printf("masterkey:\n"); // Print MasterKey
	for (int i = 0; i < 16; i = i + 4)
	{
		printf("KEY%d=%02X(%d)\n", i, ((key[i / 4] >> 24) & 0xFF), ((key[i / 4] >> 24) & 0xFF));
		printf("KEY%d=%02X(%d)\n", i + 1, ((key[i / 4] >> 16) & 0xFF), ((key[i / 4] >> 16) & 0xFF));
		printf("KEY%d=%02X(%d)\n", i + 2, ((key[i / 4] >> 8) & 0xFF), ((key[i / 4] >> 8) & 0xFF));
		printf("KEY%d=%02X(%d)\n", i + 3, (key[i / 4] & 0xFF), (key[i / 4] & 0xFF));
	}
#endif
	return 0;
}
