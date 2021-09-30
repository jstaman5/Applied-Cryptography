//Jared Staman
//CS 583 
//Project 1: AES
//Finished 9/10/21

#include <stdio.h>
#include <stdlib.h>

//FUNCTION PROTOTYPES
void invCipher(u_int8_t *in, u_int8_t *out, u_int32_t *w, int Nr);
void cipher(u_int8_t *in, u_int8_t *out, u_int32_t *w, int Nr);
void invMixColumns(u_int8_t state[4][4]);
void addRoundKey(u_int8_t state[4][4], u_int32_t *w, int Nr);
void mixColumns(u_int8_t state[4][4]);
void invShiftRows(u_int8_t state[4][4]);
void invSubBytes(u_int8_t state[4][4]);
void shiftRows(u_int8_t state[4][4]);
void subBytes(u_int8_t state[4][4]);
void keyExpansion(u_int8_t *key, u_int32_t *w, int Nk);
u_int32_t rotWord(u_int32_t input);
u_int32_t subWord(u_int32_t input);
u_int8_t ffAdd(u_int8_t a,u_int8_t b);
u_int8_t xtime(u_int8_t a);
u_int8_t ffMultiply(u_int8_t a, u_int8_t b);


FILE *fp = fopen("output.txt", "w");

int main() {

	//TEST CASE 1
	//
	//NK = 4, NR = 10
	u_int32_t w[44];
	u_int8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
							0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	keyExpansion(key, w, 4);

	//input plaintext
	u_int8_t in[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
							0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

	//output
	u_int8_t out[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	//heading for test case 1
	fprintf(fp, "PLAINTEXT:          00112233445566778899aabbccddeeff\nKEY:                000102030405060708090a0b0c0d0e0f\n\nCIPHER (ENCRYPT):\n");
	fprintf(fp, "round[ 0].input     00112233445566778899aabbccddeeff");

	cipher(in, out, w, 10);
	
	u_int8_t out2[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


	//heading for inverse of test case 1
	fprintf(fp, "\n\nINVERSE CIPHER (DECRYPT):\n");
	fprintf(fp, "round[ 0].iinput    69c4e0d86a7b0430d8cdb78070b4c55a");

	invCipher(out, out2, w, 10);


	//TEST CASE 2
	//
	//NK = 6, NR = 12
	u_int32_t w2[52];
	u_int8_t key2[24] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	
	keyExpansion(key2, w2, 6);

	u_int8_t in2[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	u_int8_t out3[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	fprintf(fp, "\n\n\nPLAINTEXT:          00112233445566778899aabbccddeeff\nKEY:                000102030405060708090a0b0c0d0e0f1011121314151617\n\nCIPHER (ENCRYPT):\n");
    fprintf(fp, "round[ 0].input     00112233445566778899aabbccddeeff");

	cipher(in2, out3, w2, 12);

	u_int8_t out4[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	fprintf(fp, "\n\nINVERSE CIPHER (DECRYPT):\n");
	fprintf(fp, "round[ 0].iinput    dda97ca4864cdfe06eaf70a0ec0d7191");

	invCipher(out3, out4, w2, 12);

	//Test Case 3
	//
	//NK = 8, NR = 14
	u_int32_t w3[60];
	u_int8_t key3[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
						0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

	keyExpansion(key3, w3, 8);

	u_int8_t in3[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    u_int8_t out5[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    fprintf(fp, "\n\n\nPLAINTEXT:          00112233445566778899aabbccddeeff\nKEY:                000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n\nCIPHER (ENCRYPT):\n");
    fprintf(fp, "round[ 0].input     00112233445566778899aabbccddeeff");

    cipher(in3, out5, w3, 14);

	u_int8_t out6[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	
	fprintf(fp, "\n\nINVERSE CIPHER (DECRYPT):\n");
	fprintf(fp, "round[ 0].iinput    8ea2b7ca516745bfeafc49904b496089");

	invCipher(out5, out6, w3, 14);


	fclose(fp);
	return 0;

}

u_int8_t Sbox[16][16] = {
    { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
    { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
    { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
    { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
    { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
    { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
    { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
    { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
    { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
    { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
    { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
    { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
    { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
    { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
    { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
    { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
    };

u_int8_t InvSbox[16][16] = {
	{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb } ,
    { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb } ,
    { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e } ,
    { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 } ,
    { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 } ,
    { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 } ,
    { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 } ,
    { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b } ,
    { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 } ,
    { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e } ,
    { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b } ,
    { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 } ,
    { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f } ,
    { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef } ,
    { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 } ,
    { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
    };

u_int32_t Rcon[] = { 0x00000000,
           0x01000000, 0x02000000, 0x04000000, 0x08000000,
           0x10000000, 0x20000000, 0x40000000, 0x80000000,
           0x1B000000, 0x36000000, 0x6C000000, 0xD8000000,
           0xAB000000, 0x4D000000, 0x9A000000, 0x2F000000,
           0x5E000000, 0xBC000000, 0x63000000, 0xC6000000,
           0x97000000, 0x35000000, 0x6A000000, 0xD4000000,
           0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000,
           0xC5000000, 0x91000000, 0x39000000, 0x72000000,
           0xE4000000, 0xD3000000, 0xBD000000, 0x61000000,
           0xC2000000, 0x9F000000, 0x25000000, 0x4A000000,
           0x94000000, 0x33000000, 0x66000000, 0xCC000000,
           0x83000000, 0x1D000000, 0x3A000000, 0x74000000,
           0xE8000000, 0xCB000000, 0x8D000000};


void invCipher(u_int8_t *in, u_int8_t *out, u_int32_t *w, int Nr) {
	u_int8_t state[4][4];
	int i, j, l, k;

	//format input to 4x4
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			state[j][i] = in[4*i + j];
		}
	}

	addRoundKey(state, w, Nr);

	//print first key schedule value
	fprintf(fp, "\nround[ 0].ik_sch    ");
    u_int32_t hold = 0;
    u_int8_t tmp = 0;
    for(k = 0; k < 4; k++) {
        for(l = 3; l >= 0; l--) {
            hold = w[Nr*4 + k];
            hold = hold >> (l*8);
            tmp = hold;
            fprintf(fp, "%02x", tmp);
        }
    }

	//j keeps track of round
	j = 0;
	for(i = Nr-1; i > 0; i--) {
		j++;
		//print start of round state
		fprintf(fp, "\nround[%2d].istart    ", j);
        for(k = 0; k < 4; k++) {
            for(l = 0; l < 4; l++) {
                fprintf(fp, "%02x", state[l][k]);
            }
        }

		invShiftRows(state);
		//print state after invShiftRows
		fprintf(fp, "\nround[%2d].is_row    ", j);
        for(k = 0; k < 4; k++) {
            for(l = 0; l < 4; l++) {
                fprintf(fp, "%02x", state[l][k]);
            }
        }

		invSubBytes(state);
		//print state after invSubBytes
		fprintf(fp, "\nround[%2d].is_box    ", j);
        for(k = 0; k < 4; k++) {
            for(l = 0; l < 4; l++) {
                fprintf(fp, "%02x", state[l][k]);
            }
        }

		addRoundKey(state, w, i);
		
		//print inverse key schedule value
		fprintf(fp, "\nround[%2d].ik_sch    ", j);
        hold = 0;
        tmp = 0;
        for(k = 0; k < 4; k++) {
            for(l = 3; l >= 0; l--) {
                hold = w[i*4 + k];
                hold = hold >> (l*8);
                tmp = hold;
                fprintf(fp, "%02x", tmp);
            }
		}
		//print state after addroundkey
		fprintf(fp, "\nround[%2d].ik_add    ", j);
        for(k = 0; k < 4; k++) {
            for(l = 0; l < 4; l++) {
                fprintf(fp, "%02x", state[l][k]);
            }
        }
		


		invMixColumns(state);
	}
	j++;

	//print start state of final round
	fprintf(fp, "\nround[%2d].istart    ", j);
    for(k = 0; k < 4; k++) {
        for(l = 0; l < 4; l++) {
            fprintf(fp, "%02x", state[l][k]);
        }
    }


	invShiftRows(state);
	//print state after invShiftRows
	fprintf(fp, "\nround[%2d].is_row    ", j);
    for(k = 0; k < 4; k++) {
        for(l = 0; l < 4; l++) {
            fprintf(fp, "%02x", state[l][k]);
        }
    }

	invSubBytes(state);
	//print state after inv sub bytes
	fprintf(fp, "\nround[%2d].is_box    ", j);
    for(k = 0; k < 4; k++) {
        for(l = 0; l < 4; l++) {
            fprintf(fp, "%02x", state[l][k]);
        }
	}


	addRoundKey(state, w, 0);

	//print key schedule value
	fprintf(fp, "\nround[%2d].ik_sch    ", j);
    hold = 0;
    tmp = 0;
    for(k = 0; k < 4; k++) {
        for(l = 3; l >= 0; l--) {
            hold = w[i*4 + k];
            hold = hold >> (l*8);
            tmp = hold;
            fprintf(fp, "%02x", tmp);
        }
    }

	//print output
    fprintf(fp, "\nround[%2d].ioutput   ", j);
    for(k = 0; k < 4; k++) {
        for(l = 0; l < 4; l++) {
            fprintf(fp, "%02x", state[l][k]);
        }
    }

	//format output array of 16
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			out[4*i + j] = state[j][i];
		}
	}


	return;
}

void cipher(u_int8_t *in, u_int8_t *out, u_int32_t *w, int Nr) {
	u_int8_t state[4][4];
	int i, j, k, l;

	//format input to 4x4
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			state[j][i] = in[4*i + j];
		}
	}

	
	addRoundKey(state, w, 0);

	//print first key schedule value
	fprintf(fp, "\nround[ 0].k_sch     ");
    u_int32_t hold = 0;
    u_int8_t tmp = 0;
    for(k = 0; k < 4; k++) {
        for(l = 3; l >= 0; l--) {
            hold = w[0*4 + k];
            hold = hold >> (l*8);
            tmp = hold;
            fprintf(fp, "%02x", tmp);
        }
    }

	for(i = 1; i < Nr; i++) {
		
		//print state at start of each round
		fprintf(fp, "\nround[%2d].start     ", i);
		for(k = 0; k < 4; k++) {
			for(l = 0; l < 4; l++) {
				fprintf(fp, "%02x", state[l][k]);
			}
		}

		subBytes(state);
		//print state after subbytes
		fprintf(fp, "\nround[%2d].s_box     ", i);
		for(k = 0; k < 4; k++) {
			for(l = 0; l < 4; l++) {
				fprintf(fp, "%02x", state[l][k]);
			}
		}

		shiftRows(state);
		//print state after shift rows
		fprintf(fp, "\nround[%2d].s_row     ", i);
		for(k = 0; k < 4; k++) {
            for(l = 0; l < 4; l++) {
                fprintf(fp, "%02x", state[l][k]);
            }
        }

		mixColumns(state);
		//print state after mixcolumns
		fprintf(fp, "\nround[%2d].m_col     ", i);
        for(k = 0; k < 4; k++) {
            for(l = 0; l < 4; l++) {
                fprintf(fp, "%02x", state[l][k]);
            }
        }

		addRoundKey(state, w, i);

		//print key schedule value
		fprintf(fp, "\nround[%2d].k_sch     ", i);
		hold = 0;
		tmp = 0;
        for(k = 0; k < 4; k++) {
			for(l = 3; l >= 0; l--) {
				hold = w[i*4 + k];
				hold = hold >> (l*8);
				tmp = hold;
				fprintf(fp, "%02x", tmp);
			}
		}


	}
	int m = i;
	//print state at start of last round
	fprintf(fp, "\nround[%2d].start     ", m);
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            fprintf(fp, "%02x", state[j][i]);
        }
    }


	subBytes(state);
	//print state after subbytes
	fprintf(fp, "\nround[%2d].s_box     ", m);
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            fprintf(fp, "%02x", state[j][i]);
        }
    }

	shiftRows(state);
	//print state after shift rows
	fprintf(fp, "\nround[%2d].s_row     ", m);
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            fprintf(fp, "%02x", state[j][i]);
        }
    }

	addRoundKey(state, w, Nr);

	//print key schedule value
	fprintf(fp, "\nround[%2d].k_sch     ", m);
	hold = 0;
    tmp = 0;
    for(i = 0; i < 4; i++) {
        for(j = 3; j >= 0; j--) {
            hold = w[Nr*4 + i];
            hold = hold >> (j*8);
            tmp = hold;
            fprintf(fp, "%02x", tmp);
        }
    }

	//print output
	fprintf(fp, "\nround[%2d].output    ", m);
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            fprintf(fp, "%02x", state[j][i]);
        }
    }

	//set output to format an array of 16
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			out[4*i + j] = state[j][i];
		}
	}

	return;
}

//inverse of mixcolumns
void invMixColumns(u_int8_t state[4][4]) {
	u_int8_t result[4][4];
	int i,j;

	u_int8_t m[4][4] = {
		{0x0e, 0x0b, 0x0d, 0x09},
		{0x09, 0x0e, 0x0b, 0x0d},
		{0x0d, 0x09, 0x0e, 0x0b},
		{0x0b, 0x0d, 0x09, 0x0e} };

	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			result[i][j] = ffMultiply(state[0][j], m[i][0]) ^ ffMultiply(state[1][j], m[i][1]) ^ ffMultiply(state[2][j], m[i][2]) ^ ffMultiply(state[3][j], m[i][3]);
        }
    }

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[i][j] = result[i][j];
        }
    }

	return;
}

//Adds a round key to the state using xor
void addRoundKey(u_int8_t state[4][4], u_int32_t *w, int Nr) {
	int i,j;
	u_int32_t hold = 0;
	u_int8_t tmp = 0;
	u_int8_t tmp2 = 0;

	for(i = 0; i < 4; i++) {
		for(j = 3; j >= 0; j--) {
			hold = w[Nr * 4 + i];
			hold = hold >> (j*8);
			tmp = hold;
			state[3-j][i] = tmp ^ state[3-j][i];
		}
	}

	return;
}

//Treats each column in state as a four-term polynomial. Polynomial is multiplied by a fixed polynomial with coefficients
void mixColumns(u_int8_t state[4][4]) {
	u_int8_t result[4][4];
	int i,j;

	u_int8_t m[4][4] = { 
		{2, 3, 1, 1},
		{1, 2, 3, 1},
		{1, 1, 2, 3},
		{3, 1, 1, 2}
	};	

	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			result[i][j] = ffMultiply(state[0][j], m[i][0]) ^ ffMultiply(state[1][j], m[i][1]) ^ ffMultiply(state[2][j], m[i][2]) ^ ffMultiply(state[3][j], m[i][3]);
		}
	}

	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			state[i][j] = result[i][j];
		}
	}

	return;
}

//Performs the inverse of shiftRows one each row of state
void invShiftRows(u_int8_t state[4][4]) {
	u_int8_t tmp, tmp2;
	int i;
	//don't touch row0
	
	//shift row1
	tmp = state[1][3];
	for(i = 3; i > 0; i--) {
		state[1][i] = state[1][i-1];
	}
	state[1][0] = tmp;

	//shift row2
	tmp = state[2][0];
	tmp2 = state[2][1];
	for(i = 0; i < 2; i++) {
		state[2][i] = state[2][i+2];
	}
	state[2][2] = tmp;
	state[2][3] = tmp2;

	//shift row3
	tmp = state[3][0];
	for(i = 0; i < 3; i++) {
		state[3][i] = state[3][i+1];
	}
	state[3][3] = tmp;

	return;
}

//Substitutes each byte in state with its corresponding value from the inverse S-box
void invSubBytes(u_int8_t state[4][4]) {
	u_int8_t left, right;
	int i, j;

	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			left = state[i][j] >> 4;
			right = state[i][j] << 4;
			right = right >> 4;
			state[i][j] = InvSbox[left][right];
		}
	}
	return;
}

//This transformation performs a circular shift on each row in the State
void shiftRows(u_int8_t state[4][4]) {
	u_int8_t tmp, tmp2;
	int i;
	//don't touch row0
	
	//shift row1 by 1
	tmp = state[1][0];
	for(i = 0; i < 3; i++) {
		state[1][i] = state[1][i+1];
	}
	state[1][3] = tmp;

	//shift row2 by 2
	tmp = state[2][0];
	tmp2 = state[2][1];
	for(i = 0; i < 2; i++) {
		state[2][i] = state[2][i+2];
	}
	state[2][2] = tmp;
	state[2][3] = tmp2;

	//shift row3 by 3
	tmp = state[3][3];
	for(i = 3; i > 0; i--) {
		state[3][i] = state[3][i-1];
	}
	state[3][0] = tmp;
	
	return;
}

//This transformation substitutes each byte in the State with its corresponding value from S-box
void subBytes(u_int8_t state[4][4]) {
	u_int8_t left, right;
	int i, j;
	
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			left = state[i][j] >> 4;
			right = state[i][j] << 4;
			right = right >> 4;
			state[i][j] = Sbox[left][right];
		}
	}
	return;
}

//Routine used to generate a series of Round Keys from the Cipher Key
void keyExpansion(u_int8_t *key, u_int32_t *w, int Nk) {
	u_int32_t tmp;
	u_int32_t tmp2;
	int i = 0;

	while(i < Nk) {
		//w[i] = (u_int32_t)(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
		tmp2 = key[4*i];
		tmp2 = tmp2 << 8;
		tmp2 = tmp2 + key[4*i+1];
		tmp2 = tmp2 << 8;
		tmp2 = tmp2 + key[4*i+2];
		tmp2 = tmp2 << 8;
		tmp2 = tmp2 + key[4*i+3];

		w[i] = tmp2;
		i += 1;
	}

	i = Nk;
	int Nb = 4;
	int Nr = Nk + 6;
 
	while(i < (Nb*(Nr+1))) {
		tmp = w[i-1];
		if(i % Nk == 0) {
			tmp = subWord(rotWord(tmp)) ^ Rcon[i/Nk];
		}
		else if(Nk > 6 && (i % Nk) == 4) {
			tmp = subWord(tmp);
		}
		w[i] = w[i-Nk] ^ tmp;
		i += 1;
	}

	return;
}

//performs a cyclic permutation on its input word
u_int32_t rotWord(u_int32_t input) {
	u_int32_t output;
	u_int8_t tmp;

	tmp = input >> 24;
	output = input << 8;
	output = output + tmp;

	return output;
}

//takes a four-byte input word and substitutes each byte in that word with its appropriate value from S-box
u_int32_t subWord(u_int32_t input) {
	u_int32_t output;
	
	u_int8_t tmp, left, right;
	
	tmp = input;
	
	int i;
	for(i = 3; i >= 0; i--) {
		tmp = input >> (i*8);
		left = tmp >> 4;
		right = tmp << 4;
		right = right >> 4;
		output = output << 8;
		output = output + Sbox[left][right];
	}
	return output;
}

//adds two finite fields, simple xor
u_int8_t ffAdd(u_int8_t a, u_int8_t b) {
	u_int8_t c;
	c = a ^ b;
	return c;
}

//multiplies a finite field by x
u_int8_t xtime(u_int8_t a) {
	u_int8_t b;
	//left shift
	b = a << 1;
	//must check for overflow
	if(b < a) {
		b = b ^ 0x1b;
	}
	return b;
}

//functions uses xtime to multiply any finite field by any other finite field
u_int8_t ffMultiply(u_int8_t a, u_int8_t b) {
	u_int8_t c = 0;
	u_int8_t a_copy = 0;

	//list of if statements checking whether one field is divisible by 0x01, 0x02...
	if( (b ^ 0x01) < b) {
		c = c ^ a;
	}

	if( (b ^ 0x02) < b) {
		a_copy = xtime(a);
		c = c ^ a_copy;
	}

	if( (b ^ 0x04) < b) {
		a_copy = xtime(a);
		a_copy = xtime(a_copy);
		c = c ^ a_copy;
	}

	if( (b ^ 0x08) < b) {
		a_copy = xtime(a);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		c = c ^ a_copy;
	}

	if( (b ^ 0x10) < b) {
		a_copy = xtime(a);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		c = c ^ a_copy;
	}

	if( (b ^ 0x20) < b) {
		a_copy = xtime(a);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		c = c ^ a_copy;
	}

	if( (b ^ 0x40) < b) {
		a_copy = xtime(a);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		c = c ^ a_copy;
	}

	if( (b ^ 0x80) < b) {
		a_copy = xtime(a);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		a_copy = xtime(a_copy);
		c = c ^ a_copy;	
	}
	return c;
}

