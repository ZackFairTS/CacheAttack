#include "attack.h"


#define BUFF_SIZE ( 80 )
#define SAMPLE_NUM 2000000

#define unit unsigned int
#define uchar unsigned char 

typedef char DataType; // Set Data Type
typedef unsigned char Byte;

pid_t pid	   =0;	 // process ID (of either parent or child) from fork

int   target_raw[ 2 ];   // unbuffered communication: attacker -> attack target
int   attack_raw[ 2 ];   // unbuffered communication: attack target -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream

void cleanup( int s ){
  // Close the   buffered communication handles.
  fclose( target_in  );
  fclose( target_out );

  // Close the unbuffered communication handles.
  close( target_raw[ 0 ] ); 
  close( target_raw[ 1 ] ); 
  close( attack_raw[ 0 ] ); 
  close( attack_raw[ 1 ] ); 

  // Forcibly terminate the attack target process.
  if( pid > 0 ) {
    kill( pid, SIGKILL );
  }

  // Forcibly terminate the attacker      process.
  exit( 1 ); 
}

/*-----------------------variables----------------------------*/
int etime, collect_time[SAMPLE_NUM],  k=0;
mpz_t collect_m[SAMPLE_NUM], collect_c[SAMPLE_NUM];
char RDiffer[SAMPLE_NUM][100];
mpf_t avrtime[8][64];
unsigned long numcount[8][64];
char okeydiffer[50];
uchar pkey[8];
uchar Key[16][6];
uchar PreKey[8];
uchar bc_c[8];
int ncounter=0;

// plaintext used to verify
uchar bp[8]= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// cypher used to verify
uchar bc_v[8] = {0x2A, 0xD8, 0xD0, 0xDA, 0x67, 0x91, 0xC4, 0xA9};


/******************** used for computing key difference ************************/
int IP_Table[64] = {  57,49,41,33,25,17,9,1,  
                      59,51,43,35,27,19,11,3,  
                      61,53,45,37,29,21,13,5,  
                      63,55,47,39,31,23,15,7,  
                      56,48,40,32,24,16,8,0,  
                      58,50,42,34,26,18,10,2,  
                      60,52,44,36,28,20,12,4,  
                      62,54,46,38,30,22,14,6};   


int IP_RecoverP_Table[64] = { 39,7 ,47,15,55,23,63,31,
                              38,6 ,46,14,54,22,62,30,
                              37,5 ,45,13,53,21,61,29,
                              36,4 ,44,12,52,20,60,28,
                              35,3 ,43,11,51,19,59,27,
                              34,2 ,42,10,50,18,58,26,
                              33,1 ,41,9 ,49,17,57,25,
                              32,0 ,40,8 ,48,16,56,24};


int Key_PCINV_Table[56] = {7,15,23,55,51,43,35,
			   6,14,22,54,50,42,34,
			   5,13,21,53,49,41,33,
			   4,12,20,52,48,40,32,
			   3,11,19,27,47,39,31,
			   2,10,18,26,46,38,30,
			   1,9, 17,25,45,37,29,
			   0,8, 16,24,44,36,28};



//Expand Table 
int E_Table[48] = {31,0, 1, 2, 3, 4,  
                   3, 4, 5, 6, 7, 8,  
                   7, 8, 9, 10,11,12,  
                   11,12,13,14,15,16,  
                   15,16,17,18,19,20,  
                   19,20,21,22,23,24,  
                   23,24,25,26,27,28,  
                   27,28,29,30,31,0};  


/******************** used for DES encryption ************************/

uchar Ip[64]={58,50, 42, 34, 26, 18, 10, 2, 
	      60, 52, 44, 36, 28, 20, 12, 4,
	      62, 54, 46, 38, 30, 22, 14, 6,
	      64, 56, 48, 40, 32, 24, 16, 8,
	      57, 49, 41, 33, 25, 17,  9, 1,
	      59, 51, 43, 35, 27, 19, 11, 3,
	      61, 53, 45, 37, 29, 21, 13, 5,
	      63, 55, 47, 39, 31, 23, 15, 7};


uchar Ipr[64]={ 40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41,  9, 49, 17, 57, 25};

uchar Pc_1[56]={57,49, 41, 33, 25, 17,  9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27, 
		19,11,  3, 60, 52, 44, 36,
		63,55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29, 
		21, 13, 5, 28, 20, 12,  4};


uchar Pc_2[48]={14, 17, 11, 24,  1,  5,
		 3, 28, 15,  6, 21, 10,
		23, 19, 12,  4, 26,  8,
		16,  7, 27, 20, 13,  2,
		41, 52, 31, 37, 47, 55, 
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32};

uchar Pc_3[48]={ 3,  4,  5,  6,  7,  8, 
		11, 12, 13, 14, 15, 16, 
		19, 20, 21, 22, 23, 24, 
		27, 28, 29, 30, 31, 32,
		35, 36, 37, 38, 39, 40,
		43, 44, 45, 46, 47, 48,
		51, 52, 53, 54, 55, 56,
		59, 60, 61, 62, 63, 64};

uchar Ex[48]={32,  1,  2,  3,  4,  5, 
	       4,  5,  6,  7,  8,  9, 
	       8,  9, 10, 11, 12, 13,
	      12, 13, 14, 15, 16, 17, 
	      16, 17, 18, 19, 20, 21,
	      20, 21, 22, 23, 24, 25,
	      24, 25, 26, 27, 28, 29,
	      28, 29, 30, 31, 32,  1};


uchar Px[32]={16,  7, 20, 21,
	      29, 12, 28, 17,
	       1, 15, 23, 26,
	       5, 18, 31, 10,
	       2,  8, 24, 14,
	      32, 27,  3,  9,
	      19, 13, 30,  6,
	      22, 11,  4, 25};


uchar ShTb[16]={1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}; 


uchar Sbox[8][64]={
	//S1
{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},

	//S2
{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},

	//S3
{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7, 
1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},

	//S4                    
{7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},

	//S5
{2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9, 
14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6, 
4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},

	//S6                   
{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11, 
10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8, 
9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6, 
4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},

	//S7
{4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6, 
1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2, 
6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},

	//S8
{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}

}; 



/******************** key difference computing ************************/
// transform char to int 
int charToint(char c){
	if(c>='0'&&c<='9')
		return c-48;
	return 0;
	}

// transform int to char 
char intTochar(int i){
	if(i>=0&&i<=9)
		return i+48;
	return 0;
	}

// transform int to binary
void intTobinary(int count, int num, char result[]){
    int k, i=0;
    
    for (count = 5; count >= 0; count--)
    {
        k = num >> count;
        
        if (k & 1){
          //  printf("1");
            result[i]='1';
            i++;

        }
        else{
            //printf("0");
            result[i]='0';
            i++;

        }
        
    }
    
}


void interact(int *etime, mpz_t m, mpz_t c)
{
	// Send m to   attack target
	gmp_fprintf( target_in, "%ZX\n", m);  
	fflush( target_in );

	// Receive result from attack target
	gmp_fscanf( target_out, "%d%ZX", etime, c);
}

void interact2(int *etime, mpz_t m, mpz_t k, mpz_t c){
	
	// Send m to   attack target
	gmp_fprintf( target_in, "%ZX\n%ZX\n", m, k);  
	fflush( target_in );

	// Receive result from attack target
	gmp_fscanf( target_out, "%d%ZX", etime, c);

}

/* DES IP transform */
void DES_IP_Transform(DataType data[64]){  
    int cnt;  
    DataType temp[64];  
    for(cnt = 0; cnt < 64; cnt++){  
        temp[cnt] = data[IP_Table[cnt]];  
    }  
    memcpy(data,temp,64);  

}  

/* DES Expand transform */
void DES_E_Transform(DataType data[48]){  
    int cnt;  
    DataType temp[48];  
    for(cnt = 0; cnt < 48; cnt++){  
        temp[cnt] = data[E_Table[cnt]];  
    }     
    memcpy(data,temp,48);  

}  


// attack 8 S-boxes
void Att8Sboxes(DataType data[48], int sum[]){

     sum[0] = (charToint(data[0])<<5) + (charToint(data[1])<<4) + (charToint(data[2])<<3) + (charToint(data[3])<<2) + (charToint(data[4])<<1) + (charToint(data[5]));
	
     sum[1] = (charToint(data[6])<<5) + (charToint(data[7])<<4) + (charToint(data[8])<<3) + (charToint(data[9])<<2) + (charToint(data[10])<<1) + (charToint(data[11]));
		
     sum[2] = (charToint(data[12])<<5) + (charToint(data[13])<<4) + (charToint(data[14])<<3) + (charToint(data[15])<<2) + (charToint(data[16])<<1) + (charToint(data[17]));

     sum[3] = (charToint(data[18])<<5) + (charToint(data[19])<<4) + (charToint(data[20])<<3) + (charToint(data[21])<<2) + (charToint(data[22])<<1) + (charToint(data[23]));

     sum[4] = (charToint(data[24])<<5) + (charToint(data[25])<<4) + (charToint(data[26])<<3) + (charToint(data[27])<<2) + (charToint(data[28])<<1) + (charToint(data[29]));

     sum[5] = (charToint(data[30])<<5) + (charToint(data[31])<<4) + (charToint(data[32])<<3) + (charToint(data[33])<<2) + (charToint(data[34])<<1) + (charToint(data[35]));

     sum[6] = (charToint(data[36])<<5) + (charToint(data[37])<<4) + (charToint(data[38])<<3) + (charToint(data[39])<<2) + (charToint(data[40])<<1) + (charToint(data[41]));

     sum[7] = (charToint(data[42])<<5) + (charToint(data[43])<<4) + (charToint(data[44])<<3) + (charToint(data[45])<<2) + (charToint(data[46])<<1) + (charToint(data[47]));

		}


// clear mpz_ts
void clearcollection(){
	int i;
	for(i=0; i<SAMPLE_NUM; i++){
		mpz_clear(collect_c[i]);
		mpz_clear(collect_m[i]);
		}

}

// transform mpz_t (in hex) to char[] (in binary)
void mpz64Tochar2(mpz_t source, char target[]){

	char *temp = {0};
	char temp2[100] = {0};
	temp=mpz_get_str(temp, 2, source);
	strcpy(temp2, temp);
	
	if(strlen(temp2)<64)
		sprintf(target, "%0*d%s", 64-strlen(temp2), 0, temp2);
	
	else
	strcpy(target, temp2);	

	}

// Get E(R0)
void getER0(char ER0[], mpz_t m){
	
//	gmp_printf("m1=%ZX\n",m);
	char plaintext[100] = {0};
	char ERtemp[100] = {0};
	// tansform mpz to 64bits str
	mpz64Tochar2(m, plaintext);
	
//	printf("m2=%s\n", plaintext);
	// IP transform
	DES_IP_Transform(plaintext);
//	printf("m3=%s\n", plaintext);

//	int i=0;	
	memcpy(ERtemp,plaintext+32,32);
//	printf("m4=%s\n", ERtemp);
        DES_E_Transform(ERtemp);  
//	printf("ER=%s\n", ERtemp);

	memcpy(ER0, ERtemp, sizeof(ERtemp));

	}

// Get E(R15)
void getER15(char ER15[], mpz_t c){
//	int i=0;
	char cyphertext[100] = {0};
	char ERtemp[100] = {0};

//	gmp_printf("c1=%ZX\n", c);
	// tansform mpz to 64bits str
	mpz64Tochar2(c, cyphertext);
	
//	printf("c2=%s\n", cyphertext);
	// IP transform
	DES_IP_Transform(cyphertext);

//	printf("c3=%s\n", cyphertext);	
	
	memcpy(ERtemp, cyphertext+32, 32);
//	printf("E1=%s\n", ERtemp);

	DES_E_Transform(ERtemp);
//	printf("E2=%s\n", ERtemp);
	memcpy(ER15, ERtemp, sizeof(ERtemp));
//	printf("E3=%s\n", ER15);
	}


/* XOR Operation */
void ERXOR(char ER0[], char ER15[], char Differ[]){
	int i;
	char temp[100] = {0};

	//printf("ER0=%s\n", ER0);
	//printf("ER5=%s\n", ER15);
	for(i=0; i<48; i++){
		temp[i] = intTochar(charToint(ER0[i])^charToint(ER15[i]));
	}
	memcpy(Differ, temp, sizeof(temp));

	
	}

/*
 * 1.Generate random plaintexts and send them to simulator D.
 * 2.Get encryption time and cyphertext for each plaintext and
 *   store them.
 *
 */
void CollectionPtxt(){
	gmp_randstate_t state;
	gmp_randinit_default(state);
	time_t seed;
	time(&seed);
	gmp_randseed_ui(state, seed);
					    
	int i, time;
	mpz_t mtemp, ctemp, testkey, m;
	mpz_init(mtemp);
	mpz_init(ctemp);	
	mpz_init(testkey);
	
	mpz_init(m);

	for(i=0; i<SAMPLE_NUM; i++){
		mpz_urandomb(mtemp, state, 64);
		
	//	gmp_printf("%ZX\n", m);

		interact(&time, mtemp, ctemp);
	//	interact2(&time, mtemp, testkey, ctemp);
			mpz_init(collect_m[i]);
			mpz_set(collect_m[i], mtemp);

			mpz_init(collect_c[i]);			
			mpz_set(collect_c[i], ctemp);

			collect_time[i] = time;

	}


	mpz_clear(mtemp);
	mpz_clear(ctemp);
	mpz_clear(testkey);


/*
	for(i=0; i<SAMPLE_NUM; i++){
		mpz_urandomb(mtemp, state, 64);

		interact(&time, mtemp, ctemp);
	//	interact2(&time, mtemp, testkey, ctemp);
			mpz_init(collect_m[i]);
			mpz_set(collect_m[i], mtemp);

			mpz_init(collect_c[i]);			
			mpz_set(collect_c[i], ctemp);

			collect_time[i] = time;

	}


	mpz_clear(mtemp);
	mpz_clear(ctemp);
	mpz_clear(testkey);

*/
	
}


// get E(R0) XOR E(R15)
void GetDiffer(){
	int i;
	char ER0[100]={0}, ER15[100]={0}, Differ[100]={0};
	for(i=0; i<SAMPLE_NUM; i++){
	//	gmp_printf("m=%ZX\n", collect_m[i]);
		getER0(ER0, collect_m[i]);
	//	printf("ER00=%s\n",ER0);

	//	gmp_printf("c=%ZX\n", collect_c[i]);
		getER15(ER15, collect_c[i]);
	//	printf("ER15=%s\n",ER15);

		ERXOR(ER0, ER15, Differ);
	//	printf("Diff=%s\n",Differ);
		// store Differ in Rdiffer
		memcpy(RDiffer[i], Differ, sizeof(Differ));
		}
	
}

// sort key difference by average encryption time
void SortKeyDiffer33(){
    int i=0, j;
    int svalues[8];
    
    // initial
    for(j=0; j<8; j++){
        for (i=0; i<64; i++) {
            mpf_init_set_ui(avrtime[j][i], 0);
            numcount[j][i] = 0;
        }
    }
    
    // attack 8 boxes
    for(i=0; i<SAMPLE_NUM; i++){
       	 Att8Sboxes(RDiffer[i], svalues);

	for(j=0; j<8; j++){
	//	if(collect_time[i]>=1595){
        	mpf_add_ui(avrtime[j][svalues[j]], avrtime[j][svalues[j]],collect_time[i]);
		numcount[j][svalues[j]] = numcount[j][svalues[j]]+1;
			}
	//	}
    }
	
	// compute average encryption time for 64 entries
	for(i=0; i<8; i++){
		for(j=0; j<64; j++){

			mpf_div_ui(avrtime[i][j], avrtime[i][j], numcount[i][j]);
			
		}
		
}
	// write to a file
//	freopen("output.txt", "w", stdout); 
//	for(i=0; i<8; i++){
//		  printf("i=%d\n",i);
//		for(j=0; j<64; j++){
//			gmp_printf("%4.3Ff\n", avrtime[i][j]);
//		}

//	}	

}

// sort key difference by minimum count
void SortKeyDiffer(){
    int i=0, j;

    int svalues[8];
    
    // initial
    for(j=0; j<8; j++){
        for (i=0; i<64; i++) {
            mpf_init_set_ui(avrtime[j][i], 0);
            numcount[j][i] = 0;
        }
    }
    
    // attack 8 boxes
    for(i=0; i<SAMPLE_NUM; i++){
       	 Att8Sboxes(RDiffer[i], svalues);

	for(j=0; j<8; j++){
		if(collect_time[i]>=1595) //1595
		numcount[j][svalues[j]] = numcount[j][svalues[j]]+1;

		}
    }
	
	// compute average encryption time for 64 entries
//	for(i=0; i<8; i++){
//		for(j=0; j<64; j++){

//			mpf_div_ui(avrtime[i][j], avrtime[i][j], numcount[i][j]);
			
//		}
		
//}
	// write to a file

//	freopen("output.txt", "w", stdout); 
//	for(i=0; i<8; i++){
//		  printf("i=%d\n",i);
//		for(j=0; j<64; j++){
//			printf("%d\n", numcount[i][j]);
//		}

//}	

}

// get original key differ in binary
void getokeydiffer(int result2[]){
   int i;
   char binarytemp[9];
   int posi[8] = {0, 6, 12, 18, 24, 30, 36, 42};
	// transform to binary key difference
	for (i=0; i<8; i++) {
       	 intTobinary(5, result2[i], binarytemp);
       	 memcpy(okeydiffer+posi[i], binarytemp, sizeof(binarytemp));
   //    	 printf("h2=%s\n",binarytemp);

    }

    printf("keydiffer=%s\n", okeydiffer);

}


// classify key difference by avrage time for each S-box 
void ClassifyKeyDiffer(){

   int result2[8];
   int ctemp;
   int i, j;

	for(i=0; i<8; i++){
		ctemp = numcount[i][0];
		result2[i] = 0;
		for(j=1; j<64; j++){
			if(ctemp > numcount[i][j]){
				ctemp = numcount[i][j];
				result2[i] = j;
				}
			}
		}

	// get key differ in binary
	getokeydiffer(result2);

}



/******************** DES encryption ************************/

// transform bits to byte
void T_1_8(Byte i1[],Byte i8[], int nlength){
	int i=0;
	//Byte tt; 
	for(i=0;i<nlength;i++){
		i8[i]=i1[8*i+0]*128+i1[8*i+1]*64+i1[8*i+2]*32+i1[8*i+3]*16+i1[8*i+4]*8+i1[8*i+5]*4+i1[8*i+6]*2+i1[8*i+7];
	}
}

// do permutaiton
void Exchange(uchar input[],uchar ip[],uchar len,uchar buf[]){
	uchar i, row, col, row1, col1, shift, shift1, tmp;

	for(i=0;i<len/8;i++)
		buf[i]=0;

	for(i=0;i<len;i++){
		shift1=0x80;
		row1=i/8;
		col1=i%8;
		shift1>>=col1;
		shift=0x80;
		tmp=ip[i]-1;
		row=tmp/8;
		col=tmp%8;
		shift>>=col;
		if(shift&input[row])
			buf[row1] |=shift1;

	}

}


void Shift(uchar input[7]){
	char i;
	uchar tmp=0;

	if(input[0]&0x80)
		tmp=0x01;

	input[0]<<=1;
	for(i=1;i<7;i++){
		if(input[i]&0x80)
		input[i-1]|=0x01;
		input[i]<<=1;
	}

	if(input[3]&0x10)
		input[6]|=0x01;

	if(tmp)
		input[3]|=0x10;

	else
		input[3]&=0xef;

}

// generate 16 rounds keys
void GenerateKey(){

	uchar output[7],i,j;
	Exchange(PreKey, Pc_1, 56, output);

	for(i=0;i<16;i++){
		for(j=0;j<ShTb[i];j++)
			Shift(output);
		Exchange(output, Pc_2, 48, Key[i]);
	}

}

// Shift left
void ShiftL(uchar in[], uchar len, uchar step){

	uchar i,j;
	for(j=0;j<step;j++){
		in[0]<<=1;
		for(i=1;i<len;i++){
			if(in[i]&0x80)
			in[i-1]|=0x01;
			in[i]<<=1;
		}
	}

}

// Xor computation
void Xor(uchar input[], uchar input1[], uchar len){

	uchar i;
	for(i=0; i<len; i++)
		input[i]^=input1[i];

}

// Round function
void FunRK(uchar rx[4], uchar *key, uchar output[4],int nr){

	uchar rx1[6], i, row, col, ch, out[4];
	for(i=0; i<4; i++)
		out[i]=0;

	Exchange(rx, Ex, 48, rx1);

	Xor(rx1, key, 6);

	for(i=0;i<8;i++)
	for(i=0;i<8;i++){
		row=0;
		col=0;

		if(rx1[0]&0x04)
			row|=0x01;

		if(rx1[0]&0x80)
			row|=0x02;

		col=(rx1[0]&0x78)>>3;
		ch=Sbox[i][row*16+col]; 

		if(!(i%2))
			ch<<=4;

		out[i/2]|=ch;
		ShiftL(rx1, 6, 6);

	} 

	Exchange(out, Px, 32, output);

}

// DES encryption
void Des(uchar input[8],uchar result[8]){
	uchar output[8], rxtmp[4], i, j;
	uchar rx[4], lx[4];
	Exchange(input, Ip, 64, output);

	for(i=0; i<4; i++){
		lx[i]=output[i];
		rx[i]=output[4+i];
	}
	
	for(i=0; i<16; i++){ 
		FunRK(rx, Key[i], rxtmp,i);
		Xor(rxtmp, lx, 4);
		for(j=0; j<4; j++){
			lx[j]=rx[j];
			rx[j]=rxtmp[j]; 
		}  

	}

	for(i=0; i<4; i++){
		output[4+i]=lx[i];
		output[i]=rx[i];
	}

	Exchange(output, Ipr, 64, result);

} 

 
void Myprintf(uchar uin[],int nlen){
	printf("\n");
	for(int i=0;i<nlen;i++)
	printf("%2x ",uin[i]);
}




/******************** brute force ************************/

int DES_Enc_Cmp(char guesskey[]){
	unsigned char tkey2[100];
	int i;
	//printf("key1=%s\n", guesskey);

    for (i=0; i<64; i++) {
        tkey2[i] = (unsigned char)(guesskey[i]-'0');
    }
	
	//printf("key2=%s\n", guesskey);

	ncounter++;
	if(ncounter%100000==0)
	   printf("%d\n ",ncounter);

	T_1_8(tkey2,PreKey,8);

	// Myprintf(PreKey, 8);
	GenerateKey();  
	Des(bp,bc_c);

           if(strcmp((char *)bc_v, (char *)bc_c)==0){
		printf("yes!!\n");
		Myprintf(PreKey,8);
 		printf("true\n");
 		return 1;
}

	return 0;
}

// compute 64 bits key from guessed 24 bits key
void getfullkey(char gkey[], char keydiffer[]){
    
    gkey[7] = '1';
    gkey[15] = '1';
    gkey[23] = '1';
    gkey[31] = '1';
    gkey[39] = '1';
    gkey[47] = '1';
    gkey[55] = '1';
    gkey[63] = '1';
    
    gkey[58] = intTochar(charToint(gkey[50]) ^ charToint(keydiffer[1]));
    gkey[1] = intTochar(charToint(gkey[58]) ^ charToint(keydiffer[18]));
    gkey[9] = intTochar(charToint(gkey[1]) ^ charToint(keydiffer[8]));
    gkey[17] = intTochar(charToint(gkey[9]) ^ charToint(keydiffer[0]));
    gkey[33] = intTochar(charToint(gkey[25]) ^ charToint(keydiffer[14]));
    gkey[41] = intTochar(charToint(gkey[33]) ^ charToint(keydiffer[2]));
    gkey[49] = intTochar(charToint(gkey[41]) ^ charToint(keydiffer[11]));

    gkey[10] = intTochar(charToint(gkey[2]) ^ charToint(keydiffer[12]));
    
    gkey[42] = intTochar(charToint(gkey[34]) ^ charToint(keydiffer[13]));
    
    gkey[8] = intTochar(charToint(gkey[0]) ^ charToint(keydiffer[19]));
    gkey[40] = intTochar(charToint(gkey[32]) ^ charToint(keydiffer[6]));
    gkey[48] = intTochar(charToint(gkey[40]) ^ charToint(keydiffer[23]));
    gkey[56] = intTochar(charToint(gkey[48]) ^ charToint(keydiffer[4]));
    gkey[35] = intTochar(charToint(gkey[56]) ^ charToint(keydiffer[7]));
    gkey[43] = intTochar(charToint(gkey[35]) ^ charToint(keydiffer[20]));
    gkey[51] = intTochar(charToint(gkey[43]) ^ charToint(keydiffer[16]));
    
    gkey[30] = intTochar(charToint(gkey[22]) ^ charToint(keydiffer[34]));
    gkey[38] = intTochar(charToint(gkey[30]) ^ charToint(keydiffer[47]));
    gkey[46] = intTochar(charToint(gkey[38]) ^ charToint(keydiffer[26]));
    gkey[54] = intTochar(charToint(gkey[46]) ^ charToint(keydiffer[30]));
    
    gkey[27] = intTochar(charToint(gkey[19]) ^ charToint(keydiffer[41]));
    gkey[4] = intTochar(charToint(gkey[27]) ^ charToint(keydiffer[25]));
    gkey[12] = intTochar(charToint(gkey[4]) ^ charToint(keydiffer[32]));
    gkey[20] = intTochar(charToint(gkey[12]) ^ charToint(keydiffer[44]));
    gkey[28] = intTochar(charToint(gkey[20]) ^ charToint(keydiffer[37]));
    gkey[44] = intTochar(charToint(gkey[36]) ^ charToint(keydiffer[28]));
    gkey[52] = intTochar(charToint(gkey[44]) ^ charToint(keydiffer[42]));
    gkey[5] = intTochar(charToint(gkey[60]) ^ charToint(keydiffer[36]));
    
    gkey[21] = intTochar(charToint(gkey[13]) ^ charToint(keydiffer[43]));
    gkey[29] = intTochar(charToint(gkey[21]) ^ charToint(keydiffer[24]));
    gkey[37] = intTochar(charToint(gkey[29]) ^ charToint(keydiffer[31]));
    gkey[45] = intTochar(charToint(gkey[37]) ^ charToint(keydiffer[38]));
    
}

// guess 24 bits to bruteforce the target  
int bruteforce(){
    
    char guesskey[100]={0};
    char temp[100] = {0};
    int index[24] = {50,25,59,2,18,26,34,57,0,16,24,32,53,61,6,14,22,62,3,11,19,36,60,13};
    int var[24];
    int i;
    
    for(i=0; i<64; i++){
        temp[i] = '0';
        guesskey[i] = '0';
    }
    
    for(var[23]=0; var[23]<2; var[23]++){
        guesskey[index[23]] = intTochar(var[23]);   
    for(var[22]=0; var[22]<2; var[22]++){
        guesskey[index[22]] = intTochar(var[22]);
    for(var[21]=0; var[21]<2; var[21]++){
        guesskey[index[21]] = intTochar(var[21]);
    for(var[20]=0; var[20]<2; var[20]++){
        guesskey[index[20]] = intTochar(var[20]);
    for(var[19]=0; var[19]<2; var[19]++){
        guesskey[index[19]] = intTochar(var[19]);
    for(var[18]=0; var[18]<2; var[18]++){
        guesskey[index[18]] = intTochar(var[18]);
    for(var[17]=0; var[17]<2; var[17]++){
         guesskey[index[17]] = intTochar(var[17]);
    for(var[16]=0; var[16]<2; var[16]++){
         guesskey[index[16]] = intTochar(var[16]);
    for(var[15]=0; var[15]<2; var[15]++){
         guesskey[index[15]] = intTochar(var[15]);
    for(var[14]=0; var[14]<2; var[14]++){
         guesskey[index[14]] = intTochar(var[14]);
     for(var[13]=0; var[13]<2; var[13]++){
         guesskey[index[13]] = intTochar(var[13]);
     for(var[12]=0; var[12]<2; var[12]++){
         guesskey[index[12]] = intTochar(var[12]);
     for(var[11]=0; var[11]<2; var[11]++){
         guesskey[index[11]] = intTochar(var[11]);
     for(var[10]=0; var[10]<2; var[10]++){
         guesskey[index[10]] = intTochar(var[10]);
     for(var[9]=0; var[9]<2; var[9]++){
         guesskey[index[9]] = intTochar(var[9]);
     for(var[8]=0; var[8]<2; var[8]++){
         guesskey[index[8]] = intTochar(var[8]);
     for(var[7]=0; var[7]<2; var[7]++){
         guesskey[index[7]] = intTochar(var[7]);
     for(var[6]=0; var[6]<2; var[6]++){
         guesskey[index[6]] = intTochar(var[6]);
     for(var[5]=0; var[5]<2; var[5]++){
         guesskey[index[5]] = intTochar(var[5]);
     for(var[4]=0; var[4]<2; var[4]++){
         guesskey[index[4]] = intTochar(var[4]);
     for(var[3]=0; var[3]<2; var[3]++){
         guesskey[index[3]] = intTochar(var[3]);
     for(var[2]=0; var[2]<2; var[2]++){
         guesskey[index[2]] = intTochar(var[2]);
     for(var[1]=0; var[1]<2; var[1]++){
         guesskey[index[1]] = intTochar(var[1]);
     for(var[0]=0; var[0]<2; var[0]++){
         guesskey[index[0]] = intTochar(var[0]);

  //       printf("guesskey=%s\n",guesskey);
         memcpy(temp, guesskey, sizeof(guesskey));
        // get 64bits key from guessed 24 bits key
	 
	getfullkey(temp,okeydiffer);
	//         printf("key=%s\n",temp);

        // des encryption 
     if(DES_Enc_Cmp(temp)==1) return 1; 
	
	 }}}}}}}}}}}}}}}}}}}}}}}}
	return 0;
	}


void attack()
{	
	int success = 0;
	//printf("%s\n", mykey);
   while( success == 0){
	printf("collecting plaintext/cyphertext...\n");
	CollectionPtxt();
	printf("done\n");
	
	printf("computing key difference...\n");
	GetDiffer();

	printf("computing...\n");
	SortKeyDiffer();
//	SortKeyDiffer33();
	printf("done\n");

	printf("classifying...\n");
	ClassifyKeyDiffer();
	printf("done!\n");

	printf("bruteforce...\n");
	success = bruteforce();
	printf("done!\n");
	ncounter = 0;

	clearcollection();
}



//	fclose(stdout);


/*
	int time2;
 	mpz_t m, c, k, test;
	mpz_init(test);

	mpz_init(m);
	mpz_init(k);
	mpz_init(c);
	mpz_set_str(m, "1B657B0880CAFFF1", 16);
	mpz_set_str(k, "9F3A6C8ABE314D52", 16);



	char cypher[100];
	char key[100], keytemp[100]={0};
	char subKeys[16][48]; 

	mpz64Tochar2(k, key);
	printf("key1=%s\n", key);

	// encrypt directly
	DES_MakeSubKeys(key,subKeys);

	DES_Encrypt(m ,subKeys, cypher);


	printf("c1=%s\n", cypher);
*/

}

 
int main( int argc, char* argv[] ) 
{

  // Ensure we clean-up correctly if Control-C (or similar) is signalled.
  signal( SIGINT, &cleanup );

  // Create pipes to/from attack target; if it fails the reason is stored
  // in errno, but we'll just abort.
  if( pipe( target_raw ) == -1 ) {
    abort();
  }
  if( pipe( attack_raw ) == -1 ) {
    abort();
  }

  switch( pid = fork() ) { 
    case -1 : {
      // the fork failed; reason is stored in errno, but we'll just abort.
      abort();
    }
 
    case +0 : {
      // (Re)connect standard input and output to pipes.
      close( STDOUT_FILENO );
      if( dup2( attack_raw[ 1 ], STDOUT_FILENO ) == -1 ) {
        abort();
      }
      close(  STDIN_FILENO );
      if( dup2( target_raw[ 0 ],  STDIN_FILENO ) == -1 ) {
        abort();
      }

      // Produce a sub-process representing the attack target.
      execl( argv[ 1 ], NULL );

      // Break and clean-up once finished.
      break;
    }

    default : {
      // Construct handles to attack target standard input and output.
      if( ( target_out = fdopen( attack_raw[ 0 ], "r" ) ) == NULL ) {
        abort();
      }
      if( ( target_in  = fdopen( target_raw[ 1 ], "w" ) ) == NULL ) {
        abort();
      }

      // Execute a function representing the attacker.
      attack();

      // Break and clean-up once finished.
      break;
    }
  }
	//clean up
	cleanup(SIGINT);
	return 0;
}
