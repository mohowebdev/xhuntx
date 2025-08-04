/*
Develop by Alberto
email: albertobsd@gmail.com
Modified for Cyclical Segmented Timed Scan with Telegram Notifications
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "bloom/bloom.h"
#include "sha3/sha3.h"
#include "util.h"

#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "secp256k1/Random.h"

#include "hash/sha256.h"
#include "hash/ripemd160.h"

#if defined(_WIN64) && !defined(__CYGWIN__)
#include "getopt.h"
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>
#endif

#ifdef __unix__
#ifdef __CYGWIN__
#else
#include <linux/random.h>
#endif
#endif

#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define CRYPTO_ETH 2

#define SEARCH_UNCOMPRESS 0
#define SEARCH_COMPRESS 1
#define SEARCH_BOTH 2

// --- TELEGRAM NOTIFICATION SETTINGS ---
// IMPORTANT: Replace these placeholders with your actual Bot Token and Chat ID.
// To disable notifications, leave one of these as an empty string "".
const char* TELEGRAM_BOT_TOKEN = "8030098883:AAGdc99JwNuP_CG8hPQ1Ze20Ua4FO8nqAr0";
const char* TELEGRAM_CHAT_ID   = "945546105";
// --- END OF SETTINGS ---

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
};


#if defined(_WIN64) && !defined(__CYGWIN__)
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
PACK(struct publickey
{
	uint8_t parity;
	union {
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
});
#else
struct __attribute__((__packed__)) publickey {
  uint8_t parity;
	union	{
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
};
#endif

const char *version = "1";

#define CPU_GRP_SIZE 1024

std::vector<Point> Gn;
Point _2Gn;

void menu();
void init_generator();

int searchbinary(struct address_value *buffer, char *data, int64_t array_length);
void sleep_ms(int milliseconds);

void _sort(struct address_value *arr,int64_t N);
void _insertionsort(struct address_value *arr, int64_t n);
void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n);
void _swap(struct address_value *a,struct address_value *b);
int64_t _partition(struct address_value *arr, int64_t n);
void _myheapsort(struct address_value	*arr, int64_t n);
void _heapify(struct address_value *arr, int64_t n, int64_t i);

void writekey(bool compressed,Int *key);
void writekeyeth(Int *key);

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);

bool readFileAddress(char *fileName);
bool forceReadFileAddress(char *fileName);
bool forceReadFileAddressEth(char *fileName);

bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom);
void writeFileIfNeeded(const char *fileName);

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process(LPVOID vargp);
#else
void *thread_process(void *vargp);
#endif

void pubkeytopubaddress_dst(char *pkey,int length,char *dst);
void rmd160toaddress_dst(char *rmd,char *dst);
	
void KECCAK_256(uint8_t *source, size_t size,uint8_t *dst);
void generate_binaddress_eth(Point &publickey,unsigned char *dst_address);

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *cryptos[2] = {"btc","eth"};
const char *publicsearch[3] = {"uncompress","compress","both"};
const char *default_fileName = "addresses.txt";

#if defined(_WIN64) && !defined(__CYGWIN__)
HANDLE* tid = NULL;
HANDLE write_keys;
HANDLE write_random;
#else
pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
#endif

uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;

Int OUTPUTSECONDS;

int FLAGSKIPCHECKSUM = 0;
int FLAGENDOMORPHISM = 0;
int FLAGBLOOMMULTIPLIER = 1;
int FLAGQUIET = 0;
int FLAGMATRIX = 0;
int NTHREADS = 1;

int FLAGSAVEREADFILE = 0;
int FLAGREADEDFILE1 = 0;

int FLAGSTRIDE = 0;
int FLAGSEARCH = 2;
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAGCRYPTO = 0;

// New flags for segmented scan
int FLAGSEGMENTS = 10;
uint64_t TIMEDURATION_SECONDS = 600; // 10 minutes default
volatile int CURRENT_SEGMENT = 0;
std::vector<Int> SEGMENT_RANGES_START;
std::vector<Int> SEGMENT_RANGES_END;

int bitrange;
char *range_start;
char *range_end;
char *str_stride;
Int stride;

struct address_value *addressTable;
struct bloom bloom;
int MAXLENGTHADDRESS = -1;

const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];

Int ONE;
Int ZERO;
Int MPZAUX;

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;

Int lambda,lambda2;

Secp256K1 *secp;

void sendToTelegram(const char *message) {
    if (strlen(TELEGRAM_BOT_TOKEN) < 10 || strlen(TELEGRAM_CHAT_ID) < 1) {
        // If credentials are not set, do nothing.
        return;
    }

    // A larger buffer to be safe.
    char command[2048]; 

    // Construct the curl command for silent, background execution.
    // Redirects stdout and stderr to /dev/null to ensure no terminal output.
    // The '&' at the end runs the command in the background.
    snprintf(command, sizeof(command),
             "curl -s -X POST \"https://api.telegram.org/bot%s/sendMessage\" --data-urlencode \"chat_id=%s\" --data-urlencode \"text=%s\" > /dev/null 2>&1 &",
             TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, message);

    // Execute the command
    system(command);
}


// Helper function to parse time duration with suffix
uint64_t parse_time(char *str) {
    char *endptr;
    uint64_t value = strtoull(str, &endptr, 10);
    switch (*endptr) {
        case 's':
        case 'S':
            return value;
        case 'm':
        case 'M':
            return value * 60;
        case 'h':
        case 'H':
            return value * 3600;
        default: // Default to seconds if no suffix
            return value;
    }
}

int main(int argc, char **argv)	{
	char buffer[2048];
	struct tothread *tt;	//tothread
	Tokenizer t;	//tokenizer
	char *fileName = NULL;
	char *hextemp = NULL;
	char *str_seconds = NULL;
	char *str_total = NULL;
	char *str_pretotal = NULL;
	char *str_divpretotal = NULL;

	int c, index_value;
	Int total, pretotal, seconds, div_pretotal;
	
#if defined(_WIN64) && !defined(__CYGWIN__)
	DWORD s;
	write_keys = CreateMutex(NULL, FALSE, NULL);
	write_random = CreateMutex(NULL, FALSE, NULL);
#else
	pthread_mutex_init(&write_keys,NULL);
	pthread_mutex_init(&write_random,NULL);
	int s;
#endif

	srand(time(NULL));

	secp = new Secp256K1();
	secp->Init();
	OUTPUTSECONDS.SetInt32(30);
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	
#if defined(_WIN64) && !defined(__CYGWIN__)
	rseed(clock() + time(NULL) + rand());
#else
	unsigned long rseedvalue;
	int bytes_read = getrandom(&rseedvalue, sizeof(unsigned long), GRND_NONBLOCK);
	if(bytes_read > 0)	{
		rseed(rseedvalue);
	}
	else	{
		fprintf(stderr,"[E] Error getrandom() ?\n");
		exit(EXIT_FAILURE);
		rseed(clock() + time(NULL) + rand()*rand());
	}
#endif
	
	printf("[+] Version %s, developed by AR\n",version);
	printf("[+] Mode: Address Hunting with Cyclical Segmented Timed Scan\n");
    
    // Manual pre-parsing for -seg and -time
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-seg") == 0 && i + 1 < argc) {
            FLAGSEGMENTS = strtol(argv[i + 1], NULL, 10);
            if (FLAGSEGMENTS <= 0) FLAGSEGMENTS = 1;
        }
        if (strcmp(argv[i], "-time") == 0 && i + 1 < argc) {
            TIMEDURATION_SECONDS = parse_time(argv[i + 1]);
            if (TIMEDURATION_SECONDS == 0) TIMEDURATION_SECONDS = 600;
        }
    }
    
	while ((c = getopt(argc, argv, "heMSc:f:I:l:qr:s:t:z:b:6")) != -1) {
		switch(c) {
			case 'h':
				menu();
			break;
			case '6':
				FLAGSKIPCHECKSUM = 1;
				fprintf(stderr,"[W] Skipping checksums on files\n");
			break;
			case 'b':
				bitrange = strtol(optarg,NULL,10);
				if(bitrange > 0 && bitrange <=256 )	{
					MPZAUX.Set(&ONE);
					MPZAUX.ShiftL(bitrange-1);
					bit_range_str_min = MPZAUX.GetBase16();
					checkpointer((void *)bit_range_str_min,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
					MPZAUX.Set(&ONE);
					MPZAUX.ShiftL(bitrange);
					if(MPZAUX.IsGreater(&secp->order))	{
						MPZAUX.Set(&secp->order);
					}
					bit_range_str_max = MPZAUX.GetBase16();
					checkpointer((void *)bit_range_str_max,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
					FLAGBITRANGE = 1;
				}
				else	{
					fprintf(stderr,"[E] invalid bits param: %s.\n",optarg);
				}
			break;
			case 'c':
				index_value = indexOf(optarg,cryptos,2);
				switch(index_value) {
					case 0: //btc
						FLAGCRYPTO = CRYPTO_BTC;
					break;
					case 1: //eth
						FLAGCRYPTO = CRYPTO_ETH;
						printf("[+] Setting search for ETH adddress.\n");
					break;
					default:
						FLAGCRYPTO = CRYPTO_NONE;
						fprintf(stderr,"[E] Unknow crypto value %s\n",optarg);
						exit(EXIT_FAILURE);
					break;
				}
			break;
			case 'e':
				FLAGENDOMORPHISM = 1;
				printf("[+] Endomorphism enabled\n");
				lambda.SetBase16("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");
                lambda2.SetBase16("ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283ce");
			break;
			case 'f':
				FLAGFILE = 1;
				fileName = optarg;
			break;
			case 'I':
				FLAGSTRIDE = 1;
				str_stride = optarg;
			break;
			case 'l':
				switch(indexOf(optarg,publicsearch,3)) {
					case SEARCH_UNCOMPRESS:
						FLAGSEARCH = SEARCH_UNCOMPRESS;
						printf("[+] Search uncompress only\n");
					break;
					case SEARCH_COMPRESS:
						FLAGSEARCH = SEARCH_COMPRESS;
						printf("[+] Search compress only\n");
					break;
					case SEARCH_BOTH:
						FLAGSEARCH = SEARCH_BOTH;
						printf("[+] Search both compress and uncompress\n");
					break;
				}
			break;
			case 'M':
				FLAGMATRIX = 1;
				printf("[+] Matrix screen\n");
			break;
			case 'q':
				FLAGQUIET	= 1;
				printf("[+] Quiet thread output\n");
			break;
			case 'r':
				if(optarg != NULL)	{
					stringtokenizer(optarg,&t);
					switch(t.n)	{
						case 1:
							range_start = nextToken(&t);
							if(isValidHex(range_start)) {
								FLAGRANGE = 1;
								range_end = secp->order.GetBase16();
							}
							else	{
								fprintf(stderr,"[E] Invalid hexstring : %s.\n",range_start);
							}
						break;
						case 2:
							range_start = nextToken(&t);
							range_end	 = nextToken(&t);
							if(isValidHex(range_start) && isValidHex(range_end)) {
									FLAGRANGE = 1;
							}
							else	{
								if(isValidHex(range_start)) {
									fprintf(stderr,"[E] Invalid hexstring : %s\n",range_start);
								}
								else	{
									fprintf(stderr,"[E] Invalid hexstring : %s\n",range_end);
								}
							}
						break;
						default:
							printf("[E] Unknow number of Range Params: %i\n",t.n);
						break;
					}
				}
			break;
			case 's':
				OUTPUTSECONDS.SetBase10(optarg);
				if(OUTPUTSECONDS.IsLower(&ZERO))	{
					OUTPUTSECONDS.SetInt32(30);
				}
				if(OUTPUTSECONDS.IsZero())	{
					printf("[+] Turn off stats output\n");
				}
				else	{
					hextemp = OUTPUTSECONDS.GetBase10();
					printf("[+] Stats output every %s seconds\n",hextemp);
					free(hextemp);
				}
			break;
			case 'S':
				FLAGSAVEREADFILE = 1;
			break;
			case 't':
				NTHREADS = strtol(optarg,NULL,10);
				if(NTHREADS <= 0)	{
					NTHREADS = 1;
				}
				printf((NTHREADS > 1) ? "[+] Threads : %u\n": "[+] Thread : %u\n",NTHREADS);
			break;
			case 'z':
				FLAGBLOOMMULTIPLIER= strtol(optarg,NULL,10);
				if(FLAGBLOOMMULTIPLIER <= 0)	{
					FLAGBLOOMMULTIPLIER = 1;
				}
				printf("[+] Bloom Size Multiplier %i\n",FLAGBLOOMMULTIPLIER);
			break;
			default:
				break;
		}
	}
	
	if(FLAGSTRIDE)	{
		if(str_stride[0] == '0' && str_stride[1] == 'x')	{
			stride.SetBase16(str_stride+2);
		}
		else{
			stride.SetBase10(str_stride);
		}
		printf("[+] Stride : %s\n",stride.GetBase10());
	}
	else	{
		FLAGSTRIDE = 1;
		stride.Set(&ONE);
	}

	init_generator();
	
	if(FLAGFILE == 0) {
		fileName =(char*) default_fileName;
	}
	
	if(FLAGCRYPTO == CRYPTO_NONE) {
		FLAGCRYPTO = CRYPTO_BTC;
		printf("[+] Setting search for btc adddress\n");
	}

	if(FLAGRANGE) {
		n_range_start.SetBase16(range_start);
		if(n_range_start.IsZero())	{
			n_range_start.AddOne();
		}
		n_range_end.SetBase16(range_end);
		if(n_range_start.IsEqual(&n_range_end) == false ) {
			if(  n_range_start.IsLower(&secp->order) &&  n_range_end.IsLowerOrEqual(&secp->order) )	{
				if( n_range_start.IsGreater(&n_range_end)) {
					fprintf(stderr,"[W] Opps, start range can't be great than end range. Swapping them\n");
					n_range_aux.Set(&n_range_start);
					n_range_start.Set(&n_range_end);
					n_range_end.Set(&n_range_aux);
				}
				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
			}
			else	{
				fprintf(stderr,"[E] Start and End range can't be great than N\nExiting.\n");
				exit(EXIT_FAILURE);
			}
		}
		else	{
			fprintf(stderr,"[E] Start and End range can't be the same\nExiting.\n");
			exit(EXIT_FAILURE);
		}
	} else if (FLAGBITRANGE) {
        n_range_start.SetBase16(bit_range_str_min);
        n_range_end.SetBase16(bit_range_str_max);
        n_range_diff.Set(&n_range_end);
        n_range_diff.Sub(&n_range_start);
    } else {
        fprintf(stderr, "[E] A search range must be provided with -r or -b for this mode.\n");
        menu();
    }

    // Setup for Cyclical Segmented Timed Scan
    printf("[+] Total search range will be divided into %d segments.\n", FLAGSEGMENTS);
    printf("[+] Each segment will be scanned for %" PRIu64 " seconds.\n", TIMEDURATION_SECONDS);
    Int segment_size;
    segment_size.Set(&n_range_diff);

    Int divisor;
    divisor.SetInt32(FLAGSEGMENTS);
    segment_size.Div(&divisor);

    printf("[+] Calculating segment boundaries...\n");
    for(int i = 0; i < FLAGSEGMENTS; i++) {
        Int seg_start, seg_end;
        seg_start.Set(&n_range_start);
        n_range_aux.Set(&segment_size);
        n_range_aux.Mult(i);
        seg_start.Add(&n_range_aux);
        
        seg_end.Set(&seg_start);
        seg_end.Add(&segment_size);
        if(i == FLAGSEGMENTS - 1) { // Ensure last segment reaches the end of the total range
            seg_end.Set(&n_range_end);
        }
        
        SEGMENT_RANGES_START.push_back(seg_start);
        SEGMENT_RANGES_END.push_back(seg_end);
        
        char *s_start_hex = seg_start.GetBase16();
        char *s_end_hex = seg_end.GetBase16();
        printf("    [+] Segment %d: 0x%s -> 0x%s\n", i + 1, s_start_hex, s_end_hex);
        free(s_start_hex);
        free(s_end_hex);
    }
	
    if(!readFileAddress(fileName)) {
        fprintf(stderr,"[E] Unexpected error reading address file.\n");
        exit(EXIT_FAILURE);
    }

	if(!FLAGREADEDFILE1)	{
		printf("[+] Sorting data ...");
		_sort(addressTable,N);
		printf(" done! %" PRIu64 " values were loaded and sorted\n",N);
		writeFileIfNeeded(fileName);
	}
	
	steps = (uint64_t *) calloc(NTHREADS,sizeof(uint64_t));
	checkpointer((void *)steps,__FILE__,"calloc","steps" ,__LINE__ - 1);
	ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
	checkpointer((void *)ends,__FILE__,"calloc","ends" ,__LINE__ -1 );

#if defined(_WIN64) && !defined(__CYGWIN__)
	tid = (HANDLE*)calloc(NTHREADS, sizeof(HANDLE));
#else
	tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
#endif
	checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ - 1);
	
    for(int j= 0;j < NTHREADS; j++)	{
		tt = (tothread*) malloc(sizeof(struct tothread));
		checkpointer((void *)tt,__FILE__,"malloc","tt" ,__LINE__ - 1);
		tt->nt = j;
		steps[j] = 0;
		s = 0;
#if defined(_WIN64) && !defined(__CYGWIN__)
		tid[j] = CreateThread(NULL, 0, thread_process, (void*)tt, 0, &s);
#else
		s = pthread_create(&tid[j],NULL,thread_process,(void *)tt);
#endif
		if(s != 0)	{
			fprintf(stderr,"[E] pthread_create thread_process failed\n");
			exit(EXIT_FAILURE);
		}
	}
	
	for(int j =0; j < 7; j++)	{
		int_limits[j].SetBase10((char*)str_limits[j]);
	}
	
	total.SetInt32(0);
	pretotal.SetInt32(0);
	seconds.SetInt32(0);
    uint64_t total_keys_in_session = 0;
    int cycle_num = 1;

	// Main control loop for Cyclical Segmented Timed Scan
    while(1) {
        printf("\n[+] Starting Scan Cycle #%d\n", cycle_num);
        for(int seg_idx = 0; seg_idx < FLAGSEGMENTS; seg_idx++) {
            CURRENT_SEGMENT = seg_idx;
            char *s_start_hex = SEGMENT_RANGES_START[seg_idx].GetBase16();
            char *s_end_hex = SEGMENT_RANGES_END[seg_idx].GetBase16();
            printf("[+] Now scanning Segment %d/%d for %" PRIu64 " seconds. Range: 0x%s -> 0x%s\n", 
                    seg_idx + 1, FLAGSEGMENTS, TIMEDURATION_SECONDS, s_start_hex, s_end_hex);
            free(s_start_hex);
            free(s_end_hex);

            uint64_t segment_timer = 0;
            uint64_t keys_at_seg_start = total_keys_in_session;

            while(segment_timer < TIMEDURATION_SECONDS) {
                sleep_ms(1000);
                segment_timer++;
                seconds.AddOne();

                uint64_t current_step_count = 0;
                for(int j = 0; j < NTHREADS; j++) {
                    current_step_count += steps[j];
                }
                
                uint64_t multiplier = 1;
                if (FLAGENDOMORPHISM) {
                    multiplier = 3;
                } else if (FLAGSEARCH == SEARCH_BOTH) {
                    multiplier = 2;
                }
                
                total_keys_in_session = current_step_count * CPU_GRP_SIZE * multiplier;
                total.SetInt64(total_keys_in_session);
                
                if(OUTPUTSECONDS.IsGreater(&ZERO) && (segment_timer % OUTPUTSECONDS.GetInt64() == 0) ) {
                    pretotal.Set(&total);
                    pretotal.Div(&seconds);
                    str_seconds = seconds.GetBase10();
                    str_pretotal = pretotal.GetBase10();
                    str_total = total.GetBase10();

                    if(pretotal.IsLower(&int_limits[0]))	{
						sprintf(buffer,"\r[+] Total %s keys in %s seconds: %s keys/s",str_total,str_seconds,str_pretotal);
					}
					else	{
						int i = 0;
						bool salir = false;
						while( i < 6 && !salir)	{
							if(pretotal.IsLower(&int_limits[i+1]))	{
								salir = true;
							}
							else	{
								i++;
							}
						}

						div_pretotal.Set(&pretotal);
						div_pretotal.Div(&int_limits[salir ? i : i-1]);
						str_divpretotal = div_pretotal.GetBase10();
						
                        sprintf(buffer,"\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
						
                        free(str_divpretotal);
					}
                    printf("%s ", buffer); // Extra space to clear line
                    fflush(stdout);
                    free(str_seconds);
                    free(str_pretotal);
                    free(str_total);
                }
            }
            printf("\n[+] Finished scanning Segment %d. Keys checked in this segment: %" PRIu64 "\n", 
                   seg_idx + 1, total_keys_in_session - keys_at_seg_start);
        }
        cycle_num++;
    }

	printf("\nEnd\n");
#ifdef _WIN64
	CloseHandle(write_keys);
	CloseHandle(write_random);
#endif
    return 0;
}

void pubkeytopubaddress_dst(char *pkey,int length,char *dst)	{
	char digest[60];
	size_t pubaddress_size = 40;
	sha256((uint8_t*)pkey, length,(uint8_t*) digest);
	RMD160Data((const unsigned char*)digest,32, digest+1);
	digest[0] = 0;
	sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
	sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);
	if(!b58enc(dst,&pubaddress_size,digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}

void rmd160toaddress_dst(char *rmd,char *dst){
	char digest[60];
	size_t pubaddress_size = 40;
	digest[0] = 0x00; // Bitcoin
	memcpy(digest+1,rmd,20);
	sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
	sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);
	if(!b58enc(dst,&pubaddress_size,digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}

int searchbinary(struct address_value *buffer, char *data, int64_t array_length) {
    int64_t min = 0, max = array_length - 1;
    while (min <= max) {
        int64_t mid = min + (max - min) / 2;
        int cmp = memcmp(data, buffer[mid].value, 20);
        if (cmp == 0) {
            return mid; // Found, return index
        } else if (cmp < 0) {
            max = mid - 1;
        } else {
            min = mid + 1;
        }
    }
    return -1; // Not found
}


#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process(LPVOID vargp) {
#else
void *thread_process(void *vargp)	{
#endif
	struct tothread *tt;
	Point pts[CPU_GRP_SIZE];
	Point endomorphism_beta[CPU_GRP_SIZE];
	Point endomorphism_beta2[CPU_GRP_SIZE];
	Point endomorphism_negeted_point[4];
	
	Int dx[CPU_GRP_SIZE / 2 + 1];
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Point pp;
	Point pn;
	int i,l,pp_offset,pn_offset,hLength = (CPU_GRP_SIZE / 2 - 1);
	uint64_t j;
	Point publickey;
	int thread_number,k;
	
	char publickeyhashrmd160[20];
	char publickeyhashrmd160_uncompress[4][20];
	
	char publickeyhashrmd160_endomorphism[12][4][20];
	
	bool calculate_y = FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH || FLAGCRYPTO  == CRYPTO_ETH;
	Int key_mpz,keyfound;
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	grp->Set(dx);
			
	while(1) { // Infinite loop for the worker thread
        int active_segment = CURRENT_SEGMENT;
        Int seg_start = SEGMENT_RANGES_START[active_segment];
        Int seg_end = SEGMENT_RANGES_END[active_segment];
        
        key_mpz.Rand(&seg_start, &seg_end);

        startP = secp->ComputePublicKey(&key_mpz);

        for(i = 0; i < hLength; i++) {
            dx[i].ModSub(&Gn[i].x,&startP.x);
        }
    
        dx[i].ModSub(&Gn[i].x,&startP.x);
        dx[i + 1].ModSub(&_2Gn.x,&startP.x);
        grp->ModInv();

        pts[CPU_GRP_SIZE / 2] = startP;

        for(i = 0; i<hLength; i++) {
            pp = startP;
            pn = startP;

            dy.ModSub(&Gn[i].y,&pp.y);
            _s.ModMulK1(&dy,&dx[i]);
            _p.ModSquareK1(&_s);
            pp.x.ModNeg();
            pp.x.ModAdd(&_p);
            pp.x.ModSub(&Gn[i].x);
            if(calculate_y)	{
                pp.y.ModSub(&Gn[i].x,&pp.x);
                pp.y.ModMulK1(&_s);
                pp.y.ModSub(&Gn[i].y);
            }

            dyn.Set(&Gn[i].y);
            dyn.ModNeg();
            dyn.ModSub(&pn.y);
            _s.ModMulK1(&dyn,&dx[i]);
            _p.ModSquareK1(&_s);
            pn.x.ModNeg();
            pn.x.ModAdd(&_p);
            pn.x.ModSub(&Gn[i].x);
            if(calculate_y)	{
                pn.y.ModSub(&Gn[i].x,&pn.x);
                pn.y.ModMulK1(&_s);
                pn.y.ModAdd(&Gn[i].y);
            }

            pp_offset = CPU_GRP_SIZE / 2 + (i + 1);
            pn_offset = CPU_GRP_SIZE / 2 - (i + 1);
            pts[pp_offset] = pp;
            pts[pn_offset] = pn;
            
            if(FLAGENDOMORPHISM)	{
                if( calculate_y  )	{
                    endomorphism_beta[pp_offset].y.Set(&pp.y);
                    endomorphism_beta[pn_offset].y.Set(&pn.y);
                    endomorphism_beta2[pp_offset].y.Set(&pp.y);
                    endomorphism_beta2[pn_offset].y.Set(&pn.y);
                }
                endomorphism_beta[pp_offset].x.ModMulK1(&pp.x, &lambda);
                endomorphism_beta[pn_offset].x.ModMulK1(&pn.x, &lambda);
                endomorphism_beta2[pp_offset].x.ModMulK1(&pp.x, &lambda2);
                endomorphism_beta2[pn_offset].x.ModMulK1(&pn.x, &lambda2);
            }
        }
        if(FLAGENDOMORPHISM)	{
            if( calculate_y  )	{
                endomorphism_beta[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
                endomorphism_beta2[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
            }
            endomorphism_beta[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &lambda);
            endomorphism_beta2[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &lambda2);
        }

        pn = startP;
        dyn.Set(&Gn[i].y);
        dyn.ModNeg();
        dyn.ModSub(&pn.y);
        _s.ModMulK1(&dyn,&dx[i]);
        _p.ModSquareK1(&_s);
        pn.x.ModNeg();
        pn.x.ModAdd(&_p);
        pn.x.ModSub(&Gn[i].x);
        if(calculate_y)	{
            pn.y.ModSub(&Gn[i].x,&pn.x);
            pn.y.ModMulK1(&_s);
            pn.y.ModAdd(&Gn[i].y);
        }
        pts[0] = pn;
        
        if(FLAGENDOMORPHISM)	{
            if( calculate_y  )	{
                endomorphism_beta[0].y.Set(&pn.y);
                endomorphism_beta2[0].y.Set(&pn.y);
            }
            endomorphism_beta[0].x.ModMulK1(&pn.x, &lambda);
            endomorphism_beta2[0].x.ModMulK1(&pn.x, &lambda2);
        }
                        
        for(j = 0; j < CPU_GRP_SIZE/4;j++){
            // Hashing Block
            if(FLAGCRYPTO == CRYPTO_BTC){
                if(FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH ){
                    if(FLAGENDOMORPHISM)	{
                        secp->GetHash160_fromX(P2PKH,0x02,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
                        secp->GetHash160_fromX(P2PKH,0x03,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);
                        secp->GetHash160_fromX(P2PKH,0x02,&endomorphism_beta[(j*4)].x,&endomorphism_beta[(j*4)+1].x,&endomorphism_beta[(j*4)+2].x,&endomorphism_beta[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[2][0],(uint8_t*)publickeyhashrmd160_endomorphism[2][1],(uint8_t*)publickeyhashrmd160_endomorphism[2][2],(uint8_t*)publickeyhashrmd160_endomorphism[2][3]);
                        secp->GetHash160_fromX(P2PKH,0x03,&endomorphism_beta[(j*4)].x,&endomorphism_beta[(j*4)+1].x,&endomorphism_beta[(j*4)+2].x,&endomorphism_beta[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[3][0],(uint8_t*)publickeyhashrmd160_endomorphism[3][1],(uint8_t*)publickeyhashrmd160_endomorphism[3][2],(uint8_t*)publickeyhashrmd160_endomorphism[3][3]);
                        secp->GetHash160_fromX(P2PKH,0x02,&endomorphism_beta2[(j*4)].x,&endomorphism_beta2[(j*4)+1].x,&endomorphism_beta2[(j*4)+2].x,&endomorphism_beta2[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[4][0],(uint8_t*)publickeyhashrmd160_endomorphism[4][1],(uint8_t*)publickeyhashrmd160_endomorphism[4][2],(uint8_t*)publickeyhashrmd160_endomorphism[4][3]);
                        secp->GetHash160_fromX(P2PKH,0x03,&endomorphism_beta2[(j*4)].x,&endomorphism_beta2[(j*4)+1].x,&endomorphism_beta2[(j*4)+2].x,&endomorphism_beta2[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[5][0],(uint8_t*)publickeyhashrmd160_endomorphism[5][1],(uint8_t*)publickeyhashrmd160_endomorphism[5][2],(uint8_t*)publickeyhashrmd160_endomorphism[5][3]);
                    }
                    else	{
                        secp->GetHash160_fromX(P2PKH,0x02,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
                        secp->GetHash160_fromX(P2PKH,0x03,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);
                    }
                }
                if(FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH){
                    if(FLAGENDOMORPHISM)	{
                        for(l = 0; l < 4; l++)	endomorphism_negeted_point[l] = secp->Negation(pts[(j*4)+l]);
                        secp->GetHash160(P2PKH,false, pts[(j*4)], pts[(j*4)+1], pts[(j*4)+2], pts[(j*4)+3],(uint8_t*)publickeyhashrmd160_endomorphism[6][0],(uint8_t*)publickeyhashrmd160_endomorphism[6][1],(uint8_t*)publickeyhashrmd160_endomorphism[6][2],(uint8_t*)publickeyhashrmd160_endomorphism[6][3]);
                        secp->GetHash160(P2PKH,false,endomorphism_negeted_point[0] ,endomorphism_negeted_point[1],endomorphism_negeted_point[2],endomorphism_negeted_point[3],(uint8_t*)publickeyhashrmd160_endomorphism[7][0],(uint8_t*)publickeyhashrmd160_endomorphism[7][1],(uint8_t*)publickeyhashrmd160_endomorphism[7][2],(uint8_t*)publickeyhashrmd160_endomorphism[7][3]);
                        for(l = 0; l < 4; l++)	endomorphism_negeted_point[l] = secp->Negation(endomorphism_beta[(j*4)+l]);
                        secp->GetHash160(P2PKH,false,endomorphism_beta[(j*4)],  endomorphism_beta[(j*4)+1], endomorphism_beta[(j*4)+2], endomorphism_beta[(j*4)+3] ,(uint8_t*)publickeyhashrmd160_endomorphism[8][0],(uint8_t*)publickeyhashrmd160_endomorphism[8][1],(uint8_t*)publickeyhashrmd160_endomorphism[8][2],(uint8_t*)publickeyhashrmd160_endomorphism[8][3]);
                        secp->GetHash160(P2PKH,false,endomorphism_negeted_point[0],endomorphism_negeted_point[1],endomorphism_negeted_point[2],endomorphism_negeted_point[3],(uint8_t*)publickeyhashrmd160_endomorphism[9][0],(uint8_t*)publickeyhashrmd160_endomorphism[9][1],(uint8_t*)publickeyhashrmd160_endomorphism[9][2],(uint8_t*)publickeyhashrmd160_endomorphism[9][3]);
                        for(l = 0; l < 4; l++)	endomorphism_negeted_point[l] = secp->Negation(endomorphism_beta2[(j*4)+l]);
                        secp->GetHash160(P2PKH,false, endomorphism_beta2[(j*4)],  endomorphism_beta2[(j*4)+1] ,  endomorphism_beta2[(j*4)+2] ,  endomorphism_beta2[(j*4)+3] ,(uint8_t*)publickeyhashrmd160_endomorphism[10][0],(uint8_t*)publickeyhashrmd160_endomorphism[10][1],(uint8_t*)publickeyhashrmd160_endomorphism[10][2],(uint8_t*)publickeyhashrmd160_endomorphism[10][3]);
                        secp->GetHash160(P2PKH,false, endomorphism_negeted_point[0], endomorphism_negeted_point[1],   endomorphism_negeted_point[2],endomorphism_negeted_point[3],(uint8_t*)publickeyhashrmd160_endomorphism[11][0],(uint8_t*)publickeyhashrmd160_endomorphism[11][1],(uint8_t*)publickeyhashrmd160_endomorphism[11][2],(uint8_t*)publickeyhashrmd160_endomorphism[11][3]);
                    }
                    else	{
                        secp->GetHash160(P2PKH,false,pts[(j*4)],pts[(j*4)+1],pts[(j*4)+2],pts[(j*4)+3],(uint8_t*)publickeyhashrmd160_uncompress[0],(uint8_t*)publickeyhashrmd160_uncompress[1],(uint8_t*)publickeyhashrmd160_uncompress[2],(uint8_t*)publickeyhashrmd160_uncompress[3]);
                    }
                }
            } else if(FLAGCRYPTO == CRYPTO_ETH){
                if(FLAGENDOMORPHISM)	{
                    for(k = 0; k < 4;k++)	{
                        endomorphism_negeted_point[k] = secp->Negation(pts[(j*4)+k]);
                        generate_binaddress_eth(pts[(4*j)+k],(uint8_t*)publickeyhashrmd160_endomorphism[0][k]);
                        generate_binaddress_eth(endomorphism_negeted_point[k],(uint8_t*)publickeyhashrmd160_endomorphism[1][k]);
                        endomorphism_negeted_point[k] = secp->Negation(endomorphism_beta[(j*4)+k]);
                        generate_binaddress_eth(endomorphism_beta[(4*j)+k],(uint8_t*)publickeyhashrmd160_endomorphism[2][k]);
                        generate_binaddress_eth(endomorphism_negeted_point[k],(uint8_t*)publickeyhashrmd160_endomorphism[3][k]);
                        endomorphism_negeted_point[k] = secp->Negation(endomorphism_beta2[(j*4)+k]);
                        generate_binaddress_eth(endomorphism_beta2[(4*j)+k],(uint8_t*)publickeyhashrmd160_endomorphism[4][k]);
                        generate_binaddress_eth(endomorphism_negeted_point[k],(uint8_t*)publickeyhashrmd160_endomorphism[5][k]);
                    }
                }
                else	{
                    for(k = 0; k < 4;k++)	{
                        generate_binaddress_eth(pts[(4*j)+k],(uint8_t*)publickeyhashrmd160_uncompress[k]);
                    }
                }
            }
            
            // Checking Block
            if( FLAGCRYPTO  == CRYPTO_BTC) {
                for(k = 0; k < 4;k++)	{
                    int point_index = (int)j*4 + k;
                    if(FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH){
                        if(FLAGENDOMORPHISM)	{
                            for(l = 0;l < 6; l++)	{
                                if(bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k],MAXLENGTHADDRESS)) {
                                    if(searchbinary(addressTable,publickeyhashrmd160_endomorphism[l][k],N) != -1) {
                                        keyfound.SetInt32(point_index - (CPU_GRP_SIZE/2)); keyfound.Add(&key_mpz);
                                        publickey = secp->ComputePublicKey(&keyfound);
                                        switch(l)	{
                                            case 0:	if(publickey.y.IsOdd())	{ keyfound.Neg(); keyfound.Add(&secp->order); } break;
                                            case 1:	if(publickey.y.IsEven()) { keyfound.Neg(); keyfound.Add(&secp->order); } break;
                                            case 2:	keyfound.ModMulK1order(&lambda); if(publickey.y.IsOdd()) { keyfound.Neg(); keyfound.Add(&secp->order); } break;
                                            case 3:	keyfound.ModMulK1order(&lambda); if(publickey.y.IsEven()) { keyfound.Neg(); keyfound.Add(&secp->order); } break;
                                            case 4:	keyfound.ModMulK1order(&lambda2); if(publickey.y.IsOdd()) { keyfound.Neg(); keyfound.Add(&secp->order); } break;
                                            case 5:	keyfound.ModMulK1order(&lambda2); if(publickey.y.IsEven()) { keyfound.Neg(); keyfound.Add(&secp->order); } break;
                                        }
                                        writekey(true,&keyfound);
                                    }
                                }
                            }
                        }
                        else	{
                            for(l = 0;l < 2; l++)	{
                                if(bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k],MAXLENGTHADDRESS)) {
                                    if(searchbinary(addressTable,publickeyhashrmd160_endomorphism[l][k],N) != -1) {
                                        keyfound.SetInt32(point_index - (CPU_GRP_SIZE/2)); keyfound.Add(&key_mpz);
                                        publickey = secp->ComputePublicKey(&keyfound);
                                        secp->GetHash160(P2PKH,true,publickey,(uint8_t*)publickeyhashrmd160);
                                        if(memcmp(publickeyhashrmd160_endomorphism[l][k],publickeyhashrmd160,20) != 0)	{
                                            keyfound.Neg();
                                            keyfound.Add(&secp->order);
                                        }
                                        writekey(true,&keyfound);
                                    }
                                }
                            }
                        }
                    }
                    if(FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH)	{
                        if(FLAGENDOMORPHISM)	{
                            for(l = 6;l < 12; l++)	{
                                if(bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k],MAXLENGTHADDRESS)) {
                                    if(searchbinary(addressTable,publickeyhashrmd160_endomorphism[l][k],N) != -1) {
                                        keyfound.SetInt32(point_index - (CPU_GRP_SIZE/2)); keyfound.Add(&key_mpz);
                                        switch(l)	{
                                            case 6: case 7: break;
                                            case 8: case 9: keyfound.ModMulK1order(&lambda); break;
                                            case 10: case 11: keyfound.ModMulK1order(&lambda2); break;
                                        }
                                        publickey = secp->ComputePublicKey(&keyfound);
                                        secp->GetHash160(P2PKH,false,publickey,(uint8_t*)publickeyhashrmd160_uncompress[0]);
                                        if(memcmp(publickeyhashrmd160_endomorphism[l][k],publickeyhashrmd160_uncompress[0],20) != 0){
                                            keyfound.Neg();
                                            keyfound.Add(&secp->order);
                                        }
                                        writekey(false,&keyfound);
                                    }
                                }
                            }
                        }
                        else	{
                            if(bloom_check(&bloom,publickeyhashrmd160_uncompress[k],MAXLENGTHADDRESS)) {
                                if(searchbinary(addressTable,publickeyhashrmd160_uncompress[k],N) != -1) {
                                    keyfound.SetInt32(point_index - (CPU_GRP_SIZE/2)); keyfound.Add(&key_mpz);
                                    writekey(false,&keyfound);
                                }
                            }
                        }
                    }
                }
            }
            else if( FLAGCRYPTO == CRYPTO_ETH) {
                int point_index = (int)j*4 + k;
                if(FLAGENDOMORPHISM)	{
                    for(k = 0; k < 4;k++)	{
                        for(l = 0;l < 6; l++)	{
                            if(bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k],MAXLENGTHADDRESS)) {
                                if(searchbinary(addressTable,publickeyhashrmd160_endomorphism[l][k],N) != -1) {
                                    keyfound.SetInt32(point_index - (CPU_GRP_SIZE/2)); keyfound.Add(&key_mpz);
                                    switch(l)	{
                                        case 0: case 1: break;
                                        case 2: case 3: keyfound.ModMulK1order(&lambda); break;
                                        case 4: case 5: keyfound.ModMulK1order(&lambda2); break;
                                    }
                                    publickey = secp->ComputePublicKey(&keyfound);
                                    generate_binaddress_eth(publickey,(uint8_t*)publickeyhashrmd160_uncompress[0]);
                                    if(memcmp(publickeyhashrmd160_endomorphism[l][k],publickeyhashrmd160_uncompress[0],20) != 0){
                                        keyfound.Neg();
                                        keyfound.Add(&secp->order);
                                    }
                                    writekeyeth(&keyfound);
                                }
                            }
                        }
                    }
                }
                else	{
                    for(k = 0; k < 4;k++)	{
                        if(bloom_check(&bloom,publickeyhashrmd160_uncompress[k],MAXLENGTHADDRESS)) {
                            if(searchbinary(addressTable,publickeyhashrmd160_uncompress[k],N) != -1) {
                                keyfound.SetInt32(point_index - (CPU_GRP_SIZE/2)); keyfound.Add(&key_mpz);
                                writekeyeth(&keyfound);
                            }
                        }
                    }
                }
            }
        }
        steps[thread_number]++;
	} 
	ends[thread_number] = 1;
	return NULL;
}


void _swap(struct address_value *a,struct address_value *b)	{
	struct address_value t;
	t  = *a;
	*a = *b;
	*b =  t;
}

void _sort(struct address_value *arr,int64_t n)	{
	uint32_t depthLimit = ((uint32_t) ceil(log(n))) * 2;
	_introsort(arr,depthLimit,n);
}

void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n) {
	int64_t p;
	if(n > 1)	{
		if(n <= 16) {
			_insertionsort(arr,n);
		}
		else	{
			if(depthLimit == 0) {
				_myheapsort(arr,n);
			}
			else	{
				p = _partition(arr,n);
				if(p > 0) _introsort(arr , depthLimit-1 , p);
				if(p < n) _introsort(&arr[p+1],depthLimit-1,n-(p+1));
			}
		}
	}
}

void _insertionsort(struct address_value *arr, int64_t n) {
	int64_t j;
	int64_t i;
	struct address_value key;
	for(i = 1; i < n ; i++ ) {
		key = arr[i];
		j= i-1;
		while(j >= 0 && memcmp(arr[j].value,key.value,20) > 0) {
			arr[j+1] = arr[j];
			j--;
		}
		arr[j+1] = key;
	}
}

int64_t _partition(struct address_value *arr, int64_t n)	{
	struct address_value pivot;
	int64_t r,left,right;
	r = n/2;
	pivot = arr[r];
	left = 0;
	right = n-1;
	do {
		while(left	< right && memcmp(arr[left].value,pivot.value,20) <= 0 )	{
			left++;
		}
		while(right >= left && memcmp(arr[right].value,pivot.value,20) > 0)	{
			right--;
		}
		if(left < right)	{
			if(left == r || right == r)	{
				if(left == r)	{
					r = right;
				}
				if(right == r)	{
					r = left;
				}
			}
			_swap(&arr[right],&arr[left]);
		}
	}while(left < right);
	if(right != r)	{
		_swap(&arr[right],&arr[r]);
	}
	return right;
}

void _heapify(struct address_value *arr, int64_t n, int64_t i) {
	int64_t largest = i;
	int64_t l = 2 * i + 1;
	int64_t r = 2 * i + 2;
	if (l < n && memcmp(arr[l].value,arr[largest].value,20) > 0)
		largest = l;
	if (r < n && memcmp(arr[r].value,arr[largest].value,20) > 0)
		largest = r;
	if (largest != i) {
		_swap(&arr[i],&arr[largest]);
		_heapify(arr, n, largest);
	}
}

void _myheapsort(struct address_value	*arr, int64_t n)	{
	int64_t i;
	for ( i = (n / 2) - 1; i >=	0; i--)	{
		_heapify(arr, n, i);
	}
	for ( i = n - 1; i > 0; i--) {
		_swap(&arr[0] , &arr[i]);
		_heapify(arr, i, 0);
	}
}

void sleep_ms(int milliseconds)	{
#if defined(_WIN64) && !defined(__CYGWIN__)
    Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    if (milliseconds >= 1000)
      sleep(milliseconds / 1000);
    usleep((milliseconds % 1000) * 1000);
#endif
}

void init_generator()	{
	Point G = secp->ComputePublicKey(&stride);
	Point g;
	g.Set(G);
	Gn.reserve(CPU_GRP_SIZE / 2);
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g,G);
		Gn[i] = g;
	}
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
}

void KECCAK_256(uint8_t *source, size_t size,uint8_t *dst)	{
	SHA3_256_CTX ctx;
	SHA3_256_Init(&ctx);
	SHA3_256_Update(&ctx,source,size);
	KECCAK_256_Final(dst,&ctx);
}

void generate_binaddress_eth(Point &publickey,unsigned char *dst_address)	{
	unsigned char bin_publickey[64];
	publickey.x.Get32Bytes(bin_publickey);
	publickey.y.Get32Bytes(bin_publickey+32);
	KECCAK_256(bin_publickey, 64, bin_publickey);
	memcpy(dst_address,bin_publickey+12,20);
}

void menu() {
	printf("\nUsage:\n");
	printf("./keyhunt -f <file> -r <range> [OPTIONS]\n\n");
    printf("Core Options:\n");
	printf("  -f file     Specify file name with addresses (required).\n");
	printf("  -r SR:EN    StartRange:EndRange (required). The end range can be omitted for search from start range to N-1 ECC value.\n");
    printf("  -b bits     Search in a specific bit range, e.g., -b 66 for the 66-bit puzzle range.\n\n");
    printf("Cyclical Scan Options:\n");
    printf("  -seg num    Number of segments to divide the range into. Default: 10\n");
    printf("  -time val   Time to scan each segment. Suffix with 's', 'm', 'h'. E.g., '15m'. Default: 10m\n\n");
	printf("Performance & Search Options:\n");
	printf("  -t tn       Threads number, must be a positive integer. Default: 1\n");
	printf("  -c crypto   Search for specific crypto. <btc, eth>. Default: btc\n");
	printf("  -e          Enable endomorphism search for a ~2x speedup (only for compressed BTC addresses).\n");
	printf("  -l look     What type of address are you looking for <compress, uncompress, both>. Default: both\n");
	printf("  -I stride   Set a stride for the key search space.\n");
	printf("  -z value    Bloom size multiplier, value >= 1. Default: 1\n\n");
    printf("Other Options:\n");
	printf("  -h          Show this help.\n");
	printf("  -q          Quiet the thread output.\n");
	printf("  -s ns       Number of seconds for the stats output, 0 to omit. Default: 30\n");
	printf("  -S          Save address file bloom/cache for faster loading next time.\n");
	printf("  -6          Skip sha256 checksum validation on cached data files.\n");
	printf("  -M          Matrix screen, feel like a h4x0r, but performance will drop.\n");
	printf("\nExample:\n");
	printf("./keyhunt -f addresses.txt -b 66 -t 8 -seg 20 -time 5m\n");
	printf("This command searches the 66-bit puzzle range using 8 threads. It divides the range\n");
    printf("into 20 segments and scans each one randomly for 5 minutes before cycling back to the start.\n\n");
	printf("Developed by AlbertoBSD\tTips BTC: 1Coffee1jV4gB5gaXfHgSHDz9xx9QSECVW\n");
	printf("Thanks to Iceland always helping and sharing his ideas.\nTips to Iceland: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at\n\n");
	exit(EXIT_FAILURE);
}

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line)	{
	if(ptr == NULL)	{
		fprintf(stderr,"[E] error in file %s, %s pointer %s on line %i\n",file,function,name,line); 
		exit(EXIT_FAILURE);
	}
}

void writekey(bool compressed,Int *key)	{
	Point publickey;
	FILE *keys;
	char *hextemp,*hexrmd,public_key_hex[132],address[50],rmdhash[20];
    char telegram_message[512];
	memset(address,0,50);
	memset(public_key_hex,0,132);
	hextemp = key->GetBase16();
	publickey = secp->ComputePublicKey(key);
	secp->GetPublicKeyHex(compressed,publickey,public_key_hex);
	secp->GetHash160(P2PKH,compressed,publickey,(uint8_t*)rmdhash);
	hexrmd = tohex(rmdhash,20);
	rmd160toaddress_dst(rmdhash,address);

#if defined(_WIN64) && !defined(__CYGWIN__)
	WaitForSingleObject(write_keys, INFINITE);
#else
	pthread_mutex_lock(&write_keys);
#endif

    snprintf(telegram_message, sizeof(telegram_message), "Key Found!\nPrivate Key: %s\nPublic Key: %s\nAddress: %s\n", hextemp, public_key_hex, address);
    sendToTelegram(telegram_message);

	keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
	if(keys != NULL)	{
		fprintf(keys,"Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);
		fclose(keys);
	}
	printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);
	
#if defined(_WIN64) && !defined(__CYGWIN__)
	ReleaseMutex(write_keys);
#else
	pthread_mutex_unlock(&write_keys);
#endif
	free(hextemp);
	free(hexrmd);
    
    // Terminate the entire program upon finding a key.
    exit(0);
}

void writekeyeth(Int *key)	{
	Point publickey;
	FILE *keys;
	char *hextemp,address[43],hash[20];
    char telegram_message[512];
	hextemp = key->GetBase16();
	publickey = secp->ComputePublicKey(key);
	generate_binaddress_eth(publickey,(unsigned char*)hash);
	address[0] = '0';
	address[1] = 'x';
	tohex_dst(hash,20,address+2);

#if defined(_WIN64) && !defined(__CYGWIN__)
	WaitForSingleObject(write_keys, INFINITE);
#else
	pthread_mutex_lock(&write_keys);
#endif

    snprintf(telegram_message, sizeof(telegram_message), "Key Found!\nPrivate Key: %s\nAddress: %s\n", hextemp, address);
    sendToTelegram(telegram_message);

	keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
	if(keys != NULL)	{
		fprintf(keys,"Private Key: %s\naddress: %s\n",hextemp,address);
		fclose(keys);
	}
	printf("\n Hit!!!! Private Key: %s\naddress: %s\n",hextemp,address);
#if defined(_WIN64) && !defined(__CYGWIN__)
	ReleaseMutex(write_keys);
#else
	pthread_mutex_unlock(&write_keys);
#endif
	free(hextemp);

    // Terminate the entire program upon finding a key.
    exit(0);
}

bool isBase58(char c) {
    const char base58Set[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    return strchr(base58Set, c) != NULL;
}

bool isValidBase58String(char *str)	{
	int len = strlen(str);
	bool continuar = true;
	for (int i = 0; i < len && continuar; i++) {
		continuar = isBase58(str[i]);
	}
	return continuar;
}


bool readFileAddress(char *fileName)	{
	FILE *fileDescriptor;
	char fileBloomName[30];
	uint8_t checksum[32];
	char dataChecksum[32],bloomChecksum[32];
	size_t bytesRead;
	uint64_t dataSize;
	
	if(FLAGSAVEREADFILE)	{
		if(!sha256_file((const char*)fileName,checksum)){
			fprintf(stderr,"[E] sha256_file error line %i\n",__LINE__ - 1);
			return false;
		}
        char hexPrefix[9];
		tohex_dst((char*)checksum, 4, hexPrefix); 
		snprintf(fileBloomName, 30, "data_%s.dat", hexPrefix);
		fileDescriptor = fopen(fileBloomName,"rb");
		if(fileDescriptor != NULL)	{
			printf("[+] Reading cached file %s\n",fileBloomName);

			bytesRead = fread(bloomChecksum,1,32,fileDescriptor);
			if(bytesRead != 32)	{ fclose(fileDescriptor); return false; }
			
			bytesRead = fread(&bloom,1,sizeof(struct bloom),fileDescriptor);
			if(bytesRead != sizeof(struct bloom))	{ fclose(fileDescriptor); return false; }
			
			printf("[+] Bloom filter for %" PRIu64 " elements.\n",bloom.entries);
			
			bloom.bf = (uint8_t*) malloc(bloom.bytes);
			if(bloom.bf == NULL)	{ fclose(fileDescriptor); return false; }

			bytesRead = fread(bloom.bf,1,bloom.bytes,fileDescriptor);
			if(bytesRead != bloom.bytes)	{ fclose(fileDescriptor); return false; }

			if(FLAGSKIPCHECKSUM == 0){
				sha256((uint8_t*)bloom.bf,bloom.bytes,(uint8_t*)checksum);
				if(memcmp(checksum,bloomChecksum,32) != 0)	{ fclose(fileDescriptor); return false; }
			}
			
			bytesRead = fread(dataChecksum,1,32,fileDescriptor);
			if(bytesRead != 32)	{ fclose(fileDescriptor); return false; }
			
			bytesRead = fread(&dataSize,1,sizeof(uint64_t),fileDescriptor);
			if(bytesRead != sizeof(uint64_t))	{ fclose(fileDescriptor); return false; }

			N = dataSize / sizeof(struct address_value);
	
			printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n",N,(double)(((double) sizeof(struct address_value)*N)/(double)1048576));
			
			addressTable = (struct address_value*) malloc(dataSize);
			if(addressTable == NULL)	{ fclose(fileDescriptor); return false; }
			
			bytesRead = fread(addressTable,1,dataSize,fileDescriptor);
			if(bytesRead != dataSize)	{ fclose(fileDescriptor); return false; }

			if(FLAGSKIPCHECKSUM == 0)	{
				sha256((uint8_t*)addressTable,dataSize,(uint8_t*)checksum);
				if(memcmp(checksum,dataChecksum,32) != 0)	{ fclose(fileDescriptor); return false; }
			}
			FLAGREADEDFILE1 = 1;
			fclose(fileDescriptor);
			MAXLENGTHADDRESS = sizeof(struct address_value);
		}
	}
	
	if(!FLAGREADEDFILE1)	{
        if(FLAGCRYPTO == CRYPTO_BTC)	{
            return forceReadFileAddress(fileName);
        }
        if(FLAGCRYPTO == CRYPTO_ETH)	{
            return forceReadFileAddressEth(fileName);
        }
	}
	return true;
}

bool forceReadFileAddress(char *fileName)	{
	FILE *fileDescriptor;
	bool validAddress;
	uint64_t numberItems,i;
	size_t r,raw_value_length;
	uint8_t rawvalue[50];
	char aux[100],*hextemp;
	fileDescriptor = fopen(fileName,"r");	
	if(fileDescriptor == NULL)	{ return false; }

	numberItems = 0;
	while(!feof(fileDescriptor))	{
		hextemp = fgets(aux,100,fileDescriptor);
		trim(aux," \t\n\r");
		if(hextemp == aux && strlen(aux) > 20) { numberItems++; }
	}
	fseek(fileDescriptor,0,SEEK_SET);
	MAXLENGTHADDRESS = 20;
	
	printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n",numberItems,(double)(((double) sizeof(struct address_value)*numberItems)/(double)1048576));
	addressTable = (struct address_value*) malloc(sizeof(struct address_value)*numberItems);
	checkpointer((void *)addressTable,__FILE__,"malloc","addressTable" ,__LINE__ -1 );
		
	if(!initBloomFilter(&bloom,numberItems))
		return false;

	i = 0;
	while(i < numberItems)	{
		validAddress = false;
		memset(aux,0,100);
		hextemp = fgets(aux,100,fileDescriptor);
        if(!hextemp) break; // End of file
		trim(aux," \t\n\r");			
		r = strlen(aux);
		if(r > 0 && r <= 40)	{
			if(r<40 && isValidBase58String(aux))	{
				raw_value_length = 25;
				b58tobin(rawvalue,&raw_value_length,aux,r);
				if(raw_value_length == 25)	{
					bloom_add(&bloom, rawvalue+1 ,sizeof(struct address_value));
					memcpy(addressTable[i].value,rawvalue+1,sizeof(struct address_value));											
					i++;
					validAddress = true;
				}
			}
			if(r == 40 && isValidHex(aux))	{
				hexs2bin(aux,rawvalue);				
				bloom_add(&bloom, rawvalue ,sizeof(struct address_value));
				memcpy(addressTable[i].value,rawvalue,sizeof(struct address_value));											
				i++;
				validAddress = true;
			}
		}
		if(!validAddress)	{
			fprintf(stderr,"[I] Omitting invalid line: %s\n",aux);
		}
	}
	N = i;
	fclose(fileDescriptor);
	return true;
}

bool forceReadFileAddressEth(char *fileName)	{
	FILE *fileDescriptor;
	bool validAddress;
	uint64_t numberItems,i;
	size_t r;
	uint8_t rawvalue[50];
	char aux[100],*hextemp;
	fileDescriptor = fopen(fileName,"r");	
	if(fileDescriptor == NULL) { return false; }
	
	numberItems = 0;
	while(!feof(fileDescriptor))	{
		hextemp = fgets(aux,100,fileDescriptor);
		trim(aux," \t\n\r");
		if(hextemp == aux && strlen(aux) >= 40) { numberItems++; }
	}
	fseek(fileDescriptor,0,SEEK_SET);
	MAXLENGTHADDRESS = 20;
	
	printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n",numberItems,(double)(((double) sizeof(struct address_value)*numberItems)/(double)1048576));
	addressTable = (struct address_value*) malloc(sizeof(struct address_value)*numberItems);
	checkpointer((void *)addressTable,__FILE__,"malloc","addressTable" ,__LINE__ -1 );
	
	if(!initBloomFilter(&bloom,numberItems))
		return false;
	
	i = 0;
	while(i < numberItems)	{
		validAddress = false;
		memset(aux,0,100);
		hextemp = fgets(aux,100,fileDescriptor);
        if(!hextemp) break; // End of file
		trim(aux," \t\n\r");			
		r = strlen(aux);
		if(r >= 40 && r <= 42){
			char *hex_part = (r == 42) ? aux + 2 : aux;
			if(isValidHex(hex_part)){
				hexs2bin(hex_part,rawvalue);
				bloom_add(&bloom, rawvalue ,sizeof(struct address_value));
				memcpy(addressTable[i].value,rawvalue,sizeof(struct address_value));											
				i++;
				validAddress = true;
			}
		}
		if(!validAddress)	{
			fprintf(stderr,"[I] Omitting invalid line: %s\n",aux);
		}
	}
	N = i;
	fclose(fileDescriptor);
	return true;
}

bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom)	{
	bool r = true;
	printf("[+] Bloom filter for %" PRIu64 " elements.\n",items_bloom);
	if(items_bloom <= 10000)	{
		if(bloom_init2(bloom_arg,10000,0.000001) == 1){
			fprintf(stderr,"[E] error bloom_init for 10000 elements.\n");
			r = false;
		}
	}
	else	{
		if(bloom_init2(bloom_arg,FLAGBLOOMMULTIPLIER*items_bloom,0.000001)	== 1){
			fprintf(stderr,"[E] error bloom_init for %" PRIu64 " elements.\n",items_bloom);
			r = false;
		}
	}
	printf("[+] Bloomfilter size: %.2f MB\n",(double)(((double) bloom_arg->bytes)/(double)1048576));
	return r;
}

void writeFileIfNeeded(const char *fileName)	{
	if(FLAGSAVEREADFILE && !FLAGREADEDFILE1)	{
		FILE *fileDescriptor;
		char fileBloomName[30];
		uint8_t checksum[32];
		char dataChecksum[32],bloomChecksum[32];
		size_t bytesWrite;
		uint64_t dataSize;
		if(!sha256_file((const char*)fileName,checksum)){
			fprintf(stderr,"[E] sha256_file error\n");
			exit(EXIT_FAILURE);
		}
        char hexPrefix[9];
		tohex_dst((char*)checksum, 4, hexPrefix);
		snprintf(fileBloomName, 30, "data_%s.dat", hexPrefix);
		fileDescriptor = fopen(fileBloomName,"wb");
		dataSize = N * (sizeof(struct address_value));

		if(fileDescriptor != NULL)	{
			printf("[+] Writing cached file %s ",fileBloomName);
			
			sha256((uint8_t*)bloom.bf,bloom.bytes,(uint8_t*)bloomChecksum);
			printf(".");
			bytesWrite = fwrite(bloomChecksum,1,32,fileDescriptor);
			if(bytesWrite != 32) { exit(EXIT_FAILURE); }
			
			printf(".");
			bytesWrite = fwrite(&bloom,1,sizeof(struct bloom),fileDescriptor);
			if(bytesWrite != sizeof(struct bloom)) { exit(EXIT_FAILURE); }

			printf(".");
			bytesWrite = fwrite(bloom.bf,1,bloom.bytes,fileDescriptor);
			if(bytesWrite != bloom.bytes) { fclose(fileDescriptor); exit(EXIT_FAILURE); }
			
			printf(".");
			sha256((uint8_t*)addressTable,dataSize,(uint8_t*)dataChecksum);

			printf(".");
			bytesWrite = fwrite(dataChecksum,1,32,fileDescriptor);
			if(bytesWrite != 32) { exit(EXIT_FAILURE); }

			printf(".");	
			bytesWrite = fwrite(&dataSize,1,sizeof(uint64_t),fileDescriptor);
			if(bytesWrite != sizeof(uint64_t)) { exit(EXIT_FAILURE); }

			printf(".");
			bytesWrite = fwrite(addressTable,1,dataSize,fileDescriptor);
			if(bytesWrite != dataSize) { exit(EXIT_FAILURE); }

			printf(". done!\n");
			FLAGREADEDFILE1 = 1;	
			fclose(fileDescriptor);		
		}
	}
}