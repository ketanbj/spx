#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <err.h>
#include <fcntl.h>
#include <syslog.h>

#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif

#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "App.h"
#include "Enclave_u.h"

#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "sgx_tcrypto.h"

#define MAX_SIZE_LEN 128
#define MAX_SIZE_ARG 32
#define MAX_SIZE_PATH 128

#define RESP_SIZE 1024

int debug = 1;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: retrive the launch token saved by last transaction */
#ifdef _MSC_VER
    /* try to get the token saved in CSIDL_LOCAL_APPDATA */
    if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, token_path)) {
        strncpy_s(token_path, _countof(token_path), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    } else {
        strncat_s(token_path, _countof(token_path), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+2);
    }

    /* open the token file */
    HANDLE token_handler = CreateFileA(token_path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
    if (token_handler == INVALID_HANDLE_VALUE) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    } else {
        /* read the token from saved file */
        DWORD read_num = 0;
        ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, NULL);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#else /* __GNUC__ */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#endif
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
#ifdef _MSC_VER
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
#else
        if (fp != NULL) fclose(fp);
#endif
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
#ifdef _MSC_VER
    if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
        return 0;
    }
    
    /* flush the file cache */
    FlushFileBuffers(token_handler);
    /* set access offset to the begin of the file */
    SetFilePointer(token_handler, 0, NULL, FILE_BEGIN);

    /* write back the token */
    DWORD write_num = 0;
    WriteFile(token_handler, token, sizeof(sgx_launch_token_t), &write_num, NULL);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    CloseHandle(token_handler);
#else /* __GNUC__ */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
#endif
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

#if defined(_MSC_VER)
/* query and enable SGX device*/
int query_sgx_status()
{
    sgx_device_status_t sgx_device_status;
    sgx_status_t sgx_ret = sgx_enable_device(&sgx_device_status);
    if (sgx_ret != SGX_SUCCESS) {
        printf("Failed to get SGX device status.\n");
        return -1;
    }
    else {
        switch (sgx_device_status) {
        case SGX_ENABLED:
            return 0;
        case SGX_DISABLED_REBOOT_REQUIRED:
            printf("SGX device has been enabled. Please reboot your machine.\n");
            return -1;
        case SGX_DISABLED_LEGACY_OS:
            printf("SGX device can't be enabled on an OS that doesn't support EFI interface.\n");
            return -1;
        case SGX_DISABLED:
            printf("SGX device not found.\n");
            return -1;
        default:
            printf("Unexpected error.\n");
            return -1;
        }
    }
}
#endif

/* Airbox Implementation */

unsigned char session_key[16] = "ABCDEFGHIJKLMNO"; // Hardcoded 128-bit key
#define MAX_SIZE_LEN 128
#define MAX_SIZE_ARG 32
#define MAX_SIZE_PATH 128
#define AES_LENGTH 16
#define RAU
#define RESP_SIZE 1024

#define SERVER_NAME "airbox_sgx_cache"
#define SERVER_URL ""
#define PROTOCOL "HTTP/1.0"
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"
#define TIMEOUT 20

/* Forwards. */
int airbox_sgx_put(char* key, int klen, char* val, int vlen);
int airbox_sgx_get(char* key, int klen, int* rvlen, char** rval);
static int open_client_socket( char* hostname, unsigned short port );
static void proxy_http(char* host, char* method, char* path, char* protocol, FILE* sockrfp, FILE* sockwfp, int do_cache);
static void proxy_ssl( char* method, char* host, char* protocol, FILE* sockrfp, FILE* sockwfp );
static void sigcatch( int sig );
static void trim( char* line );
static void send_error( int status, char* title, char* extra_header, char* text ) __attribute__((__noreturn__));
static void send_headers( int status, char* title, char* extra_header, char* mime_type, int length, time_t mod );

char wlPath[] = "requestData.txt";
FILE* wlFile = NULL;
int wlFinish = 0;

#define MAX_REQ_LINE 4096
int get_next_line(char** rline)
{
	int rlen = 0;
	char *eline;
	if(wlFile == NULL)
	{
     	wlFile= fopen(wlPath,"r");
		if(!wlFile )
		{
			printf("Unable to open workload file\n");
			return -2;
		}
	}
	//printf("Opened workload file\n");
	char* line = (char *)malloc(MAX_REQ_LINE);
	if(!line)
	{
		printf("Unable to allocate memory for next line\n");
		return -3;
	} 
		
	if(!fgets(line,MAX_REQ_LINE, wlFile))
	{
		if(feof(wlFile)) 
		{
			if(debug) printf("End of Workload\n");
			wlFinish = 1;
			return -1;
		}
		printf("Issue reading wlFile\n");
		return -4;
	}
	//printf("Got a line %s \n", line);

	if(strcmp("<REQ>\n",line) == 0)
	{
		if(debug) printf("WL: Request start\n");

		if(!fgets(line,MAX_REQ_LINE, wlFile))
        {
            printf("issue reading wlFile\n");
            return -5;
        }
		*rline = line;
		rlen = strlen(line);
	}
	else if(strcmp("</REQ>\n",line) == 0)
	{
		if(feof(wlFile))
        {
            if(debug) printf("End of Workload\n");
			wlFinish = 1;
			if(line) free(line);
			line = NULL;
            return -1;
        }
		//*line = '\0';
		//printf("WL: Request End\n");
		rlen = 0;
	}
	else
	{
		*rline = line;
		rlen = strlen(line);
	}

	return rlen;	
}

// for forwarding content in request
int get_next_char()
{
	if(wlFile == NULL)
    {
        wlFile= fopen(wlPath, "r");
        if(!wlFile )
        {
            printf("Unable to open workload file\n");
            return -2;
        }
    }
	
	return getc(wlFile);
}

void encrypt(unsigned char *key, unsigned char *input, unsigned char *output, int length)
{
	mbedtls_aes_context aes;
	unsigned char iv[16] = "random";

	// TODO: check key length
	mbedtls_aes_setkey_enc(&aes, key, 256);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv, input, output);
}

void decrypt(unsigned char *key, unsigned char *input, unsigned char *output, int length)
{
	mbedtls_aes_context aes;
	unsigned char iv[16] = "random";

    // TODO: check key length
	mbedtls_aes_setkey_dec(&aes, key, 256);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iv, input, output);
}

int proxy_main()
{
    char *line, method[4096], url[4096], protocol[4096], host[4096], path[4096];
    unsigned short port;
    int iport;
    int sockfd;
    int ssl;
    FILE* sockrfp;
    FILE* sockwfp;
    int rlen = 0;
    int do_cache = 0;
    printf(">> proxy_main\n");
    /*Read the first line of the request. */
    if ( !((rlen = get_next_line(&line)) >= 0)) 
    {
        if(rlen == -1)
        {
            if(debug) printf("No more requests\n");
            return 0;
        }
        else
        {
            send_error( 400, "Bad Request", (char*) 0, "No request found." );
        }
    }

    /* Parse it. */
    trim( line );
    if ( sscanf( line, "%[^ ] %[^ ] %[^ ]", method, url, protocol ) != 3 )
        send_error( 400, "Bad Request", (char*) 0, "Can't parse request." );

    if ( url[0] == '\0' )
        send_error( 400, "Bad Request", (char*) 0, "Null URL." );

    //openlog( "ef_proxy", 0, LOG_DAEMON );
    printf(" Checking for request: %s\n", url );
    int sgxrlen = 0; 
    char* sgxrval = NULL;
    int norm_len = strlen(url)+ (AES_LENGTH - (strlen(url) % AES_LENGTH));
    if(debug) printf("aligned url len: %d\n", norm_len); 
    char * eurl = (char *) malloc(norm_len);
    char *curl = (char *) malloc(norm_len);
    memset(eurl, 0, norm_len);
    memset(curl, 0, norm_len);
    strcpy(curl, url);
    if(debug) printf("curl: %s\n",curl);

    encrypt(session_key, (unsigned char *)curl, (unsigned char*)eurl, norm_len);
    memset(curl, 0, norm_len);
    if(airbox_sgx_get(eurl, norm_len, &sgxrlen, &sgxrval))
    {
        printf("Issue with get\n");
        //return -2;
    }

    if(sgxrlen > 0 && sgxrval != NULL)
    {
        // Parse through workload file till this request date finishes
        while ( (rlen = get_next_line(&line)) > 0 )
        {
            if(rlen == 0)
                break;
            if(debug) 
                printf("%s", line);
        }
        printf("Found len: %d\n",sgxrlen);
        if(debug)
        {
        char *psgxrval = (char *) malloc(sgxrlen);
        decrypt(session_key, (unsigned char *)sgxrval, (unsigned char *)psgxrval, sgxrlen);
        printf("----------------------------\n");
            int i = 0;
            //decrypt here before printing
            while(i < sgxrlen)
                putc(psgxrval[i++],stdout);
            putc('\n',stdout);
        }
        printf("----------------------------\n");
        // return this to user & return
        return 0;
    }
    else
    {
        do_cache = 1;
    }


    if ( strncasecmp( url, "http://", 7 ) == 0 )
    {
        (void) strncpy( url, "http", 4 );   // make sure it's lower case 
        if ( sscanf( url, "http://%[^:/]:%d%s", host, &iport, path ) == 3 )
            port = (unsigned short) iport;
        else if ( sscanf( url, "http://%[^/]%s", host, path ) == 2 )
            port = 80;
        else if ( sscanf( url, "http://%[^:/]:%d", host, &iport ) == 2 )
        {
            port = (unsigned short) iport;
            *path = '\0';
        }
        else if ( sscanf( url, "http://%[^/]", host ) == 1 )
        {
            port = 80;
            *path = '\0';
        }
        else
            send_error( 400, "Bad Request", (char*) 0, "Can't parse URL." );
        ssl = 0;
    }
    else if ( strcmp( method, "CONNECT" ) == 0 )
    {
        if ( sscanf( url, "%[^:]:%d", host, &iport ) == 2 )
                port = (unsigned short) iport;
        else if ( sscanf( url, "%s", host ) == 1 )
                port = 443;
        else
                send_error( 400, "Bad Request", (char*) 0, "Can't parse URL." );
        ssl = 1;
    }
    else
        send_error( 400, "Bad Request", (char*) 0, "Unknown URL type." );

    // Get ready to catch timeouts.. 
    (void) signal( SIGALRM, sigcatch );

    // Open the client socket to the real web server. 
    (void) alarm( TIMEOUT );
    sockfd = open_client_socket( host, port );

    // Open separate streams for read and write, r+ doesn't always work. 
    sockrfp = fdopen( sockfd, "r" );
    sockwfp = fdopen( sockfd, "w" );

    if ( ssl )
        proxy_ssl( method, host, protocol, sockrfp, sockwfp);
    else
        proxy_http( host,method, path, protocol, sockrfp, sockwfp, do_cache);

    // Done. 
    (void) close( sockfd );
    printf("<< proxy_main\n");
}


#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
#define USE_IPV6
#endif

static int
open_client_socket( char* hostname, unsigned short port )
    {
#ifdef USE_IPV6
    struct addrinfo hints;
    char portstr[10];
    int gaierr;
    struct addrinfo* ai;
    struct addrinfo* ai2;
    struct addrinfo* aiv4;
    struct addrinfo* aiv6;
    struct sockaddr_in6 sa_in;
#else /* USE_IPV6 */
    struct hostent *he;
    struct sockaddr_in sa_in;
#endif /* USE_IPV6 */
    int sa_len, sock_family, sock_type, sock_protocol;
    int sockfd;

    (void) memset( (void*) &sa_in, 0, sizeof(sa_in) );

#ifdef USE_IPV6

    (void) memset( &hints, 0, sizeof(hints) );
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    (void) snprintf( portstr, sizeof(portstr), "%d", (int) port );
    if ( (gaierr = getaddrinfo( hostname, portstr, &hints, &ai )) != 0 )
    send_error( 404, "Not Found", (char*) 0, "Unknown host." );

    /* Find the first IPv4 and IPv6 entries. */
    aiv4 = (struct addrinfo*) 0;
    aiv6 = (struct addrinfo*) 0;
    for ( ai2 = ai; ai2 != (struct addrinfo*) 0; ai2 = ai2->ai_next )
    {
    switch ( ai2->ai_family )
        {
        case AF_INET: 
        if ( aiv4 == (struct addrinfo*) 0 )
        aiv4 = ai2;
        break;
        case AF_INET6:
        if ( aiv6 == (struct addrinfo*) 0 )
        aiv6 = ai2;
        break;
        }
    }

    /* If there's an IPv4 address, use that, otherwise try IPv6. */
    if ( aiv4 != (struct addrinfo*) 0 )
    {
    if ( sizeof(sa_in) < aiv4->ai_addrlen )
        {
        (void) fprintf(
        stderr, "%s - sockaddr too small (%lu < %lu)\n",
        hostname, (unsigned long) sizeof(sa_in),
        (unsigned long) aiv4->ai_addrlen );
        exit( -1 );
        }
    sock_family = aiv4->ai_family;
    sock_type = aiv4->ai_socktype;
    sock_protocol = aiv4->ai_protocol;
    sa_len = aiv4->ai_addrlen;
    (void) memcpy( &sa_in, aiv4->ai_addr, sa_len );
    goto ok;
    }
    if ( aiv6 != (struct addrinfo*) 0 )
    {
    if ( sizeof(sa_in) < aiv6->ai_addrlen )
        {
        (void) fprintf(
        stderr, "%s - sockaddr too small (%lu < %lu)\n",
        hostname, (unsigned long) sizeof(sa_in),
        (unsigned long) aiv6->ai_addrlen );
        exit( -1 );
        }
    sock_family = aiv6->ai_family;
    sock_type = aiv6->ai_socktype;
    sock_protocol = aiv6->ai_protocol;
    sa_len = aiv6->ai_addrlen;
    (void) memcpy( &sa_in, aiv6->ai_addr, sa_len );
    goto ok;
    }

    send_error( 404, "Not Found", (char*) 0, "Unknown host." );

    ok:
    freeaddrinfo( ai );

#else /* USE_IPV6 */

    he = gethostbyname( hostname );
    if ( he == (struct hostent*) 0 )
    send_error( 404, "Not Found", (char*) 0, "Unknown host." );
    sock_family = sa_in.sin_family = he->h_addrtype;
    sock_type = SOCK_STREAM;
    sock_protocol = 0;
    sa_len = sizeof(sa_in);
    (void) memcpy( &sa_in.sin_addr, he->h_addr, he->h_length );
    sa_in.sin_port = htons( port );

#endif /* USE_IPV6 */

    sockfd = socket( sock_family, sock_type, sock_protocol );
    if ( sockfd < 0 )
    send_error( 500, "Internal Error", (char*) 0, "Couldn't create socket." );

    if ( connect( sockfd, (struct sockaddr*) &sa_in, sa_len ) < 0 )
    send_error( 503, "Service Unavailable", (char*) 0, "Connection refused." );

    return sockfd;
    }


static void proxy_http( char* host, char* method, char* path, char* protocol, FILE* sockrfp, FILE* sockwfp, int do_cache)
{
    char *line, protocol2[10000], comment[10000];
    int first_line, status, ich;
    long content_length, i;
    int rlen;

    printf(">> proxy_http\n");
    /* Send request. */
    (void) alarm( TIMEOUT );
    (void) fprintf( sockwfp, "%s %s %s\r\n", method, path, protocol );
    if(debug) 
        printf("REQUEST: --------------------------\n");
    if(debug) 
        (void) fprintf( stdout, "%s %s %s %s\r\n", host, method, path, protocol );
    /* Forward the remainder of the request from the client. */
    content_length = -1;
    while ( (rlen = get_next_line(&line)) >= 0 )
    {
        if(debug) 
            printf("rlen: %d\n", rlen);
        if ( rlen == 0 || strcmp( line, "\n" ) == 0 || strcmp( line, "\r\n" ) == 0 )
            break;
        (void) fputs( line, sockwfp );
        if(debug) 
            (void) fputs( line, stdout );
        (void) alarm( TIMEOUT );
        trim( line );
        if ( strncasecmp( line, "Content-Length:", 15 ) == 0 )
        {
            content_length = atol( &(line[15]) );
        }
        if(debug) printf("%s",line);
    }
    //(void) fputs( line, sockwfp );
    (void) fputs( "\n\r", sockwfp );
    (void) fflush( sockwfp );
    if(debug) (void) fputs( line, stdout );
    /* If there's content, forward that too. */
    if ( content_length != -1 ) 
    {
        printf("Content length not null. getting content\n");
        for ( i = 0; i < content_length && ( ich = get_next_char() ) != EOF; ++i )
        {
            putc( ich, sockwfp );
            if(debug) putc(ich, stdout);
        }
        (void) fflush( sockwfp );
    }
    if(debug) 
    printf("/REQUEST: -------------------------\n");

    // Forward the response back to the client. 
    (void) alarm( TIMEOUT );
    content_length = -1;
    first_line = 1;
    status = -1;
    //printf("++ proxy_http - 1\n");
    // To be compatible with most the values are from Apache limits
    char respHeader[8190*100];
    while ( fgets( line, 8190, sockrfp ) != (char*) 0 )
    {
        if ( strcmp( line, "\n" ) == 0 || strcmp( line, "\r\n" ) == 0 )
            break;
        if(debug) 
            (void) fputs( line, stdout );
        (void) alarm( TIMEOUT );
        strcat(respHeader, line);
        trim( line );
        if ( first_line )
        {
            (void) sscanf( line, "%[^ ] %d %s", protocol2, &status, comment );
            first_line = 0;
        }
        if ( strncasecmp( line, "Content-Length:", 15 ) == 0 )
            content_length = atol( &(line[15]) );
    }
    if(do_cache)
    {
        if(debug) printf("Response Header:\n %s\n", respHeader);
    }
    //printf("++ proxy_http - 2\n");
    // Add a response header. 
    if(debug) (void) fputs( "Connection: close\r\n", stdout );
    if(debug) (void) fputs( line, stdout );
    (void) fflush( stdout );
    // Under certain circumstances we don't look for the contents, even
    // if there was a Content-Length.
    //
    if(debug) printf("++ proxy_http - 3\n");
    char* response = (char *)malloc(content_length);
    if(response == NULL)
    {
        printf("No enough memory\n");
    }
    //char* ptr = response;
    if ( strcasecmp( method, "HEAD" ) != 0 && status != 304 )
    {
        // Forward the content too, either counted or until EOF. 
        //printf("content-length: %d\n", content_length);
        for ( i = 0; ( content_length == -1 || i < content_length ) && ( ich = getc( sockrfp ) ) != EOF; ++i )
        {
            if(debug) 
                putchar( ich );
            response[i] = (char)ich;
            
            if ( i % 1000 == 0 )
                (void) alarm( TIMEOUT );
        }
    }
    //response = "\n\r";
    if(do_cache)
    {
        //printf("Response: %s\n", response);
        // airbox put here
        char *key;
        int len = strlen(host) + strlen(path) + 7;
        int aligned_len = len + (AES_LENGTH - (len % AES_LENGTH));
        key =  (char *)malloc(aligned_len);
        char *ekey = (char *)malloc(aligned_len);
        memset (key, 0, aligned_len);
        memset (ekey, 0, aligned_len);
        sprintf(key, "http://%s%s", host, path);
        if(printf) printf("http://%s%s\n", host, path);
        
        encrypt(session_key, (unsigned char*) key, (unsigned char *)ekey, aligned_len);

        int vallen = strlen(respHeader)+strlen(response)+2;
        int aligned_vallen = vallen + (AES_LENGTH - (vallen % AES_LENGTH));
        char *val = (char *) malloc(aligned_vallen);
        char *eval = (char *) malloc(aligned_vallen);
        memset(val, 0, aligned_vallen);
        memset(eval, 0, aligned_vallen);

        sprintf(val, "%s\n\r%s", respHeader, response);

        encrypt(session_key, (unsigned char*) val, (unsigned char *) eval, aligned_vallen);

        if(debug) printf("aligned key len: %d vallen: %d\n", aligned_len, aligned_vallen); 
        if(airbox_sgx_put(ekey, aligned_len, eval, aligned_vallen))
        {
            printf("Issue with put\n");
            //return -2;
        }

    }
    (void) fflush( stdout );
    printf("<< proxy_http\n");
    
}


static void
proxy_ssl( char* method, char* host, char* protocol, FILE* sockrfp, FILE* sockwfp )
    {
    int client_read_fd, server_read_fd, client_write_fd, server_write_fd;
    struct timeval timeout;
    fd_set fdset;
    int maxp1, r;
    char buf[10000];

    /* Return SSL-proxy greeting header. */
    (void) fputs( "HTTP/1.0 200 Connection established\r\n\r\n", stdout );
    (void) fflush( stdout );
    /* Now forward SSL packets in both directions until done. */
    client_read_fd = fileno( stdin );
    server_read_fd = fileno( sockrfp );
    client_write_fd = fileno( stdout );
    server_write_fd = fileno( sockwfp );
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    if ( client_read_fd >= server_read_fd )
    maxp1 = client_read_fd + 1;
    else
    maxp1 = server_read_fd + 1;
    (void) alarm( 0 );
    for (;;)
    {
    FD_ZERO( &fdset );
    FD_SET( client_read_fd, &fdset );
    FD_SET( server_read_fd, &fdset );
    r = select( maxp1, &fdset, (fd_set*) 0, (fd_set*) 0, &timeout );
    if ( r == 0 )
        send_error( 408, "Request Timeout", (char*) 0, "Request timed out." );
    else if ( FD_ISSET( client_read_fd, &fdset ) )
        {
        r = read( client_read_fd, buf, sizeof( buf ) );
        if ( r <= 0 )
        break;
        r = write( server_write_fd, buf, r );
        if ( r <= 0 )
        break;
        }
    else if ( FD_ISSET( server_read_fd, &fdset ) )
        {
        r = read( server_read_fd, buf, sizeof( buf ) );
        if ( r <= 0 )
        break;
        r = write( client_write_fd, buf, r );
        if ( r <= 0 )
        break;
        }
    }
    }


static void
sigcatch( int sig )
{
    send_error( 408, "Request Timeout", (char*) 0, "Request timed out." );
}


static void
trim( char* line )
    {
    int l;

    l = strlen( line );
    while ( line[l-1] == '\n' || line[l-1] == '\r' )
    line[--l] = '\0';
    }


static void
send_error( int status, char* title, char* extra_header, char* text )
    {
    send_headers( status, title, extra_header, "text/html", -1, -1 );
    (void) printf( "\
<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n\
<html>\n\
  <head>\n\
    <meta http-equiv=\"Content-type\" content=\"text/html;charset=UTF-8\">\n\
    <title>%d %s</title>\n\
  </head>\n\
  <body bgcolor=\"#cc9999\" text=\"#000000\" link=\"#2020ff\" vlink=\"#4040cc\">\n\
    <h4>%d %s</h4>\n\n",
    status, title, status, title );
    (void) printf( "%s\n\n", text );
    (void) printf( "\
    <hr>\n\
    <address><a href=\"%s\">%s</a></address>\n\
  </body>\n\
</html>\n",
    SERVER_URL, SERVER_NAME );
    (void) fflush( stdout );
    exit( -3);
    }


static void
send_headers( int status, char* title, char* extra_header, char* mime_type, int length, time_t mod )
    {
    time_t now;
    char timebuf[100];

    (void) printf( "%s %d %s\r\n", PROTOCOL, status, title );
    (void) printf( "Server: %s\r\n", SERVER_NAME );
    now = time( (time_t*) 0 );
    (void) strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &now ) );
    (void) printf( "Date: %s\r\n", timebuf );
    if ( extra_header != (char*) 0 )
    (void) printf( "%s\r\n", extra_header );
    if ( mime_type != (char*) 0 )
    (void) printf( "Content-Type: %s\r\n", mime_type );
    if ( length >= 0 )
    (void) printf( "Content-Length: %d\r\n", length );
    if ( mod != (time_t) -1 )
    {
    (void) strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &mod ) );
    (void) printf( "Last-Modified: %s\r\n", timebuf );
    }
    (void) printf( "Connection: close\r\n" );
    (void) printf( "\r\n" );
    }

int enc_overhead()
{
    unsigned char preq1[32] = "http://www.example.com/00000000";
    unsigned char preq2[32] = "http://www.example.org/00000000";
    unsigned char presp1[1616] = "HTTP/1.1 200 OK\
Cache-Control: max-age=604800\
Content-Type: text/html\
Date: Fri, 12 Feb 2016 07:21:14 GMT\
Etag: \"359670651+gzip+ident\"\
Expires: Fri, 19 Feb 2016 07:21:14 GMT\
Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT\
Server: ECS (mdw/1275)\
Vary: Accept-Encoding\
X-Cache: HIT\
x-ec-custom-error: 1\
Content-Length: 1270\
\
<!doctype html>\
<html>\
<head>\
    <title>Example Domain</title>\
\
    <meta charset=\"utf-8\" />\
    <meta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\" />\
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\
    <style type=\"text/css\">\
    body {\
        background-color: #f0f0f2;\
        margin: 0;\
        padding: 0;\
        font-family: \"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;\
        \
    }\
    div {\
        width: 600px;\
        margin: 5em auto;\
        padding: 50px;\
        background-color: #fff;\
        border-radius: 1em;\
    }\
    a:link, a:visited {\
        color: #38488f;\
        text-decoration: none;\
    }\
    @media (max-width: 700px) {\
        body {\
            background-color: #fff;\
        }\
        div {\
            width: auto;\
            margin: 0 auto;\
            border-radius: 0;\
            padding: 1em;\
        }\
    }\
    </style>\
</head>\
\
<body>\
<div>\
    <h1>Example Domain</h1>\
    <p>This domain is established to be used for illustrative examples in documents. You may use this\
    domain in examples without prior coordination or asking for permission.</p>\
    <p><a href=\"http://www.iana.org/domains/example\">More information...</a></p>\
</div>\
</body>\
</html>";

    unsigned char presp2[1936] = "HTTP/1.1 200 OK\
Cache-Control: max-age=604800\
Content-Type: text/html\
Date: Fri, 12 Feb 2016 07:31:25 GMT\
Etag: \"359670651+gzip+ident\"\
Expires: Fri, 19 Feb 2016 07:31:25 GMT\
Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT\
Server: ECS (mdw/1275)\
Vary: Accept-Encoding\
X-Cache: HIT\
x-ec-custom-error: 1\
Content-Length: 1270\
HTTP/1.1 200 OK\
Cache-Control: max-age=604800\
Content-Type: text/html\
Date: Fri, 12 Feb 2016 07:31:26 GMT\
Etag: \"359670651+gzip+ident\"\
Expires: Fri, 19 Feb 2016 07:31:26 GMT\
Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT\
Server: ECS (mdw/1275)\
Vary: Accept-Encoding\
X-Cache: HIT\
x-ec-custom-error: 1\
Content-Length: 1270\
\
<!doctype html>\
<html>\
<head>\
    <title>Example Domain</title>\
\
    <meta charset=\"utf-8\" />\
    <meta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\" />\
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\
    <style type=\"text/css\">\
    body {\
        background-color: #f0f0f2;\
        margin: 0;\
        padding: 0;\
        font-family: \"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;\
        \
    }\
    div {\
        width: 600px;\
        margin: 5em auto;\
        padding: 50px;\
        background-color: #fff;\
        border-radius: 1em;\
    }\
    a:link, a:visited {\
        color: #38488f;\
        text-decoration: none;\
    }\
    @media (max-width: 700px) {\
        body {\
            background-color: #fff;\
        }\
        div {\
            width: auto;\
            margin: 0 auto;\
            border-radius: 0;\
            padding: 1em;\
        }\
    }\
    </style>\
</head>\
\
<body>\
<div>\
    <h1>Example Domain</h1>\
    <p>This domain is established to be used for illustrative examples in documents. You may use this\
    domain in examples without prior coordination or asking for permission.</p>\
    <p><a href=\"http://www.iana.org/domains/example\">More information...</a></p>\
</div>\
</body>\
</html>";

    unsigned char *ereq1 = (unsigned char *)malloc(32);
    memset(ereq1,0,32);
    unsigned char *eresp1 = (unsigned char *)malloc(1616);
    memset(eresp1,0,32);

    unsigned char *ereq2 = (unsigned char *)malloc(32);
    memset(ereq2,0,32);
    unsigned char *eresp2 = (unsigned char *)malloc(1936);
    memset(eresp2,0,32);

    encrypt(session_key, preq1, ereq1,32);
    encrypt(session_key,preq1, ereq1,32);
    encrypt(session_key,preq1, ereq1,32);

    
    encrypt(session_key, preq2, ereq2,32);
    encrypt(session_key, preq2, ereq2,32);
    encrypt(session_key, preq2, ereq2,32);

    encrypt(session_key, presp1, eresp1,1616); 
    encrypt(session_key, presp2, eresp2,1936); 

    return 0;
}


int read_file(char* path, char** buf)
{
#if 1
	int i = 0;
	FILE *f = NULL;
	if(debug) printf("Trying to open file %s \n", path); 
	f = fopen(path, "r");
	if(!f)
	{
		printf("Unable to open file\n"); 
		return 0;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char* temp = (char *)malloc(fsize+1);
	if(debug) printf("size of read file: %d\n", fsize);
	fread(temp, fsize, 1, f);
	fclose(f);
	temp[fsize] = 0;

	*buf = temp;
#else
	char *retfile = "File content xxxxx";
	int fsize = strlen(retfile);
	printf("size of read file: %d\n", fsize);
	memcpy(*buf, retfile, fsize);
#endif
	return fsize;	
}

int write_file(char* path, char* buf, int len)
{
	int res = 0;
	FILE *f = fopen(path, "w");
	if(!f) printf("Unable to open file to write: %s\n", path);
	res = fwrite(buf, 1, len, f);
	fclose(f);
	return res;
}

int airbox_sgx_get(char* key, int klen, int* rvlen, char** rval)
{
    //char klens[MAX_SIZE_LEN] = { 0 };
    //sprintf(klens,"%d",klen);
 
	char *test = "hello world";
	char value[100] = { 0 };

	char path[MAX_SIZE_PATH] = {0};

	get(global_eid, key, klen, path, MAX_SIZE_PATH);

    if (debug) printf("host received: %s - %d \n", path, strlen(path));

    // TODO: This must be a number of paths and then, we have to do it for all paths serially
    if(strlen(path) > 1) {
        //read from path
	    int i = 0;
        char *fcont = NULL; //= {0};
	    if(debug) printf("Reading file ...\n");
        int bytesread = read_file(path, &fcont);//"File content xxxxx";
        if(debug)  {
		    printf("airbox-sgx-host\n");
		    printf("Nb bytes read: %d\n", bytesread);
		    while(i < bytesread)
			   putc(fcont[i++],stdout);
        }

        int flen = bytesread;
		int vlen;
		char *val;
        vlen = MAX_SIZE_LEN;
		val = (char *)malloc(vlen);
		complete_get(global_eid, fcont, flen, val, vlen);
 
        if(debug) printf("Written C. flen %s \n", flen);

        if(debug) printf("Size to be read: %d \n",vlen);

        if(debug) printf("host received: %d bytes\n", vlen);
        // copy to host
        *rvlen = vlen;
        *rval = val;
	} else {
		printf("Nothing found for this key\n");
		*rvlen = 0;
		*rval = NULL;
	}

    printf("AirBox Get Finished\n");	
	return 0;
}

int airbox_sgx_put(char* key, int klen, char* val, int vlen)
{
    char path[MAX_SIZE_PATH] = {0};
	put(global_eid, key, klen, path, MAX_SIZE_PATH);
    printf("Written K. encrypted key\n");
	
    if(debug) printf("host received: %s\n", path);
	//TODO: this can be a number of paths that we have to write to
	if(strlen(path) > 1) {
		char *retval;
		int retvlen;
		retvlen = 1024;
		retval = (char *)malloc(retvlen);

		complete_put(global_eid, val, vlen, retval, retvlen);

        if(debug) printf("Written V. flen %d\n", vlen);
		
        //if(debug) printf("[Host] Size to be written: %d \n", vlen);

        if(debug) printf("host received: %d bytes\n", retvlen);
		
		// write to file
		//int res = write_file(path, retval, retvlen);
		int res = 0;
		if(debug) printf("%d bytes out of %d written to path: %s\n", res, retvlen, path);

    	printf("AirBox Put Finished\n");	
	}

	return 0;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

#if defined(_MSC_VER)
    if (query_sgx_status() < 0) {
        /* either SGX is disabled, or a reboot is required to enable SGX */
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
#endif 

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Unable to run in enclave\n");
        getchar();
        return -1; 
    }

	//while(!wlFinish)
	//{
		proxy_main();
	//}

	/* Airbox Test */

    /*unsigned char preq[] = "http://www.example.com/000000000";
    unsigned char presp[] = "response to check000000000000000";
    unsigned char check[] = "rrrrrrrrrrrrrrrr0000000000000000";

    unsigned char *ereq = (unsigned char *) malloc(32);
    memset(ereq, 0, 32);
    unsigned char *eresp = (unsigned char *) malloc(32);
    memset(eresp, 0, 32);
    unsigned char *echeck = (unsigned char *) malloc(32);
    memset(echeck, 0, 32);

    printf("Plain Req: %d - %s\nResp: %d - %s\nCheck: %d - %s\n", strlen((char *)preq),preq, strlen((char *)presp), presp, strlen((char *)check), check);

    //encrypt(session_key, preq, ereq, strlen(preq));
    //encrypt(session_key, presp, eresp, strlen(presp));
    encrypt(session_key, preq, ereq, AES_LENGTH*2);
    encrypt(session_key, presp, eresp, AES_LENGTH*2);
    encrypt(session_key, check, echeck, AES_LENGTH*2);
    

	int i = 0;

	printf("---- ereq\n");
	while(i < strlen((char *)preq))
		printf("%x",ereq[i++]);
	printf("\n");
	printf("---- ereq\n");
	
	i = 0;
	printf("---- eresp\n");
	while(i < strlen((char *)presp))
		printf("%x",eresp[i++]);
	printf("\n");
	printf("---- eresp\n");

    char *sgxrval = NULL;
	int sgxrlen = 0;
    if(airbox_sgx_get((char *)ereq, strlen((char *)preq), &sgxrlen, &sgxrval))
    {
        printf("Issue with get\n");
        return -2;
    }
	printf("%d\n", sgxrlen);

    if(airbox_sgx_put((char *)ereq, strlen((char *)preq), (char *)eresp, strlen((char *)preq)))
    {
        printf("Issue with put\n");
        return -2;
    }
    
    if(airbox_sgx_get((char *)echeck, strlen((char *)check), &sgxrlen, &sgxrval))
    {
        printf("Issue with get\n");
        return -2;
    }
    printf("%d\n", sgxrlen);
    if(sgxrlen > 0)
    {
		decrypt(session_key, (unsigned char *)sgxrval, presp, AES_LENGTH*2);
		printf("Response: %s\n",presp);
    }

    if(airbox_sgx_get((char *)ereq, strlen((char *)preq), &sgxrlen, &sgxrval))
    {
        printf("Issue with get\n");
        return -2;
    }
	if (sgxrlen > 0)
	{
    	printf("%d\n", sgxrlen);
		i = 0;
    	printf("---- sgxrval\n");
   		 while(i < sgxrlen)
        	printf("%x",sgxrval[i++]);
    	printf("\n");
    	printf("---- sgxrval\n");

    	decrypt(session_key, (unsigned char *)sgxrval, eresp, AES_LENGTH);
    	printf("Response: %s\n",eresp);
	}*/

	/* Airbox test end */

	//test_init(global_eid);

	//test_access(global_eid);
	
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}
