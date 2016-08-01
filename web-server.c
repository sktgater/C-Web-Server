#include <sys/wait.h>   /* for waitpid() */
#include <sys/stat.h>   /* for stat() */
#include <sys/types.h>  /* for socket(), waitpid() and stat() */
#include <sys/socket.h> /* for socket(), bind(), listen() and accept() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <netdb.h>      /* for gethostbyname() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() and strlen() */
#include <unistd.h>     /* for close(), fork() and stat() */
#include <stdio.h>      /* for printf() */

#define MAXPENDING 5
#define BUFSIZE 4096

/* Print out error message and terminate the program */
void die(char *errMsg)
{
    perror(errMsg);
    exit(1);
}

/* Handle the client */
int HandleTCPClient
(int clntSock, int mdbSock, struct sockaddr_in clntAddr, char *root);

/* Server static content */
int HandleStatic
(int clntSock, char *root, char *method, char *uri, char *httpv, char *ipaddr);

/* Server dynamic content */
int HandleDynamic
(int clntSock, int mdbSock, char *method, char *uri, char *httpv, char *ipaddr);

/* http-server */
int main(int argc, char **argv)
{
    int serSock;                        /* Socket descriptor for server */
    int mdbSock;                        /* Socket descriptor for mdb-lookup-server */
    int clntSock;                       /* Socket descriptor for client */
    struct sockaddr_in serAddr;         /* Local address */
    struct sockaddr_in mdbAddr;         /* mdb-lookup-server address */
    struct sockaddr_in clntAddr;        /* Client address */
    unsigned int clntLen;               /* Length of client address data structure */
    unsigned short serPort;             /* Server port */
    unsigned short mdbPort;             /* mdb-lookup-server port */
    char *mdbHost;                      /* mdb-lookup-server host name */
    
    if (argc != 5)      /* Test for correct number of arguments */
    {
        printf("usage: %s <server_port> <web_root> "
                "<mdb-lookup-host> <mdb-lookup-port>\n",
                argv[0]);
        exit(1);
    }

    char *webRoot = argv[2];    /* 2nd arg: root path of the web */
    mdbHost = argv[3];          /* 3rd arg: mdb-lookup-server host name */
    serPort = atoi(argv[1]);    /* 1st arg: server port */
    mdbPort = atoi(argv[4]);    /* 4th arg: mdb-lookup-server port */

    /* Get mdb-lookup-server IP from its host name*/
    struct hostent *he;
    if ((he = gethostbyname(mdbHost)) == NULL)
        die("gethostbyname() fail\n");
    char *mdbIP = inet_ntoa(*(struct in_addr *)he->h_addr);

    /* Construct local address structure */
    memset(&serAddr, 0, sizeof(serAddr));        // Zero out structure
    serAddr.sin_family = AF_INET;               // Internet address family
    serAddr.sin_port = htons(serPort);          // Local port
    serAddr.sin_addr.s_addr = htonl(INADDR_ANY);// Any incoming interface

    /* Construct mdb-lookup-server address structure */
    memset(&mdbAddr, 0, sizeof(mdbAddr));        // Zero out structure
    mdbAddr.sin_family = AF_INET;               // Internet address family
    mdbAddr.sin_port = htons(mdbPort);          // mdb-lookup-server port
    mdbAddr.sin_addr.s_addr = inet_addr(mdbIP); // mdb-lookup-server IP address

    /* Construct sockets */
    if ((serSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0               // Socket for incoming connection
            || (mdbSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)       // Socket for connecting to mdb-lookup-server
        die("socket() fail");

    /* Bind to the local address */
    if (bind(serSock, (struct sockaddr *) &serAddr, sizeof(serAddr)) < 0)
        die("bind() fail");

    /* Mark the socket so it will listen for incoming connections */
    if (listen(serSock, MAXPENDING) < 0)
        die("listen() fail");

    /* Establish the connection to the mdb-lookup-server */
    if (connect(mdbSock, (struct sockaddr *) &mdbAddr, sizeof(mdbAddr)) < 0)
        die("connect() fail");

    pid_t pid;  // Process ID

    for ( ; ; )
    {
        while ((pid = waitpid((pid_t) -1, NULL, WNOHANG)) > 0)  // avoid zombie process
            ;

        /* Set the size of the in-out parameter */
        clntLen = sizeof(clntAddr);

        /* Wait for a client to connect */
        if ((clntSock = accept(serSock, (struct sockaddr *) &clntAddr,
                        &clntLen)) < 0)
        {
            perror("accept() fail");
            close(clntSock);
            continue;
        }

        /* clntSock is connected to a client */

        /* fork a child process to handle the client */
        pid = fork();

        if (pid < 0)
            die("fork() fail");
        else if (pid == 0)
        {
                //child process
            return HandleTCPClient(clntSock, mdbSock, clntAddr, webRoot);      // return after the client has been handled 
        }
        else
            close(clntSock);   // parent process will close the client socket and continue on to the next iteration of the loop
    }

    close(mdbSock);
    close(serSock);
    return 0;
}

char msg501[BUFSIZE];           /* HTTP status code 501 */
char msg400[BUFSIZE];           /* HTTP status code 400 */
char msg403[BUFSIZE];           /* HTTP status code 403 */
char msg404[BUFSIZE];           /* HTTP status code 404 */

/* Log each client IP address and request to stdout */ 
void logIP
(char *ipaddr, char *method, char *uri, char *httpv, char *msg)
{
    printf("%s \"%s %s %s\" %s\n", 
            ipaddr, method, uri, httpv, msg);
}

/* Handle the TCP Client */
int HandleTCPClient
(int clntSock, int mdbSock, struct sockaddr_in clntAddr, char *root)
{
    /* Ignore SIGPIPE so that we don't terminate when we call */
    /* send() on a disconnected socket */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        perror("signal() fail");
        return 1;
    }

    /* Wrap the socket with FILE * so we can read the socket using fgets() */
    FILE *input = fdopen(clntSock, "r");
    if (input == NULL)                          /* Test for error caused by fdopen() */
    {
        perror("fdopen() fail");
        return 1;
    }

    char buf[BUFSIZE];                          /* Storage for HTTP request */

    if (fgets(buf, BUFSIZE, input) == NULL)     /* Test for error caused by fgets() */
    {
        if (ferror(input))
        {
            perror("IO error");
            fclose(input);
        }
        else
        {
            perror("Client terminated connection without sending file");
            fclose(input);
        }
        return 1;
    }
    
    /* Parse HTTP request into three parts */
    char *token_separators = "\t \r\n";
    char *method, *requestURI, *httpVersion;
    if ((method = strtok(buf, token_separators)) == NULL ||
            (requestURI = strtok(NULL, token_separators)) == NULL ||
            (httpVersion = strtok(NULL, token_separators)) == NULL)
    {
        perror("Not correct form for HTTP request.\n");
        fclose(input);
        return 1;
    }
    
    /* Client IP Address */
    char *ipAddr = inet_ntoa(clntAddr.sin_addr);

    /* Store each HTTP response into corresponding array */
    snprintf(msg501, BUFSIZE, 
            "HTTP/1.0 501 Not Implemented\r\n"
            "\r\n"
            "<html><body><h1>501 Not Implemented</h1></body></html>\r\n");
    snprintf(msg400, BUFSIZE,
            "HTTP/1.0 400 Bad Request\r\n"
            "\r\n"
            "<html><body><h1>400 Bad Request</h1></body></html>\r\n");
    snprintf(msg403, BUFSIZE,
            "HTTP/1.0 403 Forbidden\r\n"
            "\r\n"
            "<html><body><h1>403 Forbidden</h1></body></html>\r\n");
    snprintf(msg404, BUFSIZE,
            "HTTP/1.0 404 Not Found\r\n"
            "\r\n"
            "<html><body><h1>404 Not Found</h1></body></html>\r\n");

    /* Not Implement: not GET method, nor HTTP/1.0 neither HTTP/1.1 */
    if (strcmp(method, "GET") != 0 || 
            (strcmp(httpVersion, "HTTP/1.0") != 0 && strcmp(httpVersion, "HTTP/1.1") != 0))
    {
        logIP(ipAddr, method, requestURI, httpVersion, "501 Not Implemented");
        if (send(clntSock, msg501, strlen(msg501), 0) != strlen(msg501))        /* send HTTP response 501 */
            perror("send() fail");
        fclose(input);
        return 1;
    }

    /* Bad Request: not start with '/', contain '/../', end with '/..' */
    if (requestURI[0] != '/' || 
            strstr(requestURI, "/../") != NULL || 
            strcmp(requestURI + strlen(requestURI) - 3, "/..") == 0)
    {
        logIP(ipAddr, method, requestURI, httpVersion, "400 Bad Request");
        if (send(clntSock, msg400, strlen(msg400), 0) != strlen(msg400))        /* send HTTP response 400 */
            perror("send() fail");
        fclose(input);
        return 1;
    }

    /* If requestURI starts with '/mdb-lookup', 
     * serve dynamic content, otherwise,
     * serve static content. */
    int status = 0;
    if (strncmp(requestURI, "/mdb-lookup", 11) == 0)
    {
        status = HandleDynamic(clntSock, mdbSock, method, requestURI, httpVersion, ipAddr);
    }
    else
    {
        status = HandleStatic(clntSock, root, method, requestURI, httpVersion, ipAddr);
    }
   
    fclose(input);       /* Close client socket */
    return (status == 0) ? 0 : 1;
}

/* Serve static content for TCP client */
int HandleStatic
(int clntSock, char *root, char *method, char *uri, char *httpv, char *ipaddr)
{
    char buf[BUFSIZE];          /* storage for HTTP response */

    int urilen = strlen(uri);
    /* Append 'index.html' to requestURI if it ends with '/' */
    if (uri[urilen-1] == '/')
        strcat(uri, "index.html");

    /* Remove ended '/' from root */
    if (root[strlen(root)-1] == '/')
        root[strlen(root)-1] = '\0';
    /* root: absolute path of the requested file */
    strcat(root, uri);
    
    FILE *fd = fopen(root, "rb");
    if (fd == NULL || ferror(fd))     /* Test for error caused by fopen() */
    {
        logIP(ipaddr, method, uri, httpv, "404 Not Found");
        /* Send "404 Not Found" if cannot open the file */
        if (send(clntSock, msg404, strlen(msg404), 0) != strlen(msg404))
            perror("send() fail\n");
        return 1;
    }
    /* Test if fd point to a file or a directory */
    struct stat fd_t;
    stat(root, &fd_t);
    if ((fd_t.st_mode & S_IFMT) == S_IFDIR)
    {
        logIP(ipaddr, method, uri, httpv, "403 Forbidden");
        if (send(clntSock, msg403, strlen(msg403), 0) != strlen(msg403))
            perror("send() fail\n");
        fclose(fd);
        return 1;
    }
    
    /* Legitimate HTTP request at this point, ready to responde */
    logIP(ipaddr, method, uri, httpv, "200 OK");

    /* Zero out the buffer */
    memset(buf, 0, sizeof(buf));

    /* buf: initial line and blank line of HTTP response */
    int n = snprintf(buf, sizeof(buf), "HTTP/1.0 200 OK\r\n\r\n");

    /* Send back HTTP response:
     * initial line, 
     * blank line,
     * requested file in message body */
    do
    {
        if (send(clntSock, buf, n, 0) != n)
        {
            perror("send() fail");
            fclose(fd);
            return 1;
        }
        memset(buf, 0, sizeof(buf));
    }while((n = fread(buf, 1, sizeof(buf), fd)) > 0);   // read all the content in requested file

    fclose(fd); /* Close requested file */
    return 0;
}

/* Serve dynamic content for TCP client */
int HandleDynamic
(int clntSock, int mdbSock, char *method, char *uri, char *httpv, char *ipaddr)
{
    const char *msg200 = "HTTP/1.0 200 OK\r\n\r\n";     /* Message for HTTP status code 200 */
    const char *htmlh = "<html>\n<body>\n";
    const char *htmlt = "</html>\n</body>\n";
    const char *form = 
        "<h1>mdb-lookup</h1>\n"
        "<p>\n"
        "<form method=GET action=/mdb-lookup>\n"
        "lookup: <input type=text name=key>\n"
        "<input type=submit>\n"
        "</form>\n"
        "<p>\n";

    char buf[BUFSIZE];          /* Buffer for HTTP response */
    memset(buf, 0, sizeof(buf));/* Zero out the buffer */

    /* If the requested URI is exactly '/mdb-lookup', 
     * send back the form only;
     * if the requested URI starts with '/mdb-lookup?key=', 
     * send back the the lookup result table in addition to the form;
     * otherwise, nothing. */
    int n = 0;          /* The number of bytes send to the client */
    if (strcmp(uri, "/mdb-lookup") == 0)
    {
        logIP(ipaddr, method, uri, httpv, "200 OK");
        n = sprintf(buf, "%s%s%s%s", msg200, htmlh, form, htmlt);
        if (send(clntSock, buf, n, 0) != n)
        {
            perror("send() fail\n");
            return 1;
        }
    }
    else if (strncmp(uri, "/mdb-lookup?key=", 16) == 0)
    {
        logIP(ipaddr, method, uri, httpv, "200 OK");
        char *key = uri + 16;           /* Content of the key */
        int keylen = strlen(key);       /* Length of the key */
        key[keylen] = '\n';             /* Append '\n' to the end of the key */
        key[keylen+1] = '\0';           /* Terminate string key */
        if (send(mdbSock, key, strlen(key), 0) != strlen(key))
        {
            perror("send() fail\n");
            return 1;
        }

        /* Wrap mdbSock with FILE *, so we can use fgets() to read the lookup result */
        FILE *fd = fdopen(mdbSock, "r");
        if (fd == NULL || ferror(fd))
        {
            perror("fdopen() fail\n");
            return 1;
        }

        n = sprintf(buf, "%s%s%s", msg200, htmlh, form);
        if (send(clntSock, buf, n, 0) != n)
        {
            perror("send() fail\n");
            return 1;
        }
        memset(buf, 0, sizeof(buf));

        while (strcmp(fgets(buf, sizeof(buf), fd), "\n") != 0)
        {
            if (send(clntSock, buf, strlen(buf), 0) != strlen(buf))
            {
                perror("send() fail\n");
                return 1;
            }
            memset(buf, 0, sizeof(buf));
        }

        n = sprintf(buf, "%s", htmlt);
        if (send(clntSock, buf, n, 0) != n)
        {
            perror("send() fail\n");
            return 1;
        }

        fclose(fd);
    }
    else
    {
        logIP(ipaddr, method, uri, httpv, "501 Not Implemented");
        if (send(clntSock, msg501, strlen(msg501), 0) != strlen(msg501))        /* send HTTP response 501 */
            perror("send() fail");
        return 1;
    }

    return 0;
}
