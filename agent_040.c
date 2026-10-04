#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#define PORT 9410
#define SID "0403"
#define AUTH_TOKEN "OPS-3040"

#define STORAGE_DIR "./agentfiles/IT24103040"
#define LOG_FILE "remoteops_IT24103040.log"

#define MAX_LINE 8192
#define MAX_FILE_SIZE (10 * 1024 * 1024)
#define MONITOR_INTERVAL 3

typedef struct
{
    int fd;
    char client_ip[INET_ADDRSTRLEN];

    pthread_mutex_t monitor_mutex;

    int monitor_running;
    pthread_t monitor_thread;
    int monitor_thread_created;

    unsigned short udp_port;

} client_session_t;

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static volatile sig_atomic_t server_running = 1;


/* ---------------------------------------------------------
   SIGNAL HANDLER
   --------------------------------------------------------- */

static void handle_signal(int sig)
{
    (void)sig;
    server_running = 0;
}


/* ---------------------------------------------------------
   LOGGING
   --------------------------------------------------------- */

static void log_event(const char *client_ip, const char *event)
{
    pthread_mutex_lock(&log_mutex);

    FILE *fp = fopen(LOG_FILE, "a");

    if (fp != NULL)
    {
        time_t now = time(NULL);

        struct tm current_time;

        localtime_r(&now, &current_time);

        char timestamp[32];

        strftime(
            timestamp,
            sizeof(timestamp),
            "%Y-%m-%d %H:%M:%S",
            &current_time
        );

        fprintf(
            fp,
            "[%s] [%s] %s\n",
            timestamp,
            client_ip,
            event
        );

        fclose(fp);
    }

    pthread_mutex_unlock(&log_mutex);
}


/* ---------------------------------------------------------
   SEND ALL
   Ensures all bytes are transmitted.
   --------------------------------------------------------- */

static int send_all(int fd, const void *buffer, size_t length)
{
    const char *ptr = buffer;

    while (length > 0)
    {
        ssize_t sent = send(fd, ptr, length, 0);

        if (sent < 0)
        {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (sent == 0)
            return -1;

        ptr += sent;
        length -= (size_t)sent;
    }

    return 0;
}


/* ---------------------------------------------------------
   RECEIVE EXACT NUMBER OF BYTES
   --------------------------------------------------------- */

static int recv_exact(int fd, void *buffer, size_t length)
{
    char *ptr = buffer;

    while (length > 0)
    {
        ssize_t received = recv(fd, ptr, length, 0);

        if (received < 0)
        {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (received == 0)
            return 0;

        ptr += received;
        length -= (size_t)received;
    }

    return 1;
}


/* ---------------------------------------------------------
   RECEIVE ONE LINE
   --------------------------------------------------------- */

static int recv_line(int fd, char *buffer, size_t size)
{
    size_t index = 0;

    while (index + 1 < size)
    {
        char c;

        ssize_t received = recv(fd, &c, 1, 0);

        if (received < 0)
        {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (received == 0)
            return 0;

        if (c == '\n')
        {
            buffer[index] = '\0';

            if (index > 0 && buffer[index - 1] == '\r')
                buffer[index - 1] = '\0';

            return 1;
        }

        buffer[index++] = c;
    }

    buffer[size - 1] = '\0';

    return -2;
}


/* ---------------------------------------------------------
   SEND RESPONSE
   Every response receives SID:0403
   --------------------------------------------------------- */

static int send_response(int fd, const char *format, ...)
{
    char body[MAX_LINE - 64];
    char response[MAX_LINE];

    va_list args;

    va_start(args, format);

    vsnprintf(
        body,
        sizeof(body),
        format,
        args
    );

    va_end(args);

    snprintf(
        response,
        sizeof(response),
        "%s SID:%s\n",
        body,
        SID
    );

    return send_all(
        fd,
        response,
        strlen(response)
    );
}


/* ---------------------------------------------------------
   CREATE STORAGE DIRECTORY
   --------------------------------------------------------- */

static int ensure_storage(void)
{
    if (mkdir("./agentfiles", 0755) < 0 &&
        errno != EEXIST)
    {
        return -1;
    }

    if (mkdir(STORAGE_DIR, 0755) < 0 &&
        errno != EEXIST)
    {
        return -1;
    }

    return 0;
}


/* ---------------------------------------------------------
   FILE NAME SECURITY CHECK
   Prevent path traversal.
   --------------------------------------------------------- */

static int safe_filename(const char *filename)
{
    if (filename == NULL)
        return 0;

    if (filename[0] == '\0')
        return 0;

    if (strlen(filename) > 255)
        return 0;

    if (strstr(filename, "..") != NULL)
        return 0;

    if (strchr(filename, '/') != NULL)
        return 0;

    if (strchr(filename, '\\') != NULL)
        return 0;

    return 1;
}


/* ---------------------------------------------------------
   SYSTEM INFORMATION
   CPU load
   Memory usage
   Uptime
   --------------------------------------------------------- */

static void get_sysinfo(char *output, size_t size)
{
    double cpu_load = 0.0;

    long mem_total = 0;
    long mem_available = 0;

    double uptime = 0.0;


    /* CPU load */

    FILE *fp = fopen("/proc/loadavg", "r");

    if (fp != NULL)
    {
        fscanf(fp, "%lf", &cpu_load);

        fclose(fp);
    }


    /* Memory */

    fp = fopen("/proc/meminfo", "r");

    if (fp != NULL)
    {
        char key[64];

        long value;

        char unit[16];

        while (
            fscanf(
                fp,
                "%63s %ld %15s",
                key,
                &value,
                unit
            ) == 3
        )
        {
            if (strcmp(key, "MemTotal:") == 0)
            {
                mem_total = value;
            }
            else if (
                strcmp(key, "MemAvailable:") == 0
            )
            {
                mem_available = value;
            }
        }

        fclose(fp);
    }


    /* Uptime */

    fp = fopen("/proc/uptime", "r");

    if (fp != NULL)
    {
        fscanf(fp, "%lf", &uptime);

        fclose(fp);
    }


    long memory_used_mb =
        (mem_total - mem_available) / 1024;


    snprintf(
        output,
        size,
        "%.2f %ld %ld",
        cpu_load,
        memory_used_mb,
        (long)uptime
    );
}


/* ---------------------------------------------------------
   PROCESS LIST
   --------------------------------------------------------- */

static void get_processes(char *output, size_t size)
{
    FILE *fp = popen(
        "ps -eo pid=,comm= --sort=pid | head -30",
        "r"
    );

    if (fp == NULL)
    {
        snprintf(
            output,
            size,
            "PROCESS_LIST_ERROR"
        );

        return;
    }


    size_t used = 0;

    int first = 1;

    char line[256];


    while (fgets(line, sizeof(line), fp))
    {
        line[strcspn(line, "\r\n")] = '\0';


        char *ptr = line;

        while (*ptr == ' ')
            ptr++;


        if (*ptr == '\0')
            continue;


        size_t length = strlen(ptr);


        if (!first)
        {
            if (used + 1 >= size)
                break;

            output[used++] = ',';
        }


        if (used + length >= size - 1)
            break;


        memcpy(
            output + used,
            ptr,
            length
        );

        used += length;

        first = 0;
    }


    output[used] = '\0';

    pclose(fp);
}


/* ---------------------------------------------------------
   EXEC WHITELIST
   Only the five commands from assignment.
   --------------------------------------------------------- */

static int execute_allowed(
    const char *name,
    char *output,
    size_t size
)
{
    const char *command = NULL;


    if (strcmp(name, "DATE") == 0)
    {
        command = "date";
    }
    else if (strcmp(name, "UPTIME") == 0)
    {
        command = "uptime";
    }
    else if (strcmp(name, "DISKFREE") == 0)
    {
        command = "df -h .";
    }
    else if (strcmp(name, "HOSTNAME") == 0)
    {
        command = "hostname";
    }
    else if (strcmp(name, "WHOAMI") == 0)
    {
        command = "whoami";
    }
    else
    {
        return 0;
    }


    FILE *fp = popen(command, "r");

    if (fp == NULL)
    {
        snprintf(
            output,
            size,
            "EXECUTION_ERROR"
        );

        return 1;
    }


    size_t used = 0;

    char line[512];


    while (
        fgets(line, sizeof(line), fp) != NULL &&
        used + 1 < size
    )
    {
        for (
            size_t i = 0;
            line[i] != '\0' && used + 1 < size;
            i++
        )
        {
            char c = line[i];

            if (
                c == '\n' ||
                c == '\r' ||
                c == '\t'
            )
            {
                c = ' ';
            }

            output[used++] = c;
        }
    }


    while (
        used > 0 &&
        output[used - 1] == ' '
    )
    {
        used--;
    }


    output[used] = '\0';

    pclose(fp);

    return 1;
}


/* ---------------------------------------------------------
   UDP MONITOR THREAD
   --------------------------------------------------------- */

static void *monitor_loop(void *argument)
{
    client_session_t *session = argument;


    int udp_fd = socket(
        AF_INET,
        SOCK_DGRAM,
        0
    );

    if (udp_fd < 0)
        return NULL;


    struct sockaddr_in destination;

    memset(
        &destination,
        0,
        sizeof(destination)
    );


    destination.sin_family = AF_INET;

    destination.sin_port =
        htons(session->udp_port);


    if (
        inet_pton(
            AF_INET,
            session->client_ip,
            &destination.sin_addr
        ) != 1
    )
    {
        close(udp_fd);

        return NULL;
    }


    while (1)
    {
        pthread_mutex_lock(
            &session->monitor_mutex
        );

        int running =
            session->monitor_running;

        pthread_mutex_unlock(
            &session->monitor_mutex
        );


        if (!running)
            break;


        char statistics[256];

        get_sysinfo(
            statistics,
            sizeof(statistics)
        );


        char datagram[512];

        snprintf(
            datagram,
            sizeof(datagram),
            "SYSINFO %s SID:%s\n",
            statistics,
            SID
        );


        sendto(
            udp_fd,
            datagram,
            strlen(datagram),
            0,
            (struct sockaddr *)&destination,
            sizeof(destination)
        );


        sleep(MONITOR_INTERVAL);
    }


    close(udp_fd);

    return NULL;
}


/* ---------------------------------------------------------
   STOP MONITOR
   --------------------------------------------------------- */

static void stop_monitor(client_session_t *session)
{
    pthread_mutex_lock(
        &session->monitor_mutex
    );

    int was_running =
        session->monitor_running;

    session->monitor_running = 0;

    pthread_mutex_unlock(
        &session->monitor_mutex
    );


    if (
        was_running &&
        session->monitor_thread_created
    )
    {
        pthread_join(
            session->monitor_thread,
            NULL
        );

        session->monitor_thread_created = 0;
    }
}


/* ---------------------------------------------------------
   PUT FILE
   --------------------------------------------------------- */

static void handle_put(
    client_session_t *session,
    const char *filename,
    unsigned long long filesize
)
{
    if (!safe_filename(filename))
    {
        send_response(
            session->fd,
            "ERR 003 INVALID_FILENAME"
        );

        log_event(
            session->client_ip,
            "PUT rejected: invalid filename"
        );

        return;
    }


    if (filesize > MAX_FILE_SIZE)
    {
        send_response(
            session->fd,
            "ERR 004 FILE_TOO_LARGE"
        );

        log_event(
            session->client_ip,
            "PUT rejected: file too large"
        );

        return;
    }


    char path[512];

    snprintf(
        path,
        sizeof(path),
        "%s/%s",
        STORAGE_DIR,
        filename
    );


    FILE *fp = fopen(path, "wb");

    if (fp == NULL)
    {
        send_response(
            session->fd,
            "ERR 006 FILE_WRITE_ERROR"
        );

        return;
    }


    char buffer[8192];

    unsigned long long remaining =
        filesize;

    int success = 1;


    while (remaining > 0)
    {
        size_t amount =
            remaining > sizeof(buffer)
                ? sizeof(buffer)
                : (size_t)remaining;


        int result =
            recv_exact(
                session->fd,
                buffer,
                amount
            );


        if (result != 1)
        {
            success = 0;

            break;
        }


        if (
            fwrite(
                buffer,
                1,
                amount,
                fp
            ) != amount
        )
        {
            success = 0;

            break;
        }


        remaining -= amount;
    }


    fclose(fp);


    if (!success)
    {
        remove(path);

        log_event(
            session->client_ip,
            "PUT failed during transfer"
        );

        return;
    }


    char event[512];

    snprintf(
        event,
        sizeof(event),
        "PUT %s %llu bytes",
        filename,
        filesize
    );


    log_event(
        session->client_ip,
        event
    );


    send_response(
        session->fd,
        "OK FILE_RECEIVED %s",
        filename
    );
}


/* ---------------------------------------------------------
   GET FILE
   --------------------------------------------------------- */

static void handle_get(
    client_session_t *session,
    const char *filename
)
{
    if (!safe_filename(filename))
    {
        send_response(
            session->fd,
            "ERR 005 FILE_NOT_FOUND"
        );

        return;
    }


    char path[512];

    snprintf(
        path,
        sizeof(path),
        "%s/%s",
        STORAGE_DIR,
        filename
    );


    FILE *fp = fopen(path, "rb");

    if (fp == NULL)
    {
        send_response(
            session->fd,
            "ERR 005 FILE_NOT_FOUND"
        );

        log_event(
            session->client_ip,
            "GET file not found"
        );

        return;
    }


    fseek(fp, 0, SEEK_END);

    long filesize = ftell(fp);

    rewind(fp);


    if (filesize < 0)
    {
        fclose(fp);

        send_response(
            session->fd,
            "ERR 006 FILE_READ_ERROR"
        );

        return;
    }


    char header[512];

    snprintf(
        header,
        sizeof(header),
        "OK FILE_SEND %s %ld SID:%s\n",
        filename,
        filesize,
        SID
    );


    if (
        send_all(
            session->fd,
            header,
            strlen(header)
        ) < 0
    )
    {
        fclose(fp);

        return;
    }


    char buffer[8192];

    size_t bytes;


    while (
        (bytes = fread(
            buffer,
            1,
            sizeof(buffer),
            fp
        )) > 0
    )
    {
        if (
            send_all(
                session->fd,
                buffer,
                bytes
            ) < 0
        )
        {
            fclose(fp);

            return;
        }
    }


    fclose(fp);


    char event[512];

    snprintf(
        event,
        sizeof(event),
        "GET %s %ld bytes",
        filename,
        filesize
    );


    log_event(
        session->client_ip,
        event
    );
}


/* ---------------------------------------------------------
   CLIENT HANDLER THREAD
   --------------------------------------------------------- */

static void *client_handler(void *argument)
{
    client_session_t *session = argument;

    char line[MAX_LINE];

    int authenticated = 0;


    log_event(
        session->client_ip,
        "Connection accepted"
    );


    while (server_running)
    {
        int result =
            recv_line(
                session->fd,
                line,
                sizeof(line)
            );


        if (result == 0)
            break;


        if (result < 0)
        {
            log_event(
                session->client_ip,
                "Connection error"
            );

            break;
        }


        /* ---------------------------------------------
           AUTHENTICATION
           --------------------------------------------- */

        if (!authenticated)
        {
            if (
                strncmp(
                    line,
                    "AUTH ",
                    5
                ) == 0
            )
            {
                const char *token =
                    line + 5;


                if (
                    strcmp(
                        token,
                        AUTH_TOKEN
                    ) == 0
                )
                {
                    authenticated = 1;


                    send_response(
                        session->fd,
                        "OK AUTHENTICATED"
                    );


                    log_event(
                        session->client_ip,
                        "AUTH successful"
                    );
                }
                else
                {
                    send_response(
                        session->fd,
                        "ERR 001 AUTH_FAILED"
                    );


                    log_event(
                        session->client_ip,
                        "AUTH failed"
                    );
                }
            }
            else
            {
                send_response(
                    session->fd,
                    "ERR 001 AUTH_FAILED"
                );


                log_event(
                    session->client_ip,
                    "Rejected command before AUTH"
                );
            }


            continue;
        }


        /* Log command */

        log_event(
            session->client_ip,
            line
        );


        /* ---------------------------------------------
           SYSINFO
           --------------------------------------------- */

        if (
            strcmp(
                line,
                "SYSINFO"
            ) == 0
        )
        {
            char information[256];

            get_sysinfo(
                information,
                sizeof(information)
            );


            send_response(
                session->fd,
                "OK SYSINFO %s",
                information
            );
        }


        /* ---------------------------------------------
           LISTPROC
           --------------------------------------------- */

        else if (
            strcmp(
                line,
                "LISTPROC"
            ) == 0
        )
        {
            char processes[6000];

            get_processes(
                processes,
                sizeof(processes)
            );


            send_response(
                session->fd,
                "OK PROCS %s",
                processes
            );
        }


        /* ---------------------------------------------
           EXEC
           --------------------------------------------- */

        else if (
            strncmp(
                line,
                "EXEC ",
                5
            ) == 0
        )
        {
            const char *name =
                line + 5;


            char output[2048];


            if (
                execute_allowed(
                    name,
                    output,
                    sizeof(output)
                )
            )
            {
                send_response(
                    session->fd,
                    "OK EXEC_RESULT %s",
                    output
                );
            }
            else
            {
                send_response(
                    session->fd,
                    "ERR 002 COMMAND_NOT_ALLOWED"
                );
            }
        }


        /* ---------------------------------------------
           PUT
           --------------------------------------------- */

        else if (
            strncmp(
                line,
                "PUT ",
                4
            ) == 0
        )
        {
            char filename[256];

            unsigned long long filesize;


            if (
                sscanf(
                    line + 4,
                    "%255s %llu",
                    filename,
                    &filesize
                ) != 2
            )
            {
                send_response(
                    session->fd,
                    "ERR 003 INVALID_PUT"
                );

                continue;
            }


            handle_put(
                session,
                filename,
                filesize
            );
        }


        /* ---------------------------------------------
           GET
           --------------------------------------------- */

        else if (
            strncmp(
                line,
                "GET ",
                4
            ) == 0
        )
        {
            char filename[256];


            if (
                sscanf(
                    line + 4,
                    "%255s",
                    filename
                ) != 1
            )
            {
                send_response(
                    session->fd,
                    "ERR 005 FILE_NOT_FOUND"
                );

                continue;
            }


            handle_get(
                session,
                filename
            );
        }


        /* ---------------------------------------------
           MONITOR STOP
           --------------------------------------------- */

        else if (
            strcmp(
                line,
                "MONITOR STOP"
            ) == 0
        )
        {
            stop_monitor(session);


            send_response(
                session->fd,
                "OK MONITOR_STOPPED"
            );


            log_event(
                session->client_ip,
                "MONITOR STOP"
            );
        }


        /* ---------------------------------------------
           MONITOR START
           --------------------------------------------- */

        else if (
            strncmp(
                line,
                "MONITOR START ",
                14
            ) == 0
        )
        {
            unsigned int port;


            if (
                sscanf(
                    line + 14,
                    "%u",
                    &port
                ) != 1 ||
                port == 0 ||
                port > 65535
            )
            {
                send_response(
                    session->fd,
                    "ERR 007 INVALID_UDP_PORT"
                );

                continue;
            }


            stop_monitor(session);


            session->udp_port =
                (unsigned short)port;


            pthread_mutex_lock(
                &session->monitor_mutex
            );

            session->monitor_running = 1;

            pthread_mutex_unlock(
                &session->monitor_mutex
            );


            if (
                pthread_create(
                    &session->monitor_thread,
                    NULL,
                    monitor_loop,
                    session
                ) != 0
            )
            {
                pthread_mutex_lock(
                    &session->monitor_mutex
                );

                session->monitor_running = 0;

                pthread_mutex_unlock(
                    &session->monitor_mutex
                );


                send_response(
                    session->fd,
                    "ERR 008 MONITOR_START_FAILED"
                );
            }
            else
            {
                session->monitor_thread_created = 1;


                send_response(
                    session->fd,
                    "OK MONITOR_STARTED"
                );


                log_event(
                    session->client_ip,
                    "MONITOR START"
                );
            }
        }


        /* ---------------------------------------------
           QUIT
           --------------------------------------------- */

        else if (
            strcmp(
                line,
                "QUIT"
            ) == 0
        )
        {
            stop_monitor(session);


            send_response(
                session->fd,
                "OK BYE"
            );


            log_event(
                session->client_ip,
                "QUIT"
            );


            break;
        }


        /* ---------------------------------------------
           UNKNOWN
           --------------------------------------------- */

        else
        {
            send_response(
                session->fd,
                "ERR 009 UNKNOWN_COMMAND"
            );
        }
    }


    stop_monitor(session);


    close(session->fd);


    log_event(
        session->client_ip,
        "Connection closed"
    );


    pthread_mutex_destroy(
        &session->monitor_mutex
    );


    free(session);


    return NULL;
}


/* ---------------------------------------------------------
   MAIN AGENT
   --------------------------------------------------------- */

int main(void)
{
    signal(
        SIGPIPE,
        SIG_IGN
    );

    signal(
        SIGINT,
        handle_signal
    );

    signal(
        SIGTERM,
        handle_signal
    );


    if (
        ensure_storage() < 0
    )
    {
        perror(
            "Storage setup"
        );

        return EXIT_FAILURE;
    }


    int server_fd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );


    if (server_fd < 0)
    {
        perror("socket");

        return EXIT_FAILURE;
    }


    int option = 1;


    setsockopt(
        server_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &option,
        sizeof(option)
    );


    struct sockaddr_in address;

    memset(
        &address,
        0,
        sizeof(address)
    );


    address.sin_family =
        AF_INET;

    address.sin_addr.s_addr =
        htonl(INADDR_ANY);

    address.sin_port =
        htons(PORT);


    if (
        bind(
            server_fd,
            (struct sockaddr *)&address,
            sizeof(address)
        ) < 0
    )
    {
        perror("bind");

        close(server_fd);

        return EXIT_FAILURE;
    }


    if (
        listen(
            server_fd,
            10
        ) < 0
    )
    {
        perror("listen");

        close(server_fd);

        return EXIT_FAILURE;
    }


    printf(
        "====================================\n"
    );

    printf(
        "RemoteOps Agent\n"
    );

    printf(
        "====================================\n"
    );

    printf(
        "Registration : IT24103040\n"
    );

    printf(
        "TCP Port     : 9410\n"
    );

    printf(
        "SID          : 0403\n"
    );

    printf(
        "Storage      : %s\n",
        STORAGE_DIR
    );

    printf(
        "Log File     : %s\n",
        LOG_FILE
    );

    printf(
        "====================================\n"
    );


    while (server_running)
    {
        struct sockaddr_in client_address;

        socklen_t client_length =
            sizeof(client_address);


        int client_fd =
            accept(
                server_fd,
                (struct sockaddr *)&client_address,
                &client_length
            );


        if (client_fd < 0)
        {
            if (errno == EINTR)
                continue;

            perror("accept");

            break;
        }


        client_session_t *session =
            calloc(
                1,
                sizeof(*session)
            );


        if (session == NULL)
        {
            close(client_fd);

            continue;
        }


        session->fd =
            client_fd;


        inet_ntop(
            AF_INET,
            &client_address.sin_addr,
            session->client_ip,
            sizeof(session->client_ip)
        );


        pthread_mutex_init(
            &session->monitor_mutex,
            NULL
        );


        pthread_t thread;


        if (
            pthread_create(
                &thread,
                NULL,
                client_handler,
                session
            ) != 0
        )
        {
            perror(
                "pthread_create"
            );


            pthread_mutex_destroy(
                &session->monitor_mutex
            );


            close(client_fd);

            free(session);

            continue;
        }


        pthread_detach(thread);
    }


    close(server_fd);


    printf(
        "RemoteOps Agent stopped.\n"
    );


    return EXIT_SUCCESS;
}
