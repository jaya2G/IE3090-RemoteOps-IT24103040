#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define TCP_PORT 9410

#define SID "0403"
#define AUTH_TOKEN "OPS-3040"

#define MAX_LINE 8192
#define BUFFER_SIZE 8192


typedef struct
{
    int udp_fd;

    volatile int running;

} monitor_state_t;


/* ---------------------------------------------------------
   SEND ALL
   --------------------------------------------------------- */

static int send_all(
    int fd,
    const void *buffer,
    size_t length
)
{
    const char *ptr = buffer;


    while (length > 0)
    {
        ssize_t sent =
            send(
                fd,
                ptr,
                length,
                0
            );


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
   RECEIVE EXACT BYTES
   --------------------------------------------------------- */

static int recv_exact(
    int fd,
    void *buffer,
    size_t length
)
{
    char *ptr = buffer;


    while (length > 0)
    {
        ssize_t received =
            recv(
                fd,
                ptr,
                length,
                0
            );


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
   RECEIVE LINE
   --------------------------------------------------------- */

static int recv_line(
    int fd,
    char *buffer,
    size_t size
)
{
    size_t index = 0;


    while (index + 1 < size)
    {
        char c;


        ssize_t received =
            recv(
                fd,
                &c,
                1,
                0
            );


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


            if (
                index > 0 &&
                buffer[index - 1] == '\r'
            )
            {
                buffer[index - 1] = '\0';
            }


            return 1;
        }


        buffer[index++] = c;
    }


    buffer[size - 1] = '\0';


    return -2;
}


/* ---------------------------------------------------------
   UDP MONITOR RECEIVER
   --------------------------------------------------------- */

static void *monitor_receiver(
    void *argument
)
{
    monitor_state_t *state =
        argument;


    char buffer[1024];


    while (state->running)
    {
        struct sockaddr_in sender;

        socklen_t sender_length =
            sizeof(sender);


        ssize_t received =
            recvfrom(
                state->udp_fd,
                buffer,
                sizeof(buffer) - 1,
                0,
                (struct sockaddr *)&sender,
                &sender_length
            );


        if (received < 0)
        {
            if (errno == EINTR)
                continue;


            if (
                errno == EAGAIN ||
                errno == EWOULDBLOCK
            )
            {
                continue;
            }


            break;
        }


        buffer[received] = '\0';


        char ip[
            INET_ADDRSTRLEN
        ];


        inet_ntop(
            AF_INET,
            &sender.sin_addr,
            ip,
            sizeof(ip)
        );


        printf(
            "\n[UDP %s:%d] %s\n> ",
            ip,
            ntohs(sender.sin_port),
            buffer
        );


        fflush(stdout);
    }


    return NULL;
}


/* ---------------------------------------------------------
   START UDP RECEIVER
   --------------------------------------------------------- */

static int start_udp_monitor(
    monitor_state_t *state,
    unsigned short port,
    pthread_t *thread_id
)
{
    state->udp_fd =
        socket(
            AF_INET,
            SOCK_DGRAM,
            0
        );


    if (state->udp_fd < 0)
    {
        perror("UDP socket");

        return -1;
    }


    int yes = 1;


    setsockopt(
        state->udp_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &yes,
        sizeof(yes)
    );


    struct timeval timeout;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;


    setsockopt(
        state->udp_fd,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &timeout,
        sizeof(timeout)
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
        htons(port);


    if (
        bind(
            state->udp_fd,
            (struct sockaddr *)&address,
            sizeof(address)
        ) < 0
    )
    {
        perror("UDP bind");

        close(state->udp_fd);

        state->udp_fd = -1;

        return -1;
    }


    state->running = 1;


    if (
        pthread_create(
            thread_id,
            NULL,
            monitor_receiver,
            state
        ) != 0
    )
    {
        perror(
            "pthread_create"
        );


        state->running = 0;

        close(state->udp_fd);

        state->udp_fd = -1;

        return -1;
    }


    return 0;
}


/* ---------------------------------------------------------
   STOP UDP RECEIVER
   --------------------------------------------------------- */

static void stop_udp_monitor(
    monitor_state_t *state,
    pthread_t *thread_id,
    int *thread_created
)
{
    if (!*thread_created)
        return;


    state->running = 0;


    pthread_join(
        *thread_id,
        NULL
    );


    close(
        state->udp_fd
    );


    state->udp_fd = -1;


    *thread_created = 0;
}


/* ---------------------------------------------------------
   SEND COMMAND
   --------------------------------------------------------- */

static int send_command(
    int fd,
    const char *command
)
{
    char line[MAX_LINE];


    snprintf(
        line,
        sizeof(line),
        "%s\n",
        command
    );


    return send_all(
        fd,
        line,
        strlen(line)
    );
}


/* ---------------------------------------------------------
   PUT FILE
   --------------------------------------------------------- */

static int put_file(
    int fd,
    const char *local_path,
    const char *remote_name
)
{
    FILE *fp =
        fopen(
            local_path,
            "rb"
        );


    if (fp == NULL)
    {
        perror(
            "Opening local file"
        );

        return -1;
    }


    fseek(
        fp,
        0,
        SEEK_END
    );


    long size =
        ftell(fp);


    rewind(fp);


    if (size < 0)
    {
        fclose(fp);

        return -1;
    }


    char header[512];


    snprintf(
        header,
        sizeof(header),
        "PUT %s %ld\n",
        remote_name,
        size
    );


    if (
        send_all(
            fd,
            header,
            strlen(header)
        ) < 0
    )
    {
        fclose(fp);

        return -1;
    }


    char buffer[BUFFER_SIZE];

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
                fd,
                buffer,
                bytes
            ) < 0
        )
        {
            fclose(fp);

            return -1;
        }
    }


    fclose(fp);


    return 0;
}


/* ---------------------------------------------------------
   GET FILE
   --------------------------------------------------------- */

static int get_file(
    int fd,
    const char *remote_name,
    const char *local_path
)
{
    char command[512];


    snprintf(
        command,
        sizeof(command),
        "GET %s",
        remote_name
    );


    if (
        send_command(
            fd,
            command
        ) < 0
    )
    {
        return -1;
    }


    char response[MAX_LINE];


    int result =
        recv_line(
            fd,
            response,
            sizeof(response)
        );


    if (result <= 0)
        return -1;


    printf(
        "< %s\n",
        response
    );


    if (
        strncmp(
            response,
            "OK FILE_SEND ",
            13
        ) != 0
    )
    {
        return 0;
    }


    char filename[256];

    unsigned long long filesize;


    if (
        sscanf(
            response + 13,
            "%255s %llu",
            filename,
            &filesize
        ) != 2
    )
    {
        fprintf(
            stderr,
            "Invalid FILE_SEND response.\n"
        );

        return -1;
    }


    FILE *fp =
        fopen(
            local_path,
            "wb"
        );


    if (fp == NULL)
    {
        perror(
            "Opening destination"
        );

        return -1;
    }


    char buffer[BUFFER_SIZE];


    unsigned long long remaining =
        filesize;


    while (remaining > 0)
    {
        size_t amount =
            remaining > sizeof(buffer)
                ? sizeof(buffer)
                : (size_t)remaining;


        int result =
            recv_exact(
                fd,
                buffer,
                amount
            );


        if (result != 1)
        {
            fclose(fp);

            remove(local_path);

            return -1;
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
            fclose(fp);

            remove(local_path);

            return -1;
        }


        remaining -= amount;
    }


    fclose(fp);


    printf(
        "Saved %llu bytes to %s\n",
        filesize,
        local_path
    );


    return 0;
}


/* ---------------------------------------------------------
   HELP
   --------------------------------------------------------- */

static void print_help(void)
{
    printf("\n");

    printf(
        "auth\n"
    );

    printf(
        "sysinfo\n"
    );

    printf(
        "listproc\n"
    );

    printf(
        "exec DATE\n"
    );

    printf(
        "exec UPTIME\n"
    );

    printf(
        "exec DISKFREE\n"
    );

    printf(
        "exec HOSTNAME\n"
    );

    printf(
        "exec WHOAMI\n"
    );

    printf(
        "put <local_file> [remote_name]\n"
    );

    printf(
        "get <remote_name> [local_file]\n"
    );

    printf(
        "monitor start [udp_port]\n"
    );

    printf(
        "monitor stop\n"
    );

    printf(
        "quit\n"
    );

    printf(
        "help\n"
    );

    printf("\n");
}


/* ---------------------------------------------------------
   MAIN CONTROLLER
   --------------------------------------------------------- */

int main(
    int argc,
    char *argv[]
)
{
    const char *server_ip =
        argc > 1
            ? argv[1]
            : "127.0.0.1";


    int fd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );


    if (fd < 0)
    {
        perror("socket");

        return EXIT_FAILURE;
    }


    struct sockaddr_in server;

    memset(
        &server,
        0,
        sizeof(server)
    );


    server.sin_family =
        AF_INET;

    server.sin_port =
        htons(TCP_PORT);


    if (
        inet_pton(
            AF_INET,
            server_ip,
            &server.sin_addr
        ) != 1
    )
    {
        fprintf(
            stderr,
            "Invalid IP address.\n"
        );

        close(fd);

        return EXIT_FAILURE;
    }


    if (
        connect(
            fd,
            (struct sockaddr *)&server,
            sizeof(server)
        ) < 0
    )
    {
        perror("connect");

        close(fd);

        return EXIT_FAILURE;
    }


    printf(
        "\nConnected to RemoteOps Agent\n"
    );

    printf(
        "Server: %s:%d\n",
        server_ip,
        TCP_PORT
    );

    printf(
        "SID: %s\n",
        SID
    );


    print_help();


    monitor_state_t monitor;

    monitor.udp_fd = -1;
    monitor.running = 0;


    pthread_t monitor_thread;

    int monitor_thread_created = 0;


    char input[MAX_LINE];


    while (1)
    {
        printf("> ");

        fflush(stdout);


        if (
            fgets(
                input,
                sizeof(input),
                stdin
            ) == NULL
        )
        {
            break;
        }


        input[
            strcspn(
                input,
                "\r\n"
            )
        ] = '\0';


        if (input[0] == '\0')
            continue;


        /* AUTH */

        if (
            strcmp(
                input,
                "auth"
            ) == 0
        )
        {
            char command[256];


            snprintf(
                command,
                sizeof(command),
                "AUTH %s",
                AUTH_TOKEN
            );


            send_command(
                fd,
                command
            );


            char response[MAX_LINE];


            if (
                recv_line(
                    fd,
                    response,
                    sizeof(response)
                ) > 0
            )
            {
                printf(
                    "< %s\n",
                    response
                );
            }
        }


        /* SYSINFO */

        else if (
            strcmp(
                input,
                "sysinfo"
            ) == 0
        )
        {
            send_command(
                fd,
                "SYSINFO"
            );


            char response[MAX_LINE];


            if (
                recv_line(
                    fd,
                    response,
                    sizeof(response)
                ) > 0
            )
            {
                printf(
                    "< %s\n",
                    response
                );
            }
        }


        /* LISTPROC */

        else if (
            strcmp(
                input,
                "listproc"
            ) == 0
        )
        {
            send_command(
                fd,
                "LISTPROC"
            );


            char response[MAX_LINE];


            if (
                recv_line(
                    fd,
                    response,
                    sizeof(response)
                ) > 0
            )
            {
                printf(
                    "< %s\n",
                    response
                );
            }
        }


        /* EXEC */

        else if (
            strncmp(
                input,
                "exec ",
                5
            ) == 0
        )
        {
            char command[MAX_LINE];


            snprintf(
                command,
                sizeof(command),
                "EXEC %s",
                input + 5
            );


            send_command(
                fd,
                command
            );


            char response[MAX_LINE];


            if (
                recv_line(
                    fd,
                    response,
                    sizeof(response)
                ) > 0
            )
            {
                printf(
                    "< %s\n",
                    response
                );
            }
        }


        /* PUT */

        else if (
            strncmp(
                input,
                "put ",
                4
            ) == 0
        )
        {
            char local[512];

            char remote[256];


            int count =
                sscanf(
                    input + 4,
                    "%511s %255s",
                    local,
                    remote
                );


            if (count < 1)
            {
                printf(
                    "Usage: put <local> [remote]\n"
                );

                continue;
            }


            if (count == 1)
            {
                const char *base =
                    strrchr(
                        local,
                        '/'
                    );


                if (base != NULL)
                    base++;
                else
                    base = local;


                if (
                    strlen(base) >=
                    sizeof(remote)
                )
                {
                    printf(
                        "Filename too long.\n"
                    );

                    continue;
                }


                strcpy(
                    remote,
                    base
                );
            }


            if (
                put_file(
                    fd,
                    local,
                    remote
                ) == 0
            )
            {
                char response[MAX_LINE];


                if (
                    recv_line(
                        fd,
                        response,
                        sizeof(response)
                    ) > 0
                )
                {
                    printf(
                        "< %s\n",
                        response
                    );
                }
            }
        }


        /* GET */

        else if (
            strncmp(
                input,
                "get ",
                4
            ) == 0
        )
        {
            char remote[256];

            char local[512];


            int count =
                sscanf(
                    input + 4,
                    "%255s %511s",
                    remote,
                    local
                );


            if (count < 1)
            {
                printf(
                    "Usage: get <remote> [local]\n"
                );

                continue;
            }


            if (count == 1)
            {
                snprintf(
                    local,
                    sizeof(local),
                    "%s.download",
                    remote
                );
            }


            get_file(
                fd,
                remote,
                local
            );
        }


        /* MONITOR START */

        else if (
            strcmp(
                input,
                "monitor start"
            ) == 0 ||
            strncmp(
                input,
                "monitor start ",
                14
            ) == 0
        )
        {
            unsigned int port = 9000;


            if (
                strncmp(
                    input,
                    "monitor start ",
                    14
                ) == 0
            )
            {
                sscanf(
                    input + 14,
                    "%u",
                    &port
                );
            }


            if (
                port == 0 ||
                port > 65535
            )
            {
                printf(
                    "Invalid UDP port.\n"
                );

                continue;
            }


            if (monitor_thread_created)
            {
                stop_udp_monitor(
                    &monitor,
                    &monitor_thread,
                    &monitor_thread_created
                );
            }


            if (
                start_udp_monitor(
                    &monitor,
                    (unsigned short)port,
                    &monitor_thread
                ) == 0
            )
            {
                char command[128];


                snprintf(
                    command,
                    sizeof(command),
                    "MONITOR START %u",
                    port
                );


                send_command(
                    fd,
                    command
                );


                char response[MAX_LINE];


                if (
                    recv_line(
                        fd,
                        response,
                        sizeof(response)
                    ) > 0
                )
                {
                    printf(
                        "< %s\n",
                        response
                    );


                    if (
                        strncmp(
                            response,
                            "OK MONITOR_STARTED",
                            19
                        ) != 0
                    )
                    {
                        stop_udp_monitor(
                            &monitor,
                            &monitor_thread,
                            &monitor_thread_created
                        );
                    }
                    else
                    {
                        monitor_thread_created = 1;
                    }
                }
            }
        }


        /* MONITOR STOP */

        else if (
            strcmp(
                input,
                "monitor stop"
            ) == 0
        )
        {
            send_command(
                fd,
                "MONITOR STOP"
            );


            char response[MAX_LINE];


            if (
                recv_line(
                    fd,
                    response,
                    sizeof(response)
                ) > 0
            )
            {
                printf(
                    "< %s\n",
                    response
                );
            }


            stop_udp_monitor(
                &monitor,
                &monitor_thread,
                &monitor_thread_created
            );
        }


        /* QUIT */

        else if (
            strcmp(
                input,
                "quit"
            ) == 0
        )
        {
            send_command(
                fd,
                "QUIT"
            );


            char response[MAX_LINE];


            if (
                recv_line(
                    fd,
                    response,
                    sizeof(response)
                ) > 0
            )
            {
                printf(
                    "< %s\n",
                    response
                );
            }


            break;
        }


        /* HELP */

        else if (
            strcmp(
                input,
                "help"
            ) == 0
        )
        {
            print_help();
        }


        else
        {
            printf(
                "Unknown command. "
                "Type help.\n"
            );
        }
    }


    stop_udp_monitor(
        &monitor,
        &monitor_thread,
        &monitor_thread_created
    );


    close(fd);


    return EXIT_SUCCESS;
}
