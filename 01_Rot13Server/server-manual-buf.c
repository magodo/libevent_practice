/*************************************************************************
 Author: Zhaoting Weng
 Created Time: Thu 18 Jan 2018 11:22:56 AM CST
 Description: Refer to http://www.wangafu.net/~nickm/libevent-book/01_intro.html
 ************************************************************************/

/* getaddrinfo, et al. */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <event2/event.h>


#define BUFSIZE 1024
#define QLEN 10

char rot13(char c)
{
    if ((c >= 'a' && c <= 'm') || (c >= 'A' && c <= 'M'))
        return c+13;
    else if ((c >= 'n' && c <= 'z') || (c >= 'n' && c <= 'Z'))
        return c-13;
    else
        return c;
}

// forward declaration
void cb_read(evutil_socket_t fd, short event, void *arg);
void cb_write(evutil_socket_t fd, short event, void *arg);

struct fd_state
{
    char buffer[BUFSIZE];
    size_t buffer_used;
    size_t n_written;
    size_t n_to_write;

    struct event *read_event;
    struct event *write_event;
};

struct fd_state* alloc_fd_state(struct event_base *base, evutil_socket_t fd)
{
    struct fd_state *state = (struct fd_state*)calloc(sizeof(struct fd_state), 1);
    if (!state)
        return NULL;

    state->read_event = event_new(base, fd, EV_READ|EV_PERSIST, cb_read, state);
    if (!state->read_event)
    {
        free(state);
        return NULL;
    }

    state->write_event = event_new(base, fd, EV_WRITE|EV_PERSIST, cb_write, state);
    if (!state->write_event)
    {
        event_free(state->read_event);
        free(state);
        return NULL;
    }

    return state;
}

void free_fd_state(struct fd_state* state)
{
    event_free(state->read_event);
    event_free(state->write_event);
    free(state);
}

void cb_read(evutil_socket_t fd, short event, void *arg)
{
    struct fd_state* state = (struct fd_state*)arg;
    char buf[BUFSIZE];
    ssize_t n_read; 

    while (1)
    {
        n_read = recv(fd, buf, sizeof(buf), 0);

        /* peer shutdown or blocks or other error. */
        if (n_read <= 0)
            break;

        /* loop every byte received, process it. echo them once '\n' is encountered. */
        for (int i = 0; i < n_read; ++i)
        {
            if (state->buffer_used < sizeof(state->buffer))
            {
                state->buffer[state->buffer_used++] = rot13(buf[i]);
            }
            if (buf[i] == '\n')
            {
                state->n_to_write = state->buffer_used;
                event_add(state->write_event, NULL);
            }
        }
    }

    if (n_read == 0)
    {
        fprintf(stderr, "peer shutdown\n");
        close(fd);
        event_del(state->read_event);
        free_fd_state(state);
    }
    else
    {
        if (errno == EAGAIN)
            return;
        else
        {
            perror("recv");
            close(fd);
            event_del(state->read_event);
            free_fd_state(state);
        }
    }
}

void cb_write(evutil_socket_t fd, short event, void *arg)
{
    struct fd_state *state = (struct fd_state*)arg;

    while (state->n_written < state->n_to_write)
    {
        ssize_t n_write = send(fd, state->buffer + state->n_written,
                               state->n_to_write - state->n_written, 0);
        if (n_write == -1)
        {
            if (errno == EAGAIN)
                return;

            /* other errors */
            close(fd);
            event_del(state->read_event);
            event_del(state->write_event);
            free_fd_state(state);
            return;
        }

        state->n_written += n_write; 
    }

    state->n_written = state->n_to_write = state->buffer_used = 0;
    event_del(state->write_event);
}

void cb_accept(evutil_socket_t listen_fd, short event, void *arg)
{
    struct event_base *base = (struct event_base*)arg;
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);

    int fd = accept(listen_fd, (struct sockaddr*)&ss, &slen);
    if (fd == -1)
    {
        perror("accept");
    }
    else if (fd > FD_SETSIZE)
    {
        fprintf(stderr, "fd exceeds FD_SETSIZE\n");
        close(fd);
    }
    else
    {
        struct fd_state *state = alloc_fd_state(base, fd);
        evutil_make_socket_nonblocking(fd);
        event_add(state->read_event, NULL);
    }
}

void serve(evutil_socket_t listen_fd)
{
    struct event_base *base;
    struct event *listener_event;

    base = event_base_new();
    if (base == NULL)
    {
        //close(listen_fd);
        return;
    }

    listener_event = event_new(base, listen_fd, EV_READ|EV_PERSIST, cb_accept, base);
    event_add(listener_event, NULL);

    /* run event base until no more pending or active envents.*/
    //event_base_dispatch(base);
    event_base_loop(base, 0);

    event_free(listener_event);
    event_base_free(base);
}

evutil_socket_t initserver(int sock_type, const struct sockaddr *addr, int alen, int qlen)
{
    int fd;

    fd = socket(addr->sa_family, sock_type, 0);
    if (fd == -1)
        return fd;

    /* make the listening socket nonblocking */
    evutil_make_socket_nonblocking(fd);

#ifndef WIN32
    {
        /* Avoid TCP socket regards the address of a closed socket is in used during linger time(aka. TIME_WAIT state).
         * Enabling this flag, another socket could bind to the exact same address if the previous socket bound to it
         * is in TIME_WAIT state.*/
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
#endif

    if (bind(fd, addr, alen) == -1)
    {
        //close(fd);
        perror("bind");
        return -1;
    }

    if (listen(fd, qlen) == -1)
    {
        //close(fd);
        perror("listen");
        return -1;
    }

    return fd;
}

int run(const char *port)
{
    /* setup server */

    struct addrinfo *ai_list = NULL, *aip, hint;
    evutil_socket_t listen_fd;

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE;

    int ret;
    if ((ret = getaddrinfo(NULL, port, &hint, &ai_list)) != 0)
    {
        fprintf(stderr, "getaddrinfo error: %s", gai_strerror(ret));
        return -1;
    }

    for (aip = ai_list; aip != NULL; aip = ai_list->ai_next)
    {
        if ((listen_fd = initserver(aip->ai_socktype, aip->ai_addr, aip->ai_addrlen, QLEN)) > 0)
        {
            freeaddrinfo(ai_list);
            /* serve */
            serve(listen_fd);
            return 0;
        }
    }
}
        
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s port\n", argv[0]);
        return -1;
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    return run(argv[1]);
}
