#define LIBWEBSOCKETS_IMPLEMENTATION 0          //https://github.com/warmcat/libwebsockets
#define WEBSOCKET_FOR_LINUX_IMPLEMENTATION 1    //https://github.com/wexiangis/websocket_for_linux
#define CURRENT_IMPLEMENTATION LIBWEBSOCKETS_IMPLEMENTATION //current implementation of websocket protocol

#if(defined(LIBWEBSOCKETS_IMPLEMENTATION) && defined(WEBSOCKET_FOR_LINUX_IMPLEMENTATION) && defined(CURRENT_IMPLEMENTATION))

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>

#if (CURRENT_IMPLEMENTATION == LIBWEBSOCKETS_IMPLEMENTATION)
#include <libwebsockets.h>
#endif
#if(CURRENT_IMPLEMENTATION == WEBSOCKET_FOR_LINUX_IMPLEMENTATION)
#include "websocket_for_linux/c_test/ws_com.h"
#define SEND_PKG_MAX (1024 * 10)
#define RECV_PKG_MAX (SEND_PKG_MAX + 16)
#endif

typedef enum validity_t{
    VALID = 0, INVALID = -1
}validity_t;

typedef enum is_connected_t{
    CONNECTED = 0, DISCONNECTED = 1
}is_connected_t;

typedef enum is_required_t{
    REQUIRED = 0, NOT_REQUIRED = 1, REQUIRED_IF_BODY_PRESENT = 2, EMPTY = 3
}is_required_t;

typedef enum is_exit_t{
    EXIT = 1, CONTINUE = 0
}is_exit_t;


//Add new methods at the END of this array. DON'T SHUFFLE THIS!!!
static const char* stomp_frame_names_array[5] = {
    "CONNECT", "CONNECTED", "ERROR", "SEND", "DISCONNECT"
};

//GENERIC structs

typedef struct stomp_header_t{
    validity_t is_valid;
    is_required_t is_required;
    char* header_name;
    char* value;
}stomp_header_t;

typedef struct stomp_body_t{
    validity_t is_valid;
    is_required_t is_required;
    char* body;
}stomp_body_t;

//FRAME structs

typedef struct stomp_frame_t{
    char* frame_name;
    //////////////////////////////////////////////////////////i must add here int frame_name_index element to 
    int32_t header_number;
    stomp_header_t* headers;
    stomp_body_t* body;
}stomp_frame_t;

//SESSION structs

typedef struct pthread_buffer_t{
    int send_buffer_length;
    char* send_buffer;
    int recv_buffer_length;
    char* recv_buffer;

    stomp_frame_t* send_frame;
    int is_send_flag;

    stomp_frame_t* recv_frame;
    int is_recv_flag;

    is_exit_t exit_flag;
}pthread_buffer_t;

typedef struct stomp_over_ws_tool
{
    #if(CURRENT_IMPLEMENTATION == LIBWEBSOCKETS_IMPLEMENTATION)
    struct lws *socket;
    struct lws_context* context;
    struct lws_protocols* protocol;
    #endif
    pthread_buffer_t* block_message_buffer;
}stomp_over_ws_tool;

typedef struct stomp_session_t{
    stomp_frame_t* connect_response;
    stomp_over_ws_tool* tool;
}stomp_session_t;



//INIT Functions

////FRAMES

stomp_frame_t* init_stomp_connect_frame();

stomp_frame_t* init_stomp_connected_frame();

stomp_frame_t* init_stomp_error_frame();

stomp_frame_t* init_stomp_send_frame();

stomp_frame_t* init_stomp_disconnect_frame();

void print_stomp_frame(stomp_frame_t* stomp_frame);

////SESSIONS

stomp_session_t* init_stomp_session(stomp_frame_t* connect_frame);

is_connected_t is_stomp_session_active(stomp_session_t* session);

void destroy_stomp_session(stomp_session_t* stomp_session, stomp_frame_t* disconnect_frame);

//SET Functions

void set_stomp_frame_header(stomp_frame_t* frame, char* connect_header_name, char* header_value);

void set_stomp_frame_body(stomp_frame_t* frame, char* body);

//SEND Functions

void send_stomp_frame(stomp_session_t* stomp_session, stomp_frame_t* send_frame);

#endif