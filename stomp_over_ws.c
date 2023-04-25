#include "stomp_over_ws.h"

// GENERIC

static void destroy_stomp_frame(stomp_frame_t *frame)
{
    if (frame != NULL)
    {
        if (frame->frame_name != NULL)
        {
            free(frame->frame_name);
        }
        if (frame->headers != NULL)
        {
            free(frame->headers);
        }
        if (frame->body != NULL)
        {
            free(frame->body);
        }
        free(frame);
    }
}

static stomp_frame_t *init_stomp_frame(const char *frame_name, int header_number)
{
    stomp_frame_t *frame = (stomp_frame_t *)calloc(1, sizeof(stomp_frame_t));
    if (frame == NULL)
    {
        return NULL;
    }
    frame->frame_name = (char *)calloc(strlen(frame_name) + 1, sizeof(char));
    if (frame->frame_name == NULL)
    {
        destroy_stomp_frame(frame);
        return NULL;
    }
    strcpy(frame->frame_name, frame_name);
    frame->header_number = header_number;
    if (header_number != 0)
    {
        frame->headers = (stomp_header_t *)calloc(header_number, sizeof(stomp_header_t));
        if (frame->headers == NULL)
        {
            destroy_stomp_frame(frame);
            return NULL;
        }
    }
    frame->body = (stomp_body_t *)calloc(1, sizeof(stomp_body_t));
    if (frame->body == NULL)
    {
        destroy_stomp_frame(frame);
        return NULL;
    }
    return frame;
}

static void parse_stomp_headers(stomp_frame_t *stomp_frame, char **stomp_string_ptr)
{
    if (stomp_frame != NULL)
    {
        char *delimiters = "\r\n";
        char *arg_delimiter = ":";
        char *token = strsep(stomp_string_ptr, delimiters);

        int delim_number = 1;

        if (strlen(token) == 0)
        {
            token = strsep(stomp_string_ptr, delimiters);
            delim_number = 2;
        }
        while (strlen(token) > 0)
        {
            char *arg_token = strsep(&token, arg_delimiter);
            char *arg_value_token = strsep(&token, arg_delimiter);
            set_stomp_frame_header(stomp_frame, arg_token, arg_value_token);
            token = strsep(stomp_string_ptr, delimiters);
            if (delim_number == 2 && strlen(token) == 0)
            {
                token = strsep(stomp_string_ptr, delimiters);
            }
        }
        if (delim_number == 2)
        {
            token = strsep(stomp_string_ptr, delimiters);
        }
        *stomp_string_ptr = (*stomp_string_ptr) + 1;
    }
}

static void parse_stomp_body(stomp_frame_t *stomp_frame, char **stomp_string_ptr)
{
    set_stomp_frame_body(stomp_frame, *stomp_string_ptr);
}

static void parse_stomp_frame_2(stomp_frame_t *stomp_frame, char **stomp_string_ptr)
{
    parse_stomp_headers(stomp_frame, stomp_string_ptr);
    parse_stomp_body(stomp_frame, stomp_string_ptr);
}

static stomp_frame_t *parse_stomp_frame(char *stomp_string)
{
    char **stomp_string_ptr = &stomp_string;
    char *delimiters = "\r\n";
    char *token = strsep(stomp_string_ptr, delimiters);
    stomp_frame_t *new_frame = NULL;
    if (strcmp(token, "CONNECTED") == 0)
    {
        new_frame = init_stomp_connected_frame();
        parse_stomp_frame_2(new_frame, stomp_string_ptr);
    }
    else
    {
        if (strcmp(token, "ERROR"))
        {
            new_frame = init_stomp_error_frame();
            parse_stomp_frame_2(new_frame, stomp_string_ptr);
        }
    }
    return new_frame;
}

static char *stringify_stomp_frame(stomp_frame_t *frame, int *len_ptr)
{
    char *ret_string = NULL;
    char *ret_string_copy = NULL;

    if (frame == NULL)
    {
        return NULL;
    }

    int string_length = 0;
#if (CURRENT_IMPLEMENTATION == LIBWEBSOCKETS_IMPLEMENTATION)
    string_length += LWS_PRE;
#endif
    string_length += strlen(frame->frame_name) + 1;
    for (int i = 0; i < frame->header_number; i++)
    {
        if (frame->headers[i].is_valid == VALID)
        {
            string_length += strlen(frame->headers[i].header_name) + strlen(frame->headers[i].value) + 2;
        }
    }
    if (frame->body->is_valid == VALID)
    {
        string_length += strlen(frame->body->body);
    }
    string_length += 2; // \n before body + \0 after body
    *len_ptr = string_length;

    ret_string = (char *)calloc(string_length, sizeof(char));
    ret_string_copy = ret_string;

#if (CURRENT_IMPLEMENTATION == LIBWEBSOCKETS_IMPLEMENTATION)
    ret_string += LWS_PRE;
#endif

    strcpy(ret_string, frame->frame_name);
    ret_string += strlen(frame->frame_name);
    strcpy(ret_string, "\n");
    ret_string += 1;
    for (int i = 0; i < frame->header_number; i++)
    {
        if (frame->headers[i].is_valid == VALID)
        {
            strcpy(ret_string, frame->headers[i].header_name);
            ret_string += strlen(frame->headers[i].header_name);
            strcpy(ret_string, ":");
            ret_string += 1;
            strcpy(ret_string, frame->headers[i].value);
            ret_string += strlen(frame->headers[i].value);
            strcpy(ret_string, "\n");
            ret_string += 1;
        }
    }
    strcpy(ret_string, "\n");
    ret_string += 1;
    if (frame->body->is_valid == VALID)
    {
        strcpy(ret_string, frame->body->body);
        ret_string += strlen(frame->body->body);
    }

    return ret_string_copy;
}

void set_stomp_frame_header(stomp_frame_t *frame, char *header_name, char *header_value)
{
    if (frame == NULL)
    {
        return;
    }
    for (int i = 0; i < frame->header_number; i++)
    {
        if (strcmp(frame->headers[i].header_name, header_name) == 0)
        {
            if (frame->headers[i].is_valid == VALID)
            {
                if (frame->headers[i].value != NULL)
                {
                    free(frame->headers[i].value);
                }
            }
            frame->headers[i].is_valid = VALID;
            frame->headers[i].value = (char *)calloc(strlen(header_value) + 1, sizeof(char));
            strcpy(frame->headers[i].value, header_value);
        }
    }
}

void set_stomp_frame_body(stomp_frame_t *frame, char *body)
{
    if (frame == NULL)
    {
        return;
    }
    if (frame->body->is_valid == VALID)
    {
        if (frame->body->body != NULL)
        {
            free(frame->body->body);
        }
    }
    frame->body->is_valid = VALID;
    frame->body->body = (char *)calloc(strlen(body) + 1, sizeof(char));
    strcpy(frame->body->body, body);
}

// FRAMES

////STOMP CONNECT FRAME

#define STOMP_CONNECT_FRAME_INDEX 0
#define STOMP_CONNECT_FRAME_HEADERS_NUMBER 5

stomp_frame_t *init_stomp_connect_frame()
{
    stomp_frame_t *new_connect_frame = init_stomp_frame(stomp_frame_names_array[STOMP_CONNECT_FRAME_INDEX], STOMP_CONNECT_FRAME_HEADERS_NUMBER);

    new_connect_frame->headers[0].header_name = "accept-version";
    new_connect_frame->headers[0].is_required = REQUIRED;
    new_connect_frame->headers[0].is_valid = INVALID;
    new_connect_frame->headers[0].value = NULL;

    new_connect_frame->headers[1].header_name = "host";
    new_connect_frame->headers[1].is_required = REQUIRED;
    new_connect_frame->headers[1].is_valid = INVALID;
    new_connect_frame->headers[1].value = NULL;

    new_connect_frame->headers[2].header_name = "login";
    new_connect_frame->headers[2].is_required = NOT_REQUIRED;
    new_connect_frame->headers[2].is_valid = INVALID;
    new_connect_frame->headers[2].value = NULL;

    new_connect_frame->headers[3].header_name = "passcode";
    new_connect_frame->headers[3].is_required = NOT_REQUIRED;
    new_connect_frame->headers[3].is_valid = INVALID;
    new_connect_frame->headers[3].value = NULL;

    new_connect_frame->headers[4].header_name = "heart-beat";
    new_connect_frame->headers[4].is_required = NOT_REQUIRED;
    new_connect_frame->headers[4].is_valid = INVALID;
    new_connect_frame->headers[4].value = NULL;

    new_connect_frame->body->is_required = EMPTY;
    new_connect_frame->body->is_valid = INVALID;
    new_connect_frame->body->body = NULL;

    return new_connect_frame;
}

////STOMP CONNECTED FRAME

#define STOMP_CONNECTED_FRAME_INDEX 1
#define STOMP_CONNECTED_FRAME_HEADERS_NUMBER 4

stomp_frame_t *init_stomp_connected_frame()
{
    stomp_frame_t *new_connect_frame = init_stomp_frame(stomp_frame_names_array[STOMP_CONNECTED_FRAME_INDEX], STOMP_CONNECTED_FRAME_HEADERS_NUMBER);
    new_connect_frame->headers[0].header_name = "version";
    new_connect_frame->headers[0].is_required = REQUIRED;
    new_connect_frame->headers[0].is_valid = INVALID;
    new_connect_frame->headers[0].value = NULL;
    new_connect_frame->headers[1].header_name = "heart-beat";
    new_connect_frame->headers[1].is_required = NOT_REQUIRED;
    new_connect_frame->headers[1].is_valid = INVALID;
    new_connect_frame->headers[1].value = NULL;
    new_connect_frame->headers[2].header_name = "session";
    new_connect_frame->headers[2].is_required = NOT_REQUIRED;
    new_connect_frame->headers[2].is_valid = INVALID;
    new_connect_frame->headers[2].value = NULL;
    new_connect_frame->headers[3].header_name = "server";
    new_connect_frame->headers[3].is_required = NOT_REQUIRED;
    new_connect_frame->headers[3].is_valid = INVALID;
    new_connect_frame->headers[3].value = NULL;
    new_connect_frame->body->is_required = EMPTY;
    new_connect_frame->body->is_valid = INVALID;
    new_connect_frame->body->body = NULL;

    return new_connect_frame;
}

////STOMP ERROR FRAME

#define STOMP_ERROR_FRAME_INDEX 2
#define STOMP_ERROR_FRAME_HEADERS_NUMBER 4

stomp_frame_t *init_stomp_error_frame()
{
    stomp_frame_t *new_connect_frame = init_stomp_frame(stomp_frame_names_array[STOMP_ERROR_FRAME_INDEX], STOMP_ERROR_FRAME_HEADERS_NUMBER);
    new_connect_frame->headers[0].header_name = "receipt-id";
    new_connect_frame->headers[0].is_required = NOT_REQUIRED;
    new_connect_frame->headers[0].is_valid = INVALID;
    new_connect_frame->headers[0].value = NULL;
    new_connect_frame->headers[1].header_name = "content-type";
    new_connect_frame->headers[1].is_required = REQUIRED_IF_BODY_PRESENT;
    new_connect_frame->headers[1].is_valid = INVALID;
    new_connect_frame->headers[1].value = NULL;
    new_connect_frame->headers[2].header_name = "content-length";
    new_connect_frame->headers[2].is_required = REQUIRED_IF_BODY_PRESENT;
    new_connect_frame->headers[2].is_valid = INVALID;
    new_connect_frame->headers[2].value = NULL;
    new_connect_frame->headers[3].header_name = "message";
    new_connect_frame->headers[3].is_required = REQUIRED;
    new_connect_frame->headers[3].is_valid = INVALID;
    new_connect_frame->headers[3].value = NULL;
    new_connect_frame->body->is_required = NOT_REQUIRED;
    new_connect_frame->body->is_valid = INVALID;
    new_connect_frame->body->body = NULL;

    return new_connect_frame;
}

////STOMP SEND FRAME

#define STOMP_SEND_FRAME_INDEX 3
#define STOMP_SEND_FRAME_HEADERS_NUMBER 3

stomp_frame_t *init_stomp_send_frame()
{
    stomp_frame_t *new_connect_frame = init_stomp_frame(stomp_frame_names_array[STOMP_SEND_FRAME_INDEX], STOMP_SEND_FRAME_HEADERS_NUMBER);
    new_connect_frame->headers[0].header_name = "destination";
    new_connect_frame->headers[0].is_required = REQUIRED;
    new_connect_frame->headers[0].is_valid = INVALID;
    new_connect_frame->headers[0].value = NULL;
    new_connect_frame->headers[1].header_name = "content-type";
    new_connect_frame->headers[1].is_required = REQUIRED_IF_BODY_PRESENT;
    new_connect_frame->headers[1].is_valid = INVALID;
    new_connect_frame->headers[1].value = NULL;
    new_connect_frame->headers[2].header_name = "content-length";
    new_connect_frame->headers[2].is_required = REQUIRED_IF_BODY_PRESENT;
    new_connect_frame->headers[2].is_valid = INVALID;
    new_connect_frame->headers[2].value = NULL;
    new_connect_frame->body->is_required = NOT_REQUIRED;
    new_connect_frame->body->is_valid = INVALID;
    new_connect_frame->body->body = NULL;

    return new_connect_frame;
}

#define STOMP_DISCONNECT_FRAME_INDEX 4
#define STOMP_DISCONNECT_FRAME_HEADERS_NUMBER 0

stomp_frame_t *init_stomp_disconnect_frame()
{
    stomp_frame_t *new_connect_frame = init_stomp_frame(stomp_frame_names_array[STOMP_DISCONNECT_FRAME_INDEX], STOMP_DISCONNECT_FRAME_HEADERS_NUMBER);
    new_connect_frame->body->is_required = EMPTY;
    new_connect_frame->body->is_valid = INVALID;
    new_connect_frame->body->body = NULL;

    return new_connect_frame;
}

void print_stomp_frame(stomp_frame_t *stomp_frame)
{
    if (stomp_frame != NULL)
    {
        if (stomp_frame->frame_name != NULL)
        {
            fprintf(stderr, "%s\n", stomp_frame->frame_name);
        }
        else
        {
            fprintf(stderr, "%s\n", "UNCORRECT_NULL_FRAME_NAME");
        }
        if (stomp_frame->headers != NULL)
        {
            stomp_header_t *headers = stomp_frame->headers;
            for (int i = 0; i < stomp_frame->header_number; i++)
            {
                if (headers[i].is_valid == VALID)
                {
                    if (headers[i].header_name != NULL)
                    {
                        fprintf(stderr, "%s", headers[i].header_name);
                    }
                    else
                    {
                        fprintf(stderr, "%s", "UNCORRECT_NULL_HEADER_NAME");
                    }
                    if (headers[i].value != NULL)
                    {
                        fprintf(stderr, ":%s\n", headers[i].value);
                    }
                    else
                    {
                        fprintf(stderr, ":%s\n", "UNCORRECT_NULL_HEADER_VALUE");
                    }
                }
            }
        }
        if (stomp_frame->body != NULL)
        {
            if (stomp_frame->body->is_valid == VALID)
            {
                if (stomp_frame->body->body != NULL)
                {
                    fprintf(stderr, "\n%s^@", stomp_frame->body->body);
                }
                else
                {
                    fprintf(stderr, "\n%s^@", "UNCORRECT_NULL_BODY_VALUE");
                }
            }else{
                fprintf(stderr, "\n^@");
            }
        }
    }
    else
    {
        fprintf(stderr, "%s\n", "UNCORRECT_NULL_STOMP_FRAME");
    }
}

// SESSIONS

static void init_buffer(pthread_buffer_t *buffer)
{
    buffer->recv_buffer = NULL;
    buffer->send_buffer = NULL;
    buffer->recv_buffer_length = 0;
    buffer->send_buffer_length = 0;
    buffer->recv_frame = NULL;
    buffer->send_frame = NULL;
}

static void destroy_buffer(pthread_buffer_t *buffer)
{
    if (buffer->recv_buffer != NULL)
    {
        free(buffer->recv_buffer);
    }
    if (buffer->send_buffer != NULL)
    {
        free(buffer->send_buffer);
    }
    if (buffer->recv_frame != NULL)
    {
        free(buffer->recv_frame);
    }
    if (buffer->send_frame != NULL)
    {
        free(buffer->send_frame);
    }
    buffer->recv_frame = NULL;
    buffer->send_frame = NULL;
    buffer->recv_buffer = NULL;
    buffer->send_buffer = NULL;
    buffer->recv_buffer_length = 0;
    buffer->send_buffer_length = 0;
    buffer->is_recv_flag = 0;
    buffer->is_send_flag = 0;
}

#if (CURRENT_IMPLEMENTATION == LIBWEBSOCKETS_IMPLEMENTATION)
static int callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{

    pthread_buffer_t *buffer = (pthread_buffer_t *)user;

    switch (reason)
    {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        fprintf(stderr, "Client initialisation\n");
        // init_buffer(buffer);
        break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        fprintf(stderr, "Error during websocket channel initialisation\n");
        buffer->exit_flag = EXIT;
        destroy_buffer(buffer);
        break;

    case LWS_CALLBACK_CLOSED:
        fprintf(stderr, "Websocket channel closed\n");
        destroy_buffer(buffer);
        break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
        fprintf(stderr, "Read from websocket\n");
        if (buffer->recv_buffer == NULL && buffer->recv_frame == NULL)
        {
            buffer->recv_buffer = (char *)calloc(len + 1, sizeof(char));
            buffer->recv_buffer_length = len;
            strcpy(buffer->recv_buffer, (char *)in);
            fprintf(stderr, "%s", buffer->recv_buffer);
            buffer->recv_frame = parse_stomp_frame(buffer->recv_buffer);
            buffer->exit_flag = EXIT;
            buffer->is_recv_flag = 1;
        }
        break;

    case LWS_CALLBACK_CLIENT_WRITEABLE:
        fprintf(stderr, "Write into websocket\n");
        if (buffer->is_send_flag == 0)
        {
            fprintf(stderr, "%s", buffer->send_buffer + LWS_PRE);
            lws_write(wsi, buffer->send_buffer + LWS_PRE, buffer->send_buffer_length - LWS_PRE, LWS_WRITE_TEXT);
            buffer->is_send_flag = 1;
        }
        break;

    default:
        break;
    }
    return 0;
}
#endif

stomp_session_t *init_stomp_session(stomp_frame_t *connect_frame)
{
#if (CURRENT_IMPLEMENTATION == LIBWEBSOCKETS_IMPLEMENTATION)

    lws_set_log_level(LLL_DEBUG | LLL_PARSER | LLL_CLIENT | LLL_HEADER, NULL);

    struct lws_context *context = NULL;
    struct lws_context_creation_info info;
    struct lws_protocols protocol[2];

    protocol[0].name = "v12.stomp";
    protocol[0].callback = &callback;
    protocol[0].per_session_data_size = sizeof(pthread_buffer_t);
    protocol[0].rx_buffer_size = 0;
    protocol[0].id = 0;
    protocol[0].user = NULL;

    protocol[1].name = NULL;
    protocol[1].callback = NULL;
    protocol[1].per_session_data_size = 0;
    protocol[1].rx_buffer_size = 0;
    protocol[1].id = 0;
    protocol[1].user = NULL;

    memset(&info, 0, sizeof info);
    info.port = 0;
    info.iface = NULL;
    info.protocols = protocol;
    info.ssl_cert_filepath = NULL;
    info.ssl_private_key_filepath = NULL;
    info.extensions = NULL;
    info.gid = -1;
    info.uid = -1;
    info.options = 0;

    context = lws_create_context(&info);

    if (context == NULL)
    {
        return NULL;
    }

    struct lws_client_connect_info c_info;
    memset(&c_info, 0, sizeof(c_info));
    c_info.context = context;
    c_info.address = "localhost";          // server name
    c_info.port = 8080;                    // port number
    c_info.ssl_connection = 0;             // SSL
    c_info.path = "/ws_raw_stream";        // path to access
    c_info.host = "localhost";             // host name
    c_info.protocol = "v12.stomp";         // protocol
    c_info.ietf_version_or_minus_one = -1; // IETF version

    struct lws *socket = lws_client_connect_via_info(&c_info);

    if (socket == NULL)
    {
        return NULL;
    }
    void *user_data = lws_wsi_user(socket);

    struct stomp_over_ws_tool *tool = (stomp_over_ws_tool *)calloc(1, sizeof(stomp_over_ws_tool));
    tool->socket = socket;
    tool->block_message_buffer = (pthread_buffer_t *)user_data;
    tool->context = context;
    tool->protocol = protocol;

    int len = 0;
    if (tool->block_message_buffer != NULL)
    {
        tool->block_message_buffer->send_frame = connect_frame;
        tool->block_message_buffer->send_buffer = stringify_stomp_frame(connect_frame, &len);
        tool->block_message_buffer->send_buffer_length = len;
        tool->block_message_buffer->exit_flag = CONTINUE;
        tool->block_message_buffer->is_send_flag = 0;
        tool->block_message_buffer->is_recv_flag = 0;
    }

    lws_callback_on_writable(socket);
    //lws_service(context, 0);

    while (tool->block_message_buffer->exit_flag == CONTINUE && (tool->block_message_buffer->recv_frame == NULL || (tool->block_message_buffer->recv_frame != NULL && strcmp(tool->block_message_buffer->recv_frame->frame_name, "CONNECTED") != 0) || (tool->block_message_buffer->recv_frame != NULL && strcmp(tool->block_message_buffer->recv_frame->frame_name, "ERROR") != 0)))
    {
        if (tool->block_message_buffer->is_send_flag == 0)
        {
            lws_callback_on_writable(socket);
        }
        lws_service(context, 0);
    }

    stomp_frame_t *ret_frame = tool->block_message_buffer->recv_frame;
    stomp_session_t *new_session = (stomp_session_t *)calloc(1, sizeof(stomp_session_t));
    new_session->connect_response = ret_frame;
    new_session->tool = tool;

    // I think that this memory is freed by libwebsocket but it's my suggestion/ If you uncomment it when you will have segfault. Maybe i need create another buffer,
    // copy data in that new buffer, then give it new buffer to lws write and then free this old buffer here
    // if(tool->block_message_buffer->send_buffer != NULL)
    // {
    //     free(tool->block_message_buffer->send_buffer);
    // }
    if (tool->block_message_buffer->recv_buffer != NULL)
    {
        free(tool->block_message_buffer->recv_buffer);
    }
    tool->block_message_buffer->send_buffer_length = 0;
    tool->block_message_buffer->recv_buffer_length = 0;
    tool->block_message_buffer->recv_frame = NULL;
    tool->block_message_buffer->send_frame = NULL;
    tool->block_message_buffer->exit_flag = CONTINUE;
    tool->block_message_buffer->is_send_flag = 0;
    tool->block_message_buffer->is_recv_flag = 0;

    // int socket;
    // int ret;
    // int heart = 0;
    // Ws_DataType retPkgType;

    // char recv_buff[RECV_PKG_MAX];
    // char send_buff[SEND_PKG_MAX];

    // int port = 8080;
    // char ip[32] = "127.0.0.1";
    // char path[64] = "/stream";

    // if ((socket = ws_requestServer(ip, port, path, 5000)) <= 0)
    // {
    //     fprintf(stderr, "connect failed !!\n");
    //     return NULL;
    // }
    // fprintf(stderr, "connection success\n");

    return new_session;
#endif
}

is_connected_t is_stomp_session_active(stomp_session_t *session)
{
    if (session == NULL)
    {
        return DISCONNECTED;
    }
    if (session->connect_response == NULL || strcmp(session->connect_response->frame_name, "ERROR") == 0)
    {
        return DISCONNECTED;
    }
    return CONNECTED;
}

void destroy_stomp_session(stomp_session_t *stomp_session, stomp_frame_t *disconnect_frame)
{
#if (CURRENT_IMPLEMENTATION == LIBWEBSOCKETS_IMPLEMENTATION)
    stomp_over_ws_tool *tool = stomp_session->tool;
    struct lws_context *context = stomp_session->tool->context;
    struct lws *socket = stomp_session->tool->socket;
    if (tool->block_message_buffer != NULL)
    {
        int len = 0;
        tool->block_message_buffer->send_frame = disconnect_frame;
        tool->block_message_buffer->send_buffer = stringify_stomp_frame(disconnect_frame, &len);
        tool->block_message_buffer->send_buffer_length = len;
        tool->block_message_buffer->exit_flag = CONTINUE;
        tool->block_message_buffer->is_send_flag = 0;
        tool->block_message_buffer->is_recv_flag = 0;
    }
    //lws_service(context, 0);
    lws_callback_on_writable(socket);

    while (tool->block_message_buffer->is_send_flag == 0)
    {
        if (tool->block_message_buffer->is_send_flag == 0)
        {
            lws_callback_on_writable(socket);
        }
        lws_service(context, 0);
    }

    lws_context_destroy(tool->context);
    // maybe here must use lws_wsi_close()
#endif
}

void send_stomp_frame(stomp_session_t* stomp_session, stomp_frame_t* send_frame)
{
#if (CURRENT_IMPLEMENTATION == LIBWEBSOCKETS_IMPLEMENTATION)
    stomp_over_ws_tool *tool = stomp_session->tool;
    struct lws_context *context = stomp_session->tool->context;
    struct lws *socket = stomp_session->tool->socket;
    if (tool->block_message_buffer != NULL)
    {
        int len = 0;
        tool->block_message_buffer->send_frame = send_frame;
        tool->block_message_buffer->send_buffer = stringify_stomp_frame(send_frame, &len);
        tool->block_message_buffer->send_buffer_length = len;
        tool->block_message_buffer->exit_flag = CONTINUE;
        tool->block_message_buffer->is_send_flag = 0;
        tool->block_message_buffer->is_recv_flag = 0;
    }
    lws_callback_on_writable(socket);

    while (tool->block_message_buffer->is_send_flag == 0)
    {
        if (tool->block_message_buffer->is_send_flag == 0)
        {
            lws_callback_on_writable(socket);
        }
        lws_service(context, 0);
    }

    tool->block_message_buffer->send_buffer_length = 0;
    tool->block_message_buffer->recv_buffer_length = 0;
    tool->block_message_buffer->recv_frame = NULL;
    tool->block_message_buffer->send_frame = NULL;
    tool->block_message_buffer->exit_flag = CONTINUE;
    tool->block_message_buffer->is_send_flag = 0;
    tool->block_message_buffer->is_recv_flag = 0;
#endif
}