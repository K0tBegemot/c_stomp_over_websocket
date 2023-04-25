#include "stomp_over_ws.h"
#include <stdlib.h>

int main()
{
    stomp_frame_t *connect_frame = init_stomp_connect_frame();
    set_stomp_frame_header(connect_frame, "accept-version", "1.2");
    set_stomp_frame_header(connect_frame, "host", "localhost");
    
    stomp_session_t* session = init_stomp_session(connect_frame);
    if(is_stomp_session_active(session) == CONNECTED)
    {
        fprintf(stderr, "CONGRATULATIONS\n");
        print_stomp_frame(session->connect_response);

        stomp_frame_t* send_frame = init_stomp_send_frame();
        set_stomp_frame_header(send_frame, "destination", "/output/ws_raw_stream");
        set_stomp_frame_header(send_frame, "content-type", "application/json");
        char* string = "{\"time\" : 1682349786159, \"timezone\" : 0, \"ss_rsrp\" : [-100, 0, 0, 0, 0, 0, 0, 0], \"ss_rsrq\" : [-40, 0, 0, 0, 0, 0, 0, 0], \"ss_sinr\" : [-10, 0, 0, 0, 0, 0, 0, 0], \"cell_id\" : [\"1\", \"\", \"\", \"\", \"\", \"\", \"\", \"\"]}";
        char string_length[8];
        int string_length_length = sprintf(string_length, "%ld", strlen(string));
        set_stomp_frame_header(send_frame, "content-length", string_length);
        set_stomp_frame_body(send_frame, string);

        send_stomp_frame(session, send_frame);
    }else{
        fprintf(stderr, "OHHHH NO\n");
        print_stomp_frame(session->connect_response);
    }

    stomp_frame_t* disconnect_frame = init_stomp_disconnect_frame();
    destroy_stomp_session(session, disconnect_frame);
}