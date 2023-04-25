# c_stomp_over_websocket
A library for sending STOMP messages over WebSocket written in C language

First release : v.0.0.5 Initial Streaming Support(
* - \* changes are needed for standard behavior. at the moment, the programmer must ensure that the headers and body of the frame are set correctly, 
* - ** don't support server message RECEIPT so the command is simply sent and the connection is closed)

Heart-beating : don't support now;

See file sender.c for usage example. Lib was tested with SPRING Boot v.3.0.5

Dependencies : 
1. Libwebsockets : https://github.com/warmcat/libwebsockets
OR
(Not supported now) Websocket_for_linux : https://github.com/wexiangis/websocket_for_linux

<table>
<tr>
<th>STOMP frame</th>
<th>Availability</th>
</tr>
<tr>
<td>CONNECT</td>
<td>Available(*)</td>
</tr>
<tr>
<td>CONNECTED</td>
<td>Available(*)</td>
</tr>
<tr>
<td>SEND</td>
<td>Available(*)</td>
</tr>
<tr>
<td>DISCONNECT</td>
<td>Available(**)</td>
</tr>
<tr>
<tr>
<td>ERROR</td>
<td>Available(*)</td>
</tr>
<tr>
<td>RECEIPT</td>
<td>Not supported</td>
</tr>
<tr>
<td>MESSAGE</td>
<td>Not supported</td>
</tr>
<td>SUBSCRIBE</td>
<td>Not supported</td>
</tr>
<tr>
<td>UNSUBSCRIBE</td>
<td>Not supported</td>
</tr>
<tr>
<td>ACK</td>
<td>Not supported</td>
</tr>
<tr>
<td>NACK</td>
<td>Not supported</td>
</tr>
<tr>
<td>BEGIN</td>
<td>Not supported</td>
</tr>
<tr>
<td>COMMIT</td>
<td>Not supported</td>
</tr>
<tr>
<td>ABORT</td>
<td>Not supported</td>
</tr>
</table>
