#pragma once

#include <Mantids30/Net_Sockets/socket_stream.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>
#include <Mantids30/API_EndpointsAndSessions/session.h>
#include <json/json.h>

class AppSync_ServerImpl
{
public:
    AppSync_ServerImpl() = default;

    static bool createService();
};
