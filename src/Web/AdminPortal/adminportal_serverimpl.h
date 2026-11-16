#pragma once

#include <Mantids30/Server/WebRESTFul/session.h>
#include <Mantids30/Network/Sockets/socket_stream.h>
#include <Mantids30/Protocol/HTTP/httpv1_base.h>
#include <Mantids30/DataFormat/JSON/json.h>

class AdminPortal_ServerImpl
{
public:
    AdminPortal_ServerImpl() = default;

    static bool createService();
};
