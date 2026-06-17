#include <zmq_listener.h>

#include <logging.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include <zmq.h>

namespace photon {
namespace {

bool SubscribeTopic(void* socket, const char* topic)
{
    const int rc = zmq_setsockopt(socket, ZMQ_SUBSCRIBE, topic, std::strlen(topic));
    return rc == 0;
}

bool IsInterrupted(int error)
{
    return error == EINTR;
}

bool ReceiveMultipart(void* socket, std::vector<std::vector<std::uint8_t>>& out_frames)
{
    out_frames.clear();

    while (true) {
        zmq_msg_t msg;
        if (zmq_msg_init(&msg) != 0) {
            return false;
        }

        const int recv_size = zmq_msg_recv(&msg, socket, 0);
        if (recv_size < 0) {
            const int error = zmq_errno();
            zmq_msg_close(&msg);
            if (IsInterrupted(error)) {
                continue;
            }
            return false;
        }

        const auto* data = static_cast<const std::uint8_t*>(zmq_msg_data(&msg));
        out_frames.emplace_back(data, data + recv_size);

        const int has_more = zmq_msg_more(&msg);
        zmq_msg_close(&msg);

        if (has_more == 0) {
            break;
        }
    }

    return true;
}

} // namespace

ZmqListener::ZmqListener()
{
    m_context = zmq_ctx_new();
    if (m_context == nullptr) {
        LOG_ERROR("zmq_ctx_new failed");
    }
}

ZmqListener::~ZmqListener()
{
    CloseSocket();

    if (m_context != nullptr) {
        zmq_ctx_term(m_context);
        m_context = nullptr;
    }
}

void ZmqListener::SetSequenceEndpoint(std::optional<std::string> endpoint)
{
    m_sequence_endpoint = std::move(endpoint);
}

bool ZmqListener::Connect(const std::string& endpoint)
{
    m_hashblock_endpoint = endpoint;
    if (m_hashblock_endpoint.empty()) {
        LOG_ERROR("ZMQ hashblock endpoint is empty");
        m_connected = false;
        return false;
    }

    return Reconnect();
}

std::optional<std::array<std::uint8_t, 32>> ZmqListener::NextHash(std::chrono::milliseconds timeout)
{
    if (!m_connected || m_socket == nullptr) {
        return std::nullopt;
    }

    zmq_pollitem_t item{};
    item.socket = m_socket;
    item.events = ZMQ_POLLIN;

    const long timeout_ms = std::max<long>(0, static_cast<long>(timeout.count()));
    const int poll_rc = zmq_poll(&item, 1, timeout_ms);
    if (poll_rc == 0) {
        // Timeout with no events is expected during normal idle periods.
        return std::nullopt;
    }

    if (poll_rc < 0) {
        const int error = zmq_errno();
        if (IsInterrupted(error)) {
            return std::nullopt;
        }
        LOG_WARN(std::string("ZMQ poll error: ") + zmq_strerror(zmq_errno()));
        Reconnect();
        return std::nullopt;
    }

    if ((item.revents & ZMQ_POLLIN) == 0) {
        return std::nullopt;
    }

    std::vector<std::vector<std::uint8_t>> frames;
    if (!ReceiveMultipart(m_socket, frames)) {
        LOG_WARN(std::string("ZMQ recv error: ") + zmq_strerror(zmq_errno()));
        Reconnect();
        return std::nullopt;
    }

    if (frames.size() < 2) {
        return std::nullopt;
    }

    const std::string topic(frames[0].begin(), frames[0].end());
    if (topic != "hashblock") {
        return std::nullopt;
    }

    if (frames[1].size() < 32) {
        LOG_WARN("Received hashblock payload shorter than 32 bytes");
        return std::nullopt;
    }

    std::array<std::uint8_t, 32> hash{};
    std::copy_n(frames[1].begin(), hash.size(), hash.begin());
    return hash;
}

bool ZmqListener::Reconnect()
{
    CloseSocket();

    if (!CreateSocket()) {
        m_connected = false;
        return false;
    }

    if (zmq_connect(m_socket, m_hashblock_endpoint.c_str()) != 0) {
        LOG_ERROR(std::string("failed to connect hashblock endpoint '") + m_hashblock_endpoint + "': " + zmq_strerror(zmq_errno()));
        CloseSocket();
        m_connected = false;
        return false;
    }

    if (m_sequence_endpoint.has_value() && !m_sequence_endpoint->empty()) {
        if (zmq_connect(m_socket, m_sequence_endpoint->c_str()) != 0) {
            LOG_WARN(std::string("failed to connect sequence endpoint '") + *m_sequence_endpoint + "': " + zmq_strerror(zmq_errno()));
        }
    }

    if (!SubscribeTopic(m_socket, "hashblock")) {
        LOG_ERROR(std::string("failed to subscribe hashblock topic: ") + zmq_strerror(zmq_errno()));
        CloseSocket();
        m_connected = false;
        return false;
    }

    if (m_sequence_endpoint.has_value() && !m_sequence_endpoint->empty()) {
        if (!SubscribeTopic(m_socket, "sequence")) {
            LOG_WARN(std::string("failed to subscribe sequence topic: ") + zmq_strerror(zmq_errno()));
        }
    }

    m_connected = true;
    return true;
}

bool ZmqListener::CreateSocket()
{
    if (m_context == nullptr) {
        return false;
    }

    m_socket = zmq_socket(m_context, ZMQ_SUB);
    if (m_socket == nullptr) {
        LOG_ERROR(std::string("zmq_socket failed: ") + zmq_strerror(zmq_errno()));
        return false;
    }

    const int linger = 0;
    if (zmq_setsockopt(m_socket, ZMQ_LINGER, &linger, sizeof(linger)) != 0) {
        LOG_WARN(std::string("failed to set ZMQ_LINGER: ") + zmq_strerror(zmq_errno()));
    }

    return true;
}

void ZmqListener::CloseSocket()
{
    if (m_socket != nullptr) {
        zmq_close(m_socket);
        m_socket = nullptr;
    }

    m_connected = false;
}

} // namespace photon
