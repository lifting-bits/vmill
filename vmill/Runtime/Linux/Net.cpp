/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace {

static Memory *SysSocket(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int domain = 0;
  int type = 0;
  int protocol = 0;
  if (!syscall.TryGetArgs(memory, state, &domain, &type, &protocol)) {
    STRACE_ERROR(socket, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto fd = socket(domain, type, protocol);
  if (-1 == fd) {
    auto err = errno;
    STRACE_ERROR(socket, "Couldn't open socket: %s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(socket, "domain=%d, type=%d, protocol=%d, fd=%d",
                   domain, type, protocol, fd);
    return syscall.SetReturn(memory, state, fd);
  }
}

static Memory *SysBind(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  int sockfd = -1;
  addr_t addr = 0;
  socklen_t addrlen = 0;
  if (!syscall.TryGetArgs(memory, state, &sockfd, &addr, &addrlen)) {
    STRACE_ERROR(bind, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct sockaddr addr_val = {};
  if (addr) {
    if (!TryReadMemory(memory, addr, &addr_val)) {
      STRACE_ERROR(bind, "Couldn't read address");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  auto ret = bind(sockfd, (addr ? &addr_val : nullptr), addrlen);
  if (!addr_val.sa_data[0] && addr_val.sa_data[1]) {
    addr_val.sa_data[0] = '@';  // For printing.
  }

  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(bind, "fd=%d, sa_data=%s, addrlen=%u: %s",
                 sockfd, addr_val.sa_data, addrlen, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(bind, "fd=%d, sa_data=%s, addrlen=%u, ret=%d",
                   sockfd, addr_val.sa_data, addrlen, ret);
    return syscall.SetReturn(memory, state, ret);
  }
}

static Memory *SysConnect(Memory *memory, State *state,
                          const SystemCallABI &syscall) {
  int sockfd = -1;
  addr_t addr = 0;
  socklen_t addrlen = 0;
  if (!syscall.TryGetArgs(memory, state, &sockfd, &addr, &addrlen)) {
    STRACE_ERROR(connect, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  linux_sockaddr info = {};

  if (static_cast<size_t>(addrlen) > sizeof(info)) {
    STRACE_ERROR(connect, "addrlen=%u out of bounds", addrlen);
    return syscall.SetReturn(memory, state, -EINVAL);
  }
  if (addrlen) {
    if (!TryReadMemory(memory, addr, &info)) {
      STRACE_ERROR(connect, "Couldn't read address");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  auto ret = connect(sockfd, (addrlen ? &info : nullptr), addrlen);
  if (!info.sa_data[0] && info.sa_data[1]) {
    info.sa_data[0] = '@';  // For printing.
  }

  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(
        connect, "fd=%d, sa_data=%s, addrlen=%u: %s",
        sockfd, info.sa_data, addrlen, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(connect, "fd=%d, sa_data=%sd, addrlen=%u, ret=%d",
                   sockfd, info.sa_data, addrlen, ret);
    return syscall.SetReturn(memory, state, ret);
  }
}

static Memory *SysListen(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int sockfd = -1;
  int backlog = 0;
  if (!syscall.TryGetArgs(memory, state, &sockfd, &backlog)) {
    STRACE_ERROR(listen, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto ret = listen(sockfd, backlog);
  if (-1 == ret) {
    auto err = errno;
    STRACE_ERROR(listen, "Couldn't listend to socket %d: %s",
                 sockfd, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(listen, "fd=%d, backlog=%d, ret=%d", sockfd, backlog, ret);
    return syscall.SetReturn(memory, state, ret);
  }
}

static Memory *DoSysAccept(Memory *memory, State *state,
                           const SystemCallABI &syscall,
                           int fd, addr_t addr, addr_t addrlen_addr,
                           int flags) {
  socklen_t addrlen = 0;
  static linux_sockaddr info = {};

  if (addr) {
    if (!TryReadMemory(memory, addrlen_addr, &addrlen)) {
      STRACE_ERROR(accept_generic, "Can't read address length");
      return syscall.SetReturn(memory, state, -EFAULT);
    }

    if (static_cast<size_t>(addrlen) > sizeof(linux_sockaddr)) {
      STRACE_ERROR(accept_generic, "addrlen=%u out of bounds", addrlen);
      return syscall.SetReturn(memory, state, -EINVAL);
    }

    if (!TryReadMemory(memory, addr, &info)) {
      STRACE_ERROR(
          accept_generic,
          "Can't read or write addrlen=%u bytes of addr=%" PRIxADDR,
          addrlen, addr);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  auto orig_addrlen = addrlen;
  auto ret_fd = accept4(fd, &info, &addrlen, flags);

  if (-1 == ret_fd) {
    auto err = errno;
    STRACE_ERROR(accept_generic, "Can't accept on fd %d: %s",
                 fd, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  if (addr) {
    memory = CopyToMemory(memory, addr, &info, orig_addrlen);
  }
  if (addrlen_addr) {
    if (!TryWriteMemory(memory, addrlen_addr, addrlen)) {
      STRACE_ERROR(accept_generic, "Can't write address length.");
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  STRACE_SUCCESS(accept_generic, "fd=%d, flags=%d, ret_fd=%d",
                 fd, flags, ret_fd);

  return syscall.SetReturn(memory, state, ret_fd);
}

static Memory *SysAccept(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int fd = -1;
  addr_t addr = 0;
  addr_t addr_len = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &addr, &addr_len)) {
    STRACE_ERROR(accept, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  return DoSysAccept(memory, state, syscall, fd, addr, addr_len, 0);
}

static Memory *SysAccept4(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int fd = -1;
  addr_t addr = 0;
  addr_t addr_len = 0;
  int flags = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &addr, &addr_len, &flags)) {
    STRACE_ERROR(accept4, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  return DoSysAccept(memory, state, syscall, fd, addr, addr_len, flags);
}

static Memory *SysGetSockName(Memory *memory, State *state,
                              const SystemCallABI &syscall) {
  int fd = -1;
  addr_t addr = 0;
  addr_t addrlen_addr = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &addr, &addrlen_addr)) {
    STRACE_ERROR(getsockname, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  socklen_t addrlen = 0;
  if (!TryReadMemory(memory, addrlen_addr, &addrlen)) {
    STRACE_ERROR(getsockname, "Couldn't copy sock len.");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (static_cast<size_t>(addrlen) > sizeof(linux_sockaddr)) {
    STRACE_ERROR(getsockname, "addrlen=%u out of bounds", addrlen);
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  linux_sockaddr info = {};
  if (!TryReadMemory(memory, addr, &info)) {
    STRACE_ERROR(getsockname, "Couldn't copy sock address to/from memory.");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  const auto orig_addrlen = addrlen;
  if (!getsockname(fd, &info, &addrlen)) {
    if (addr) {
      CopyToMemory(memory, addr, &info, orig_addrlen);
    }

    if (!TryWriteMemory(memory, addrlen_addr, addrlen)) {
      STRACE_ERROR(getsockname, "Couldn't copy sock address to memory.");
      return syscall.SetReturn(memory, state, -EFAULT);
    } else {
      STRACE_SUCCESS(getsockname, "sa_family=%u, addrlen=%u",
                     info.sa_family, addrlen);
      return syscall.SetReturn(memory, state, 0);
    }
  } else {
    auto err = errno;
    STRACE_ERROR(getsockname, "Error: %s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }
}

static Memory *SysGetPeerName(Memory *memory, State *state,
                              const SystemCallABI &syscall) {
  int fd = -1;
  addr_t addr = 0;
  addr_t addrlen_addr = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &addr, &addrlen_addr)) {
    STRACE_ERROR(getpeername, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  socklen_t addrlen = 0;
  if (!TryReadMemory(memory, addrlen_addr, &addrlen)) {
    STRACE_ERROR(getpeername, "Couldn't copy sock len.");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (static_cast<size_t>(addrlen) > sizeof(linux_sockaddr)) {
    STRACE_ERROR(getpeername, "addrlen=%u out of bounds", addrlen);
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  linux_sockaddr info = {};
  if (!TryReadMemory(memory, addr, &info)) {
    STRACE_ERROR(getpeername, "Couldn't copy sock address to/from memory.");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  const auto orig_addrlen = addrlen;
  if (!getpeername(fd, &info, &addrlen)) {
    CopyToMemory(memory, addr, &info, orig_addrlen);
    if (!TryWriteMemory(memory, addrlen_addr, addrlen)) {
      STRACE_ERROR(getpeername, "Couldn't copy sock address to memory.");
      return syscall.SetReturn(memory, state, -EFAULT);

    } else {
      STRACE_SUCCESS(getpeername, "sa_family=%u addrlen=%u",
                     info.sa_family, addrlen);
      return syscall.SetReturn(memory, state, 0);
    }
  } else {
    auto err = errno;
    STRACE_ERROR(getpeername, "Error: %s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }
}

struct SocketVector {
  int pair[2];
} __attribute__((packed));

static Memory *SysSocketPair(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  int domain = 0;
  int type = 0;
  int protocol = 0;
  addr_t socket_vector = 0;
  if (!syscall.TryGetArgs(memory, state, &domain, &type,
                          &protocol, &socket_vector)) {
    STRACE_ERROR(socketpair, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  SocketVector vec = {};
  if (!TryReadMemory(memory, socket_vector, &vec)) {
    STRACE_ERROR(socketpair, "Couldn't read vector from memory");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!socketpair(domain, type, protocol, vec.pair)) {
    if (!TryWriteMemory(memory, socket_vector, vec)) {
      STRACE_ERROR(socketpair, "Couldn't write vector to memory");
      return syscall.SetReturn(memory, state, -EFAULT);
    } else {
      STRACE_SUCCESS(socketpair, "domain=%d, type=%d, protocol=%d",
                     domain, type, protocol);
      return syscall.SetReturn(memory, state, 0);
    }
  } else {
    auto err = errno;
    STRACE_ERROR(socketpair, "Error: %s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }
}

static Memory *DoSysSendTo(Memory *memory, State *state,
                           const SystemCallABI &syscall,
                           int fd, addr_t buf, size_t n, int flags,
                           addr_t addr, socklen_t addrlen) {

  if (static_cast<size_t>(addrlen) > sizeof(linux_sockaddr)) {
    STRACE_ERROR(sendto, "addrlen=%u out of bounds", addrlen);
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  if (!n) {
    STRACE_ERROR(sendto, "empty buffer");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  linux_sockaddr info = {};
  if (addrlen) {
    if (!TryReadMemory(memory, addr, &info)) {
      STRACE_ERROR(sendto, "Can't read addrlen=%u bytes from addr=%" PRIxADDR,
                   addrlen, addr);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (!CanReadMemory(memory, buf, n)) {
    STRACE_ERROR(sendto, "Can't read n=%zu bytes from buf=%" PRIxADDR,
                 n, buf);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto buf_val = new uint8_t[n];
  CopyFromMemory(memory, buf_val, buf, n);

  auto ret = sendto(
      fd, buf_val, n, flags, (addrlen ? &info : nullptr), addrlen);
  auto err = errno;
  delete[] buf_val;

  if (!info.sa_data[0] && info.sa_data[1]) {
    info.sa_data[0] = '@';  // For printing.
  }

  if (-1 == ret) {
    STRACE_ERROR(
        sendto, "fd=%d, n=%lu, sa_data=%s, addrlen=%u: %s",
        fd, n, info.sa_data, addrlen, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(
        sendto, "fd=%d, n=%lu, sa_data=%s, addrlen=%u",
        fd, n, info.sa_data, addrlen);
    return syscall.SetReturn(memory, state, ret);
  }
}

static Memory *SysSend(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  size_t n = 0;
  int flags = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &n, &flags)) {
    STRACE_ERROR(send, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  return DoSysSendTo(memory, state, syscall, fd, buf, n, flags, 0, 0);
}

static Memory *SysSendTo(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  size_t n = 0;
  int flags = 0;
  addr_t addr = 0;
  socklen_t addr_len = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &n, &flags,
                          &addr, &addr_len)) {
    STRACE_ERROR(sendto, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  return DoSysSendTo(memory, state, syscall, fd, buf, n, flags, addr, addr_len);
}

static Memory *DoSysRecvFrom(Memory *memory, State *state,
                             const SystemCallABI &syscall,
                             int fd, addr_t buf, size_t n, unsigned flags,
                             addr_t addr, addr_t addrlen_addr) {
  if (!n) {
    STRACE_ERROR(recvfrom, "Empty buffer");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  linux_sockaddr info = {};
  socklen_t addrlen = 0;
  if (addrlen_addr) {
    if (!TryReadMemory(memory, addrlen_addr, &addrlen)) {
      STRACE_ERROR(recvfrom, "Can't read addrlen from %" PRIxADDR,
                   addrlen_addr);
      return syscall.SetReturn(memory, state, -EFAULT);
    }

    if (static_cast<size_t>(addrlen) > sizeof(linux_sockaddr)) {
      STRACE_ERROR(recvfrom, "addrlen=%u out of bounds", addrlen);
      return syscall.SetReturn(memory, state, -EINVAL);
    }

    if (addrlen) {
      if (!TryReadMemory(memory, addr, &info)) {
        STRACE_ERROR(recvfrom, "Can't read addrlen=%u byte addr=%" PRIxADDR,
                     addrlen, addr);
        return syscall.SetReturn(memory, state, -EFAULT);
      }
    }
  }

  auto buf_val = new uint8_t[n];

  CopyFromMemory(memory, buf_val, buf, n);

  const auto orig_addrlen = addrlen;
  auto ret = recvfrom(fd, buf_val, n, static_cast<int>(flags), &info, &addrlen);
  auto err = errno;

  if (!CanWriteMemory(memory, buf, n)) {
    delete[] buf_val;
    STRACE_ERROR(recvfrom, "Can't write n=%lu bytes to buf=%" PRIxADDR, n, buf);
    return syscall.SetReturn(memory, state, -EFAULT);

  } else {
    CopyToMemory(memory, buf, buf_val, n);
    delete[] buf_val;
  }

  if (orig_addrlen) {
    if (!CanWriteMemory(memory, addr, orig_addrlen)) {
      STRACE_ERROR(
          recvfrom, "Can't write addrlen=%u bytes to addr=%" PRIxADDR,
          addrlen, addr);
      return syscall.SetReturn(memory, state, -EFAULT);
    }

    CopyToMemory(memory, addr, &info, orig_addrlen);

    if (!TryWriteMemory(memory, addrlen_addr, addrlen)) {
      STRACE_ERROR(
          recvfrom, "Can't write addrlen=%u to %" PRIxADDR,
          addrlen, addrlen_addr);
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (-1 == ret) {
    STRACE_ERROR(recvfrom, "%s", strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(recvfrom, "n=%lu buf=%" PRIxADDR " addrlen=%u",
                   n, buf, addrlen);
    return syscall.SetReturn(memory, state, ret);
  }
}

static Memory *SysRecv(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  size_t n = 0;
  unsigned flags = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &n, &flags)) {
    STRACE_ERROR(recv, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  return DoSysRecvFrom(memory, state, syscall, fd, buf, n, flags, 0, 0);
}

static Memory *SysRecvFrom(Memory *memory, State *state,
                           const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  size_t n = 0;
  unsigned flags = 0;
  addr_t addr = 0;
  addr_t addr_len = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &n, &flags,
                          &addr, &addr_len)) {
    STRACE_ERROR(recvfrom, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  return DoSysRecvFrom(memory, state, syscall, fd, buf, n,
                       flags, addr, addr_len);
}

static Memory *SysShutdown(Memory *memory, State *state,
                           const SystemCallABI &syscall) {
  int socket = -1;
  int how = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &how)) {
    STRACE_ERROR(shutdown, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!shutdown(socket, how)) {
    STRACE_SUCCESS(shutdown, "socket=%d how=%d", socket, how);
    return syscall.SetReturn(memory, state, 0);
  } else {
    auto err = errno;
    STRACE_ERROR(shutdown, "socket=%d how=%d: %s", socket, how, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }
}

// TODO(pag): Not clear how to make a compatibility version of this.
static Memory *SysSetSockOpt(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  int socket = -1;
  int level = 0;
  int option_name = 0;
  addr_t optval = 0;
  socklen_t optlen = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &level, &option_name,
                          &optval, &optlen)) {
    STRACE_ERROR(setsockopt, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!optlen) {
    STRACE_ERROR(setsockopt, "Zero-length socket option");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  if (!CanReadMemory(memory, optval, optlen)) {
    STRACE_ERROR(
        setsockopt, "Can't read optlen=%u bytes from optval=%" PRIxADDR,
        optlen, optval);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto option_value_data = new uint8_t[optlen];
  CopyFromMemory(memory, option_value_data, optval, optlen);

  auto ret = setsockopt(socket, level, option_name,
                        option_value_data, optlen);

  auto err = errno;
  delete[] option_value_data;

  if (-1 == ret) {
    STRACE_ERROR(
        setsockopt, "socket=%d, optlen=%u, optval=%" PRIxADDR ": %s",
        socket, optlen, optval, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(
        setsockopt, "socket=%d, optlen=%u, optval=%" PRIxADDR ": ret=%d",
        socket, optlen, optval, ret);
    return syscall.SetReturn(memory, state, ret);
  }
}

// TODO(pag): Not clear how to make a compatibility version of this.
static Memory *SysGetSockOpt(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  int socket = -1;
  int level = 0;
  int option_name = 0;
  addr_t optval = 0;
  addr_t optlen_ptr = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &level, &option_name,
                          &optval, &optlen_ptr)) {
    STRACE_ERROR(getsockopt, "Can't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  socklen_t optlen = 0;
  if (!TryReadMemory(memory, optlen_ptr, &optlen)) {
    STRACE_ERROR(getsockopt, "Can't read optlen_ptr=%" PRIxADDR,
                 optlen_ptr);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!CanReadMemory(memory, optval, optlen)) {
    STRACE_ERROR(
        getsockopt, "Can't read all optlen_ptr=%u bytes from optval=%" PRIxADDR,
        optlen, optval);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!optlen) {
    STRACE_ERROR(getsockopt, "Zero-length optval");
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  auto option_value_data = new uint8_t[optlen];
  CopyFromMemory(memory, option_value_data, optval, optlen);

  auto ret = getsockopt(socket, level, option_name,
                        option_value_data, &optlen);

  if (-1 == ret) {
    auto err = errno;
    delete[] option_value_data;
    STRACE_ERROR(getsockopt, "socket=%u optlen=%u: %s", socket, optlen,
                 strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  if (!CanWriteMemory(memory, optval, optlen)) {
    delete[] option_value_data;
    STRACE_ERROR(getsockopt, "Can't write optlen=%u bytes to optval=%" PRIxADDR,
                 optlen, optval);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!TryWriteMemory(memory, optlen_ptr, &optlen)) {
    delete[] option_value_data;
    STRACE_ERROR(getsockopt, "Can't write optlen=%u to optlen_ptr=%" PRIxADDR,
                 optlen, optlen_ptr);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  CopyToMemory(memory, optval, option_value_data, optlen);
  delete[] option_value_data;

  STRACE_SUCCESS(
      getsockopt, "socket=%d, optlen=%u, optval=%" PRIxADDR ": ret=%d",
      socket, optlen, optval, ret);
  return syscall.SetReturn(memory, state, ret);
}

template <typename IOVecT>
struct IOVec final : public iovec {
  IOVec(void) {
    iov_base = nullptr;
    iov_len = 0;
  }

  int Import(Memory *&memory, IOVecT &compat) {
    if (!compat.iov_base) {
      compat.iov_len = 0;
    }

    if (0 > compat.iov_len) {
      return EINVAL;
    }

    if (!CanReadMemory(memory, compat.iov_base, compat.iov_len)) {
      return EFAULT;
    }

    iov_len = compat.iov_len;
    iov_base = new uint8_t[iov_len];
    CopyFromMemory(memory, iov_base, compat.iov_base, iov_len);
    return 0;
  }

  int Export(Memory *&memory, IOVecT &compat) {
    if (iov_len) {
      if (!CanWriteMemory(memory, compat.iov_base, iov_len)) {
        return EFAULT;
      }
      CopyToMemory(memory, compat.iov_base, iov_base, iov_len);
    }
    compat.iov_len = static_cast<decltype(compat.iov_len)>(iov_len);
    return 0;
  }

  ~IOVec(void) {
    if (iov_base) {
      delete[] reinterpret_cast<uint8_t *>(iov_base);
    }
  }
};

template <typename MsgHdrT, typename IOVecT>
struct MessageHeader final : public msghdr {

  MessageHeader(void)
      : orig_iov(nullptr) {
    msg_name = nullptr;
    msg_namelen = 0;
    msg_iov = nullptr;
    msg_iovlen = 0;
    msg_control = nullptr;
    msg_controllen = 0;
    msg_flags = 0;
  }

  int Import(Memory *&memory, MsgHdrT &compat) {
    if (!compat.msg_name) {
      compat.msg_namelen = 0;
    }
    if (!compat.msg_iov) {
      compat.msg_iovlen = 0;
    }
    if (!compat.msg_control) {
      compat.msg_controllen = 0;
    }

    if (0 > compat.msg_namelen || 0 > compat.msg_iovlen ||
        0 > compat.msg_controllen) {
      return EINVAL;
    }

    if (compat.msg_namelen) {
      if (!CanReadMemory(memory, compat.msg_name, compat.msg_namelen)) {
        return EFAULT;
      }

      // Import the message name.
      msg_namelen = compat.msg_namelen;
      msg_name = new uint8_t[msg_namelen];
      CopyFromMemory(memory, msg_name, compat.msg_name, msg_namelen);
    }

    if (compat.msg_iovlen) {
      auto total_len = compat.msg_iovlen * sizeof(IOVecT);
      if (!CanReadMemory(memory, compat.msg_iov, total_len)) {
        return EFAULT;
      }

      msg_iovlen = compat.msg_iovlen;
      orig_iov = new IOVecT[msg_iovlen];
      CopyFromMemory(memory, orig_iov, compat.msg_iov, total_len);

      auto iov = new IOVec<IOVecT>[msg_iovlen];
      msg_iov = iov;

      // Import each io vector and their associated data.
      for (auto i = 0U; i < msg_iovlen; ++i) {
        if (auto ret = iov[i].Import(memory, orig_iov[i])) {
          return ret;
        }
      }
    }

    if (compat.msg_control) {
      if (!CanReadMemory(memory, compat.msg_control, compat.msg_controllen)) {
        return EFAULT;
      }

      msg_controllen = compat.msg_controllen;
      msg_control = new uint8_t[msg_controllen];
      CopyFromMemory(memory, msg_control, compat.msg_control, msg_controllen);
    }

    return 0;
  }

  int Export(Memory *&memory, MsgHdrT &compat) {
    if (msg_name) {
      if (!CanWriteMemory(memory, compat.msg_name, msg_namelen)) {
        return EFAULT;
      }
      CopyToMemory(memory, compat.msg_name, msg_name, msg_namelen);
    }

    if (msg_iov) {
      auto iov = reinterpret_cast<IOVec<IOVecT> *>(msg_iov);
      for (auto i = 0U; i < msg_iovlen; ++i) {
        if (auto ret = iov[i].Export(memory, orig_iov[i])) {
          return ret;
        }
      }
      if (!CanWriteMemory(memory, compat.msg_iov, msg_iovlen)) {
        return EFAULT;
      }

      auto total_len = msg_iovlen * sizeof(IOVecT);
      CopyToMemory(memory, compat.msg_iov, orig_iov, total_len);
    }

    if (msg_control) {
      if (!CanWriteMemory(memory, compat.msg_control, msg_controllen)) {
        return EFAULT;
      }
      CopyToMemory(memory, compat.msg_control, msg_control, msg_controllen);
    }

    compat.msg_flags = msg_flags;
    compat.msg_namelen = msg_namelen;
    compat.msg_iovlen = static_cast<decltype(compat.msg_iovlen)>(msg_iovlen);
    compat.msg_controllen = static_cast<decltype(compat.msg_controllen)>(
        msg_controllen);
    return 0;
  }

  ~MessageHeader(void) {
    if (msg_name) {
      delete[] reinterpret_cast<uint8_t *>(msg_name);
    }
    if (msg_iov) {
      delete[] reinterpret_cast<IOVec<IOVecT> *>(msg_iov);
    }
    if (orig_iov) {
      delete[] orig_iov;
    }
    if (msg_control) {
      delete[] reinterpret_cast<uint8_t *>(msg_control);
    }
  }

  IOVecT *orig_iov;
};

template <typename MsgHdrT, typename IOVecT>
static Memory *SysSendMsg(Memory *memory, State *state,
                          const SystemCallABI &syscall) {
  int socket = -1;
  addr_t message = 0;
  int flags = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &message, &flags)) {
    STRACE_ERROR(sendmsg, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  MsgHdrT compat_header = {};
  if (!TryReadMemory(memory, message, &compat_header)) {
    STRACE_ERROR(sendmsg, "socket=%d flags=%x: can't read message=%" PRIxADDR,
                 socket, flags, message);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  MessageHeader<MsgHdrT, IOVecT> header;
  auto err = header.Import(memory, compat_header);
  if (err) {
    STRACE_ERROR(sendmsg, "socket=%d flags=%x: %s",
                 socket, flags, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  auto ret = sendmsg(socket, &header, flags);
  if (-1 == ret) {
    err = errno;
    STRACE_ERROR(sendmsg, "socket=%d flags=%x: %s",
                 socket, flags, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  } else {
    STRACE_SUCCESS(sendmsg, "socket=%d flags=%x", socket, flags);
    return syscall.SetReturn(memory, state, ret);
  }
}

template <typename MsgHdrT, typename IOVecT>
static Memory *SysRecvMsg(Memory *memory, State *state,
                          const SystemCallABI &syscall) {
  int socket = -1;
  addr_t message = 0;
  int flags = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &message, &flags)) {
    STRACE_ERROR(recvmsg, "Couldn't get args");
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  MsgHdrT compat_header = {};
  if (!TryReadMemory(memory, message, &compat_header)) {
    STRACE_ERROR(recvmsg, "socket=%d flags=%x: can't read message=%" PRIxADDR,
                 socket, flags, message);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  MessageHeader<MsgHdrT, IOVecT> header;
  auto err = header.Import(memory, compat_header);
  if (err) {
    STRACE_ERROR(recvmsg, "socket=%d flags=%x: %s",
                 socket, flags, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  auto ret = recvmsg(socket, &header, flags);
  if (-1 == ret) {
    err = errno;
    STRACE_ERROR(recvmsg, "socket=%d flags=%x: %s",
                 socket, flags, strerror(err));
    return syscall.SetReturn(memory, state, -err);
  }

  err = header.Export(memory, compat_header);
  if (!TryWriteMemory(memory, message, compat_header)) {
    STRACE_ERROR(recvmsg, "socket=%d flags=%x: can't write message=%" PRIxADDR,
                 socket, flags, message);
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  STRACE_SUCCESS(
      recvmsg, "socket=%d, flags=%x, message=%" PRIxADDR ", ret=%ld",
      socket, flags, message, ret);
  return syscall.SetReturn(memory, state, ret);
}

#if 0

// TODO(pag): Eventually, to handle these we need to remove the `orig_iov`
//            from inside of the `MessageHeader` type.
template <typename MsgHdrT, typename IOVecT>
struct MultiMessageHeader {
  struct CompatType {
    MsgHdrT msg_hdr;
    unsigned msg_len;
  };

  MultiMessageHeader(void)
      : msg_hdr(),
        msg_len(0) {}

  int Import(Memory *&memory, CompatType &compat) {
    msg_len = compat.msg_len;
    return msg_hdr.Import(memory, compat.msg_hdr);
  }

  int Export(Memory *&memory, CompatType &compat) {
    compat.msg_len = msg_len;
    return msg_hdr.Export(memory, compat.msg_hdr);
  }

  MessageHeader<MsgHdrT, IOVecT> msg_hdr;
  unsigned msg_len;
};


extern "C" {

// Forward declarations, just in case we're compiling on a non-Linux OS
struct mmsghdr;

extern int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                    unsigned int flags);

extern int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                    unsigned int flags, struct timespec *timeout);
}  // extern C

template <typename MsgHdrT, typename IOVecT, typename TimeSpecT>
static Memory *SysRecvMmsg(Memory *memory, State *state,
                           const SystemCallABI &syscall) {
  using MmsgHdrT = typename MultiMessageHeader<MsgHdrT, IOVecT>::CompatType;

  int socket = -1;
  addr_t msgvec = 0;
  unsigned vlen = 0;
  unsigned flags = 0;
  addr_t timeout = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &msgvec, &vlen, &flags,
                          &timeout)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto total_size = sizeof(MmsgHdrT) * vlen;
  if (!CanReadMemory(memory, msgvec, total_size)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto compat_vec = new MmsgHdrT[vlen];
  auto vec = new MultiMessageHeader<MsgHdrT, IOVecT>[vlen];

  delete[] vec;
  delete[] compat_vec;

  MmsgHdrT compat_header = {};
  if (!TryReadMemory(memory, message, &compat_header)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  MessageHeader<MsgHdrT, IOVecT> header;
  auto err = header.Import(memory, compat_header);
  if (err) {
    return syscall.SetReturn(memory, state, -err);
  }

  auto ret = recvmsg(socket, &header, flags);
  if (-1 == ret) {
    auto err = errno;
    return syscall.SetReturn(memory, state, -err);
  }

  err = header.Export(memory, compat_header);
  if (!TryWriteMemory(memory, message, compat_header)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  return syscall.SetReturn(memory, state, ret);
}

#endif

#ifdef VMILL_RUNTIME_X86

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

// ABI for argument pack passed to the `socketcall` system call. This is
// parameterized by `AddrT` because if this is a 32-bit compatibility
// `socketcall` then all addresses and arguments must be treated as 32-bit
// values.
template <typename AddrT>
class SocketCallABI : public SystemCallABI {
 public:
  SocketCallABI(const SystemCallABI &syscall_, addr_t arg_addr_)
      : syscall(syscall_),
        arg_addr(arg_addr_),
        padding(0) {}

  virtual ~SocketCallABI(void) = default;

  addr_t GetPC(const State *state) const final {
    return syscall.GetPC(state);
  }

  void SetPC(State *state, addr_t new_pc) const final {
    syscall.SetPC(state, new_pc);
  }

  void SetSP(State *state, addr_t new_sp) const final {
    syscall.SetSP(state, new_sp);
  }

  addr_t GetReturnAddress(Memory *, addr_t ret_addr) const final {
    return ret_addr;
  }

  addr_t GetSystemCallNum(Memory *memory, State *state) const final {
    return syscall.GetSystemCallNum(memory, state);
  }

  Memory *DoSetReturn(Memory *memory, State *state,
                      addr_t ret_val) const final {
    return syscall.SetReturn(memory, state, ret_val);
  }

  bool CanReadArgs(Memory *memory, State *, int num_args) const final {
    return CanReadMemory(
        memory, arg_addr, static_cast<size_t>(num_args) * sizeof(AddrT));
  }

  addr_t GetArg(Memory *&memory, State *state, int i) const final {
    return ReadMemory<AddrT>(
        memory,
        arg_addr + static_cast<addr_t>(static_cast<addr_t>(i) * sizeof(AddrT)));
  }

  const SystemCallABI &syscall;
  addr_t arg_addr;
  uint32_t padding;
};

#pragma clang diagnostic pop

template <typename AddrT>
static Memory *SysSocketCall(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  int call = 0;
  AddrT args = 0;
  if (!syscall.TryGetArgs(memory, state, &call, &args)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (0 > call || call > SYS_SENDMMSG) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  SocketCallABI<AddrT> abi(syscall, args);
  switch (call) {
    case SYS_SOCKET:
      return SysSocket(memory, state, abi);
    case SYS_BIND:
      return SysBind(memory, state, abi);
    case SYS_CONNECT:
      return SysConnect(memory, state, abi);
    case SYS_LISTEN:
      return SysListen(memory, state, abi);
    case SYS_ACCEPT:
      return SysAccept(memory, state, abi);
    case SYS_GETSOCKNAME:
      return SysGetSockName(memory, state, abi);
    case SYS_GETPEERNAME:
      return SysGetPeerName(memory, state, abi);
    case SYS_SOCKETPAIR:
      return SysSocketPair(memory, state, abi);
    case SYS_SEND:
      return SysSend(memory, state, abi);
    case SYS_RECV:
      return SysRecv(memory, state, abi);
    case SYS_SENDTO:
      return SysSendTo(memory, state, abi);
    case SYS_RECVFROM:
      return SysRecvFrom(memory, state, abi);
    case SYS_SHUTDOWN:
      return SysShutdown(memory, state, abi);
    case SYS_SETSOCKOPT:
      return SysSetSockOpt(memory, state, abi);
    case SYS_GETSOCKOPT:
      return SysGetSockOpt(memory, state, abi);
    case SYS_SENDMSG:
      return SysSendMsg<linux32_msghdr, linux32_iovec>(memory, state, abi);
    case SYS_RECVMSG:
      return SysRecvMsg<linux32_msghdr, linux32_iovec>(memory, state, abi);
    case SYS_ACCEPT4:
      return SysAccept4(memory, state, abi);

    case SYS_RECVMMSG:
    case SYS_SENDMMSG:
    default:
      return abi.SetReturn(
          memory, state,
          static_cast<addr_t>(static_cast<addr_diff_t>(-ENOSYS)));
  }
}

#endif  // VMILL_RUNTIME_X86

}  // namespace
