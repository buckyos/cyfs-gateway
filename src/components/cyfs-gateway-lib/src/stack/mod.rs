mod tcp_stack;
mod rtcp_stack;
mod udp_stack;
mod stack;
mod tls_stack;
mod quic_stack;
mod limiter;
mod tls_cert_resolver;

#[cfg(unix)]
use std::os::fd::AsRawFd;
use buckyos_kit::AsyncStream;
pub use tcp_stack::*;
pub use rtcp_stack::*;
pub use udp_stack::*;
pub use quic_stack::*;
pub use stack::*;
pub use tls_stack::*;
pub use tls_cert_resolver::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StackErrorCode {
    BindFailed,
    ProcessChainError,
    InvalidConfig,
    TunnelError,
    StreamError,
    InvalidTlsKey,
    InvalidTlsCert,
    ServerError,
    IoError,
    QuicError,
    UnsupportedStackProtocol,
    InvalidData,
    PermissionDenied,
    ListenFailed,
    AlreadyExists,
    BindUnmatched,
}
pub type StackResult<T> = sfo_result::Result<T, StackErrorCode>;
pub type StackError = sfo_result::Error<StackErrorCode>;
pub use sfo_result::into_err as into_stack_err;
pub use sfo_result::err as stack_err;
use url::Url;
use crate::{DatagramClientBox, TunnelManager};

pub(crate) async fn stream_forward(mut stream: Box<dyn AsyncStream>, target: &str, tunnel_manager: &TunnelManager) -> StackResult<()> {
    let url = Url::parse(target).map_err(into_stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward url {}",
                                    target
                                ))?;
    let mut forward_stream = tunnel_manager
        .open_stream_by_url(&url)
        .await
        .map_err(into_stack_err!(StackErrorCode::TunnelError))?;

    tokio::io::copy_bidirectional(&mut stream, forward_stream.as_mut())
        .await
        .map_err(into_stack_err!(StackErrorCode::StreamError, "target {target}"))?;
    Ok(())
}

pub(crate) async fn datagram_forward(datagram: Box<dyn DatagramClientBox>, target: &str, tunnel_manager: &TunnelManager) -> StackResult<()> {
    let url = Url::parse(&target).map_err(into_stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward url {}",
                                    target
                                ))?;
    let forward_datagram = tunnel_manager.create_datagram_client_by_url(&url).await
        .map_err(into_stack_err!(StackErrorCode::TunnelError))?;

    copy_datagram_bidirectional(datagram, forward_datagram).await
        .map_err(into_stack_err!(StackErrorCode::TunnelError))?;
    Ok(())
}

pub(crate) async fn copy_datagram_bidirectional(a: Box<dyn DatagramClientBox>, b: Box<dyn DatagramClientBox>) -> Result<(), std::io::Error> {
    let recv = {
        let a = a.clone();
        let b = b.clone();
        async move {
            loop {
                let mut buf = [0u8; 4096];
                let n = a.recv_datagram(&mut buf).await?;
                b.send_datagram(&buf[..n]).await?;
            }
            Ok::<(), std::io::Error>(())
        }
    };

    let send = async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = b.recv_datagram(&mut buf).await?;
            a.send_datagram(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };

    let ret = tokio::try_join!(recv, send);
    ret?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn sockaddr_to_socket_addr(addr: &libc::sockaddr_storage) -> std::io::Result<std::net::SocketAddr> {
    unsafe {
        match (*addr).ss_family as i32 {
            libc::AF_INET => {
                let addr_in: *const libc::sockaddr_in = addr as *const _ as *const libc::sockaddr_in;
                // 转换端口：网络字节序 -> 主机字节序
                let port = u16::from_be((*addr_in).sin_port);
                // 转换 IPv4 地址：网络字节序的 u32 -> Ipv4Addr
                // Ipv4Addr::from 直接接收一个 u32，并按网络字节序解释
                let ip_addr = std::net::Ipv4Addr::from((*addr_in).sin_addr.s_addr.to_le_bytes());
                Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip_addr, port)))
            }
            libc::AF_INET6 => {
                let addr_in6: *const libc::sockaddr_in6 = addr as *const _ as *const libc::sockaddr_in6;
                // 转换端口：网络字节序 -> 主机字节序
                let port = u16::from_be((*addr_in6).sin6_port);
                // 转换 IPv6 地址：直接使用 libc::sockaddr_in6 中的 sin6_addr 字段
                // sin6_addr 是一个包含 16 个 u8 的数组，表示 IPv6 地址的 128 位
                let segments = (*addr_in6).sin6_addr.s6_addr;
                let ipv6_addr = std::net::Ipv6Addr::from(segments);
                Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ipv6_addr, port, (*addr_in6).sin6_flowinfo, (*addr_in6).sin6_scope_id)))
            }
            _ => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "addr family must be either AF_INET or AF_INET6"))
            }, // 未知地址族
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn set_socket_opt<T: AsRawFd, V>(
    socket: &T,
    level: libc::c_int,
    name: libc::c_int,
    optval: V,
) -> StackResult<()> {
    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &optval as *const _ as *mut libc::c_void,
            std::mem::size_of::<V>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(stack_err!(
                            StackErrorCode::IoError,
                            "setsockopt error {}", std::io::Error::last_os_error()
                        ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn get_socket_opt<T: AsRawFd, V>(
    socket: &T,
    level: libc::c_int,
    name: libc::c_int,
    optval: &mut V,
) -> StackResult<libc::socklen_t> {
    unsafe {
        let mut len = std::mem::size_of::<V>() as libc::socklen_t;
        let ret = libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            optval as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return Err(stack_err!(
                            StackErrorCode::IoError,
                            "getsockopt error {}", std::io::Error::last_os_error()
                        ));
        }
        Ok(len)
    }
}

#[cfg(target_os = "linux")]
fn get_destination_addr(msg: &libc::msghdr) -> Option<libc::sockaddr_storage> {
    unsafe {
        let mut cmsg: *mut libc::cmsghdr = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let rcmsg = &*cmsg;
            match (rcmsg.cmsg_level, rcmsg.cmsg_type) {
                (libc::SOL_IP, libc::IP_RECVORIGDSTADDR) => {
                    let mut dst_addr: libc::sockaddr_storage = std::mem::zeroed();

                    std::ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut dst_addr as *mut _ as *mut _,
                        std::mem::size_of::<libc::sockaddr_in>(),
                    );

                    return Some(dst_addr);
                }
                (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR) => {
                    let mut dst_addr: libc::sockaddr_storage = std::mem::zeroed();

                    std::ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut dst_addr as *mut _ as *mut _,
                        std::mem::size_of::<libc::sockaddr_in6>(),
                    );

                    return Some(dst_addr);
                }
                _ => {}
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }

    None
}

#[cfg(target_os = "linux")]
pub(crate) fn recv_from<T: AsRawFd>(
    socket: &T,
    buf: &mut [u8]
) -> std::io::Result<(usize, std::net::SocketAddr, std::net::SocketAddr)> {
    unsafe {
        let mut control_buf = [0u8; 64];
        let mut src_addr: libc::sockaddr_storage = std::mem::zeroed();

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &mut src_addr as *mut _ as *mut _;
        msg.msg_namelen = std::mem::size_of_val(&src_addr) as libc::socklen_t;

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len() as libc::size_t,
        };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        msg.msg_control = control_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = TryFrom::try_from(control_buf.len())
            .expect("failed to convert usize to msg_controllen");

        let fd = socket.as_raw_fd();
        let ret = libc::recvmsg(fd, &mut msg, 0);
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let dst_addr = match get_destination_addr(&msg) {
            None => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "missing destination address in msghdr"));
            }
            Some(d) => d,
        };

        Ok((
            ret as usize,
            sockaddr_to_socket_addr(&src_addr)?,
            sockaddr_to_socket_addr(&dst_addr)?,
        ))
    }
}

#[cfg(target_os = "linux")]
fn has_root_privileges() -> bool {
    // 获取当前进程的有效用户ID (EUID)
    let euid: libc::uid_t = unsafe { libc::geteuid() };
    // Root 用户的 UID 为 0
    euid == 0
}
