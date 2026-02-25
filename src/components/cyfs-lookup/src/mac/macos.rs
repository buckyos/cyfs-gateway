use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::ptr;

use super::normalize_mac;
use crate::{lookup_err, LookupResult};

pub async fn lookup_mac_once(ip: IpAddr) -> LookupResult<Option<String>> {
    let target = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Ok(None),
    };

    tokio::task::spawn_blocking(move || lookup_mac_sync(target))
        .await
        .map_err(|e| lookup_err!("lookup mac task for {} failed: {}", ip, e))?
}

fn lookup_mac_sync(target: Ipv4Addr) -> LookupResult<Option<String>> {
    unsafe {
        let mut mib = [
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            libc::AF_INET,
            libc::NET_RT_FLAGS,
            libc::RTF_LLINFO,
        ];

        let mut needed: libc::size_t = 0;
        if libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            ptr::null_mut(),
            &mut needed,
            ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(lookup_err!("sysctl size query for {} failed", target));
        }

        if needed == 0 {
            return Ok(None);
        }

        let mut buf = vec![0u8; needed];
        if libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            buf.as_mut_ptr() as *mut _,
            &mut needed,
            ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(lookup_err!("sysctl arp table query for {} failed", target));
        }

        let mut offset = 0usize;
        while offset + mem::size_of::<libc::rt_msghdr>() <= needed {
            let rtm = &*(buf.as_ptr().add(offset) as *const libc::rt_msghdr);
            if rtm.rtm_msglen == 0 {
                break;
            }

            let msg_len = rtm.rtm_msglen as usize;
            if offset + msg_len > needed {
                break;
            }

            let mut sa_ptr = (buf.as_ptr().add(offset) as *const u8).add(mem::size_of::<libc::rt_msghdr>());
            let mut dst_ip: Option<Ipv4Addr> = None;
            let mut mac: Option<String> = None;

            for i in 0..libc::RTAX_MAX {
                if (rtm.rtm_addrs & (1 << i)) == 0 {
                    continue;
                }

                let sa = &*(sa_ptr as *const libc::sockaddr);
                let sa_len = if sa.sa_len == 0 { mem::size_of::<libc::sockaddr>() } else { sa.sa_len as usize };
                if sa_len == 0 {
                    break;
                }

                if i == libc::RTAX_DST && sa.sa_family as i32 == libc::AF_INET {
                    let sin = &*(sa_ptr as *const libc::sockaddr_inarp);
                    let bytes = sin.sin_addr.s_addr.to_be_bytes();
                    dst_ip = Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
                }

                if i == libc::RTAX_GATEWAY && sa.sa_family as i32 == libc::AF_LINK {
                    let sdl = &*(sa_ptr as *const libc::sockaddr_dl);
                    if sdl.sdl_alen as usize >= 6 {
                        let nlen = sdl.sdl_nlen as usize;
                        let base = sdl.sdl_data.as_ptr() as *const u8;
                        let addr_ptr = base.add(nlen);
                        let mac_slice = std::slice::from_raw_parts(addr_ptr, sdl.sdl_alen as usize);
                        mac = normalize_mac(mac_slice);
                    }
                }

                sa_ptr = sa_ptr.add((sa_len + (mem::size_of::<usize>() - 1)) & !(mem::size_of::<usize>() - 1));
            }

            if dst_ip == Some(target) {
                if mac.is_some() {
                    return Ok(mac);
                }
            }

            offset += msg_len;
        }
    }

    Ok(None)
}
