use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetIpNetTable, SendARP, MIB_IPNETTABLE,
};

use super::normalize_mac;
use crate::{lookup_err, LookupResult};

pub async fn lookup_mac_once(ip: IpAddr) -> LookupResult<Option<String>> {
    let target = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Ok(None),
    };

    tokio::task::spawn_blocking(move || lookup_mac_v4_from_table(target))
        .await
        .map_err(|e| lookup_err!("lookup mac task for {} failed: {}", ip, e))?
}

pub async fn active_probe(ip: IpAddr) -> LookupResult<()> {
    let target = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Ok(()),
    };

    tokio::task::spawn_blocking(move || {
        let mut mac = [0u8; 8];
        let mut len = mac.len() as u32;
        let dest_ip = u32::from_be_bytes(target.octets());
        let status = unsafe { SendARP(dest_ip, 0, mac.as_mut_ptr() as *mut _, &mut len) };
        if status == NO_ERROR {
            Ok(())
        } else {
            Err(lookup_err!("SendARP for {} failed with code {}", target, status))
        }
    })
    .await
    .map_err(|e| lookup_err!("active probe task for {} failed: {}", ip, e))?
}

fn lookup_mac_v4_from_table(target: Ipv4Addr) -> LookupResult<Option<String>> {
    unsafe {
        let mut size: u32 = 0;
        let mut status = GetIpNetTable(std::ptr::null_mut(), &mut size, 0);
        if status != ERROR_INSUFFICIENT_BUFFER && status != NO_ERROR {
            return Err(lookup_err!(
                "GetIpNetTable size query for {} failed with code {}",
                target,
                status
            ));
        }

        if size < size_of::<MIB_IPNETTABLE>() as u32 {
            size = size_of::<MIB_IPNETTABLE>() as u32;
        }

        let mut buf = vec![0u8; size as usize];
        let table_ptr = buf.as_mut_ptr() as *mut MIB_IPNETTABLE;
        status = GetIpNetTable(table_ptr, &mut size, 0);
        if status != NO_ERROR {
            return Err(lookup_err!(
                "GetIpNetTable read for {} failed with code {}",
                target,
                status
            ));
        }

        let table = &*table_ptr;
        let count = table.dwNumEntries as usize;
        let first_row = table.table.as_ptr();
        for index in 0..count {
            let row_ptr = first_row.add(index);
            let row = &*row_ptr;
            let row_ip_be = Ipv4Addr::from(row.dwAddr.to_be_bytes());
            let row_ip_ne = Ipv4Addr::from(row.dwAddr.to_ne_bytes());
            if row_ip_be == target || row_ip_ne == target {
                let len = (row.dwPhysAddrLen as usize).min(row.bPhysAddr.len());
                return Ok(normalize_mac(&row.bPhysAddr[..len]));
            }
        }
    }
    Ok(None)
}
