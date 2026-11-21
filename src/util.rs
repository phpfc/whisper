//! Small helpers shared by several modules.
//!
//! No `crate::` references in here: the `stun_responder` example pulls this
//! file in with `#[path]` (the crate has no library target) because `stun.rs`
//! depends on it.

use std::io;

/// Windows fails a receive with WSAEMSGSIZE when the datagram is larger than
/// the buffer (other systems truncate it), and with WSAENETRESET when an ICMP
/// "TTL expired" arrives for an earlier send.
const WSAEMSGSIZE: i32 = 10040;
const WSAENETRESET: i32 = 10052;

/// Receive errors about a single datagram or an ICMP report for an earlier
/// send, not about the socket. Windows reports the port-unreachable caused by
/// probing a dead candidate as `ConnectionReset` on the next `recv_from`.
pub fn is_transient(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionReset
            | ConnectionRefused
            | HostUnreachable
            | NetworkUnreachable
            | Interrupted
            | WouldBlock
    ) || (cfg!(windows) && matches!(e.raw_os_error(), Some(WSAEMSGSIZE | WSAENETRESET)))
}

/// Splits a comma-separated list: entries are trimmed and empty ones dropped.
pub fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(String::from)
        .collect()
}

/// The list held by environment variable `name`; `None` when the variable is
/// unset or has no entries, so that an empty value means "use the default".
pub fn list_from_env(name: &str) -> Option<Vec<String>> {
    list_from(std::env::var(name).ok().as_deref())
}

fn list_from(raw: Option<&str>) -> Option<Vec<String>> {
    let list = parse_list(raw?);
    (!list.is_empty()).then_some(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_datagram_receive_errors_are_not_fatal() {
        use io::ErrorKind::*;
        assert!(is_transient(&ConnectionReset.into()));
        assert!(is_transient(&ConnectionRefused.into()));
        assert!(!is_transient(&InvalidInput.into()));
    }

    #[test]
    fn lists_are_split_on_commas_trimmed_and_stripped_of_empties() {
        assert_eq!(
            parse_list("10.0.0.2:6881, 10.0.0.3:6881 ,,\t, 10.0.0.4:6881,"),
            ["10.0.0.2:6881", "10.0.0.3:6881", "10.0.0.4:6881"]
        );
        assert_eq!(parse_list("only"), ["only"]);
        assert!(parse_list("").is_empty());
        assert!(parse_list(" , ,").is_empty());
    }

    #[test]
    fn an_unset_or_empty_variable_has_no_list() {
        assert_eq!(list_from(None), None);
        assert_eq!(list_from(Some("")), None);
        assert_eq!(list_from(Some(" , ")), None);
        assert_eq!(
            list_from(Some("a:1, b:2")),
            Some(vec!["a:1".into(), "b:2".into()])
        );
    }
}
