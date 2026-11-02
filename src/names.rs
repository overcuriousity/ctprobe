//! Name normalisation, registered domains and homoglyph skeletons.

const MAX_NAME: usize = 253;

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Lowercases and validates a DNS name, keeping a leading `*.`. Returns `None`
/// for anything that is not a hostname, including IP addresses.
pub fn normalize(name: &str) -> Option<String> {
    let trimmed = name.trim().trim_end_matches('.');
    let (wild, host) = match trimmed.strip_prefix("*.") {
        Some(h) => (true, h),
        None => (false, trimmed),
    };
    if host.is_empty() {
        return None;
    }
    let host = if host.is_ascii() {
        host.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(host).ok()?
    };
    if host.len() > MAX_NAME || !host.split('.').all(valid_label) {
        return None;
    }
    if host.rsplit('.').next().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some(if wild { format!("*.{host}") } else { host })
}

/// The registered domain per the Public Suffix List, private section included.
pub fn registered_domain(name: &str) -> Option<String> {
    let host = name.strip_prefix("*.").unwrap_or(name);
    psl::domain_str(host).map(str::to_string)
}

/// Unicode UTS #39 skeleton of a name, with punycode labels decoded first.
pub fn skeleton(name: &str) -> String {
    let (unicode, _) = idna::domain_to_unicode(name);
    unicode_security::confusable_detection::skeleton(&unicode).collect::<String>().to_lowercase()
}

/// Number of labels left of the registered domain.
pub fn depth(name: &str) -> u8 {
    let Some(reg) = registered_domain(name) else { return 0 };
    let total = name.split('.').count();
    total.saturating_sub(reg.split('.').count()).min(u8::MAX as usize) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_names() {
        assert_eq!(normalize("Example.COM.").as_deref(), Some("example.com"));
        assert_eq!(normalize("*.Foo.org").as_deref(), Some("*.foo.org"));
        assert_eq!(normalize("10.0.0.1"), None);
        assert_eq!(normalize("Acme Corp"), None);
        assert_eq!(normalize("bücher.de").as_deref(), Some("xn--bcher-kva.de"));
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("a..b.com"), None);
        assert_eq!(normalize("*.*.foo.org"), None);
        assert_eq!(normalize("localhost").as_deref(), Some("localhost"));
    }

    #[test]
    fn registered_domains() {
        assert_eq!(registered_domain("a.b.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registered_domain("foo.github.io").as_deref(), Some("foo.github.io"));
        assert_eq!(registered_domain("*.foo.github.io").as_deref(), Some("foo.github.io"));
        assert_eq!(registered_domain("localhost"), None);
        assert_eq!(registered_domain("co.uk"), None);
    }

    #[test]
    fn skeleton_folds_confusables() {
        assert_eq!(skeleton("xn--pypal-4ve.com"), skeleton("paypal.com"));
        assert_eq!(skeleton("rnicrosoft.com"), skeleton("microsoft.com"));
        assert_ne!(skeleton("paypal.com"), skeleton("google.com"));
    }

    #[test]
    fn depth_counts_labels_left_of_registered_domain() {
        assert_eq!(depth("example.com"), 0);
        assert_eq!(depth("a.b.example.com"), 2);
        assert_eq!(depth("*.example.com"), 1);
        assert_eq!(depth("localhost"), 0);
    }
}
