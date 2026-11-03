//! Conservative recognition of extensionless CMS REXX source.

use super::text::{self, Controls};

pub(super) fn looks_like_cms_exec(data: &[u8]) -> bool {
    let data = data.get(..data.len().min(128 * 1024)).unwrap_or(data);
    if !data.trim_ascii_start().starts_with(b"/*") || text::is_binary(data, Controls::Script) {
        return false;
    }
    let mut in_comment = false;
    let mut say = false;
    let mut pull = false;
    let mut loop_stmt = false;
    let mut end = false;
    let mut execio = false;
    for line in data.split(|&b| b == b'\n') {
        let mut code = Vec::with_capacity(line.len());
        let mut i = 0;
        while let Some(&byte) = line.get(i) {
            if in_comment {
                if line.get(i..i + 2) == Some(b"*/") {
                    in_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
            } else if line.get(i..i + 2) == Some(b"/*") {
                in_comment = true;
                i += 2;
            } else {
                code.push(byte.to_ascii_uppercase());
                i += 1;
            }
        }
        let s = code.trim_ascii();
        say |= s.starts_with(b"SAY ");
        pull |= s.starts_with(b"PULL ");
        loop_stmt |= s.starts_with(b"DO WHILE ");
        end |= s == b"END" || s.starts_with(b"END ");
        execio |= s.starts_with(b"\"EXECIO ") || s.starts_with(b"'EXECIO ");
    }
    say && pull && loop_stmt && end && execio
}

#[cfg(test)]
mod tests {
    use super::looks_like_cms_exec;

    #[test]
    fn recognizes_cms_exec_but_not_comment_examples_or_binary() {
        let good = b"/* REXX */\nsay 'hello'\npull name\n\"EXECIO * DISKR FILE NAMES A (FIFO\"\ndo while queued() > 0\n say name\nend\n";
        assert!(looks_like_cms_exec(good));
        assert!(!looks_like_cms_exec(
            b"/*\nsay x\npull y\n\"EXECIO * DISKR\"\ndo while x\nend\n*/\n"
        ));
        assert!(!looks_like_cms_exec(
            b"/* text */\nsay x\npull y\ndo while x\nend\n"
        ));
        let mut binary = good.to_vec();
        binary.extend_from_slice(&[0; 32]);
        assert!(!looks_like_cms_exec(&binary));
    }
}
