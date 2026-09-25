//! wordstats: counts the words of texts and prints the most frequent ones,
//! leaving out stopwords ("the", "and", "of"…).
//!
//! ```text
//! wordstats [--stopwords FILE]... [--lang LANG]... [--top N] [--format text|json] [FILE]...
//! ```
//!
//! A stopword list is a text file with one word per line (`#` starts a
//! comment). `--lang LANG` loads `LANG.txt` from the directory named by the
//! `WORDSTATS_DATA` environment variable, and `WORDSTATS_FORMAT` sets the
//! default output format. Without files, standard input is read. Later
//! options override earlier ones.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::{env, fs};

const USAGE: &str = "usage: wordstats [--stopwords FILE]... [--lang LANG]... [--top N] [--format text|json] [FILE]...";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Text,
    Json,
}

impl Format {
    fn parse(name: &str) -> Result<Format, String> {
        match name {
            "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            other => Err(format!("unknown format \"{other}\" (expected text or json)")),
        }
    }
}

#[derive(Debug)]
struct Options {
    stopwords: Vec<PathBuf>,
    langs: Vec<String>,
    top: usize,
    format: Format,
    files: Vec<PathBuf>,
}

enum Error {
    Usage(String),
    Failed(String),
}

fn parse_args(args: impl IntoIterator<Item = String>, default_format: Format) -> Result<Option<Options>, String> {
    let mut options =
        Options { stopwords: Vec::new(), langs: Vec::new(), top: 10, format: default_format, files: Vec::new() };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--stopwords" => options.stopwords.push(PathBuf::from(value("--stopwords")?)),
            "--lang" => options.langs.push(value("--lang")?),
            "--top" => {
                let text = value("--top")?;
                options.top = text.parse().map_err(|_| format!("--top: \"{text}\" is not a number"))?;
            }
            "--format" => options.format = Format::parse(&value("--format")?)?,
            "--" => options.files.extend(args.by_ref().map(PathBuf::from)),
            flag if flag.starts_with('-') && flag != "-" => return Err(format!("unknown option {flag}")),
            file => options.files.push(PathBuf::from(file)),
        }
    }
    Ok(Some(options))
}

/// Reads a stopword list: one word per line, `#` comments.
fn read_stopwords(path: &PathBuf, into: &mut HashSet<String>) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read stopwords {}: {e}", path.display()))?;
    for line in text.lines() {
        let word = line.split('#').next().unwrap_or("").trim();
        if !word.is_empty() {
            into.insert(word.to_lowercase());
        }
    }
    Ok(())
}

/// The words of `text`, lowercased: runs of letters and digits, of at
/// least two characters, not made of digits only.
fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().nth(1).is_some() && !w.chars().all(|c| c.is_numeric()))
        .map(str::to_lowercase)
}

/// The `top` most frequent words, most frequent first (ties in
/// alphabetical order).
fn count(texts: &[String], stopwords: &HashSet<String>, top: usize) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for text in texts {
        for word in words(text).filter(|w| !stopwords.contains(w)) {
            *counts.entry(word).or_default() += 1;
        }
    }
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    sorted.truncate(top);
    sorted
}

fn render(counts: &[(String, usize)], format: Format) -> String {
    let mut out = String::new();
    match format {
        Format::Text => {
            for (word, n) in counts {
                let _ = writeln!(out, "{n:>6}  {word}");
            }
        }
        Format::Json => {
            out.push('[');
            for (i, (word, n)) in counts.iter().enumerate() {
                let sep = if i == 0 { "" } else { "," };
                let _ = write!(out, "{sep}{{\"word\":\"{}\",\"count\":{n}}}", json_escape(word));
            }
            out.push_str("]\n");
        }
    }
    out
}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn run() -> Result<(), Error> {
    let default_format = match env::var("WORDSTATS_FORMAT") {
        Ok(name) => Format::parse(&name).map_err(|e| Error::Usage(format!("WORDSTATS_FORMAT: {e}")))?,
        Err(_) => Format::Text,
    };
    let Some(options) = parse_args(env::args().skip(1), default_format).map_err(Error::Usage)? else {
        println!("{USAGE}");
        return Ok(());
    };

    let mut stopwords = HashSet::new();
    for path in &options.stopwords {
        read_stopwords(path, &mut stopwords).map_err(Error::Failed)?;
    }
    if !options.langs.is_empty() {
        let Some(data) = env::var_os("WORDSTATS_DATA") else {
            return Err(Error::Usage("--lang needs WORDSTATS_DATA to name a directory of stopword lists".into()));
        };
        for lang in &options.langs {
            let path = PathBuf::from(&data).join(format!("{lang}.txt"));
            read_stopwords(&path, &mut stopwords).map_err(Error::Failed)?;
        }
    }

    let mut texts = Vec::new();
    if options.files.is_empty() {
        let mut text = String::new();
        io::stdin().read_to_string(&mut text).map_err(|e| Error::Failed(format!("cannot read input: {e}")))?;
        texts.push(text);
    }
    for path in &options.files {
        let bytes = fs::read(path).map_err(|e| Error::Failed(format!("cannot read {}: {e}", path.display())))?;
        texts.push(String::from_utf8_lossy(&bytes).into_owned());
    }

    let output = render(&count(&texts, &stopwords, options.top), options.format);
    io::stdout().write_all(output.as_bytes()).map_err(|e| Error::Failed(format!("cannot write output: {e}")))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::Usage(message)) => {
            eprintln!("wordstats: {message}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Error::Failed(message)) => {
            eprintln!("wordstats: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_lowercased_runs_of_letters() {
        let found: Vec<String> = words("L'été, the Café; x 2026 à-la-carte").collect();
        assert_eq!(found, ["été", "the", "café", "la", "carte"]);
    }

    #[test]
    fn stopwords_are_left_out_and_ties_are_alphabetical() {
        let stopwords: HashSet<String> = ["the".to_string()].into();
        let texts = vec!["the cat and the dog, the cat".to_string()];
        let counts = count(&texts, &stopwords, 2);
        assert_eq!(counts, [("cat".to_string(), 2), ("and".to_string(), 1)]);
    }

    #[test]
    fn output_formats() {
        let counts = vec![("say \"hi\"".to_string(), 3)];
        assert_eq!(render(&counts, Format::Text), "     3  say \"hi\"\n");
        assert_eq!(render(&counts, Format::Json), "[{\"word\":\"say \\\"hi\\\"\",\"count\":3}]\n");
    }

    #[test]
    fn later_options_win() {
        let args = ["--top", "3", "a.txt", "--top", "5", "--format", "json"].map(String::from);
        let options = parse_args(args, Format::Text).unwrap().unwrap();
        assert_eq!((options.top, options.format), (5, Format::Json));
        assert_eq!(options.files, [PathBuf::from("a.txt")]);
        assert!(parse_args(["--top".to_string()], Format::Text).is_err());
        assert!(parse_args(["--bogus".to_string()], Format::Text).is_err());
    }
}
