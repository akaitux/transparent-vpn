use std::{collections::HashSet, borrow::Borrow};
use std::path::PathBuf;
use std::error::Error;
use std::hash::{Hash, Hasher};
use tokio::{
    io::{AsyncWriteExt, AsyncBufReadExt, BufReader},
    fs::File,
};
use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};


const DEFAULT_DOMAINS_HASHSET_CAP: usize = 2_000_000;
// const DEFAULT_NXDOMAINS_HASHSET_CAP: usize = 500_000;


#[derive(Clone, Debug)]
pub struct Domain {
    domain: String,
}

impl Display for Domain {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.domain)
    }
}

impl Hash for Domain {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain.hash(state);
    }
}

impl PartialEq for Domain {
    fn eq(&self, other: &Self) -> bool {
        self.domain == other.domain
    }
}

impl Eq for Domain {}

impl Borrow<String> for Domain {
    fn borrow(&self) -> &String {
        &self.domain
    }
}

impl Borrow<str> for Domain {
    fn borrow(&self) -> &str {
        &self.domain.as_str()
    }
}

// impl ToString for Domain {
//     fn to_string(&self) -> String {
//         return self.domain.clone()
//     }
// }

impl Domain {
    pub fn new<S: Into<String>>(domain: S) -> Self {
        Domain {
            domain: domain.into(),
        }
    }

    pub fn as_str(&self) -> &str {
        self.domain.as_str()
    }
}


#[derive(Debug)]
pub struct Domains {
    domains: HashSet<Domain>,
}

impl Deref for Domains {
    type Target = HashSet<Domain>;

    fn deref(&self) -> &Self::Target {
        &self.domains
    }
}

impl DerefMut for Domains {

    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.domains
    }
}

impl Domains {
    pub fn new(hashset_cap: Option<usize>) -> Self {
        Self {
            domains: HashSet::with_capacity(hashset_cap.or(Some(DEFAULT_DOMAINS_HASHSET_CAP)).unwrap()),
        }
    }

    pub fn get(&self, domain: &str) -> Option<&Domain> {
        self.domains.get(domain)
    }

    pub fn get_copy(&self, domain: &str) -> Option<Domain> {
        let domain = self.domains.get(domain);
        if let Some(domain) = domain {
            return Some(domain.clone())
        }
        return None
    }

    pub fn count(&self) -> usize {
        self.domains.len()
    }

    pub fn set(&mut self, domain: &str) -> bool {
        self.domains.insert(Domain::new(domain))
    }

    pub async fn write_to_file(&self, write_to: &PathBuf) -> Result<(), Box<dyn Error>> {
        // Write to file 100 domains per operation
        let mut file = File::create(write_to).await?;
        let mut buf: Vec<&str> = Vec::with_capacity(100);
        for domain in &self.domains {
            if buf.len() == 100 {
                file.write(buf.join("\n").as_bytes()).await?;
                buf.clear();
            }
            buf.push(domain.as_str().clone());
        }
        if buf.len() != 0 {
            file.write(buf.join("\n").as_bytes()).await?;
        }
        file.flush().await?;
        Ok(())
    }

    pub async fn read_from_file(&mut self, read_from: &PathBuf) -> Result<(), Box<dyn Error>> {
        let file = File::open(read_from).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            self.domains.insert(Domain::new(line));
        }
        Ok(())
    }

    fn extend(&mut self, domains: HashSet<Domain>) {
        self.domains.extend(domains);
    }

    pub fn cleanup(&mut self) {
        self.domains = HashSet::with_capacity(DEFAULT_DOMAINS_HASHSET_CAP);
    }
}


