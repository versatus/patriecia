/// Adapted from https://github.com/carver/eth-trie.rs which is a fork of https://github.com/citahub/cita-trie
/// Beware there's a significant amount of TODOs scattered around the file,
/// these will be addressed in due time.
///
use crate::{db::Database, inner::InnerTrie, nibbles::Nibbles, node::Node};

#[derive(Clone, Debug)]
enum TraceStatus {
    Start,
    Doing,
    Child(u8),
    End,
}

#[derive(Clone, Debug)]
struct TraceNode {
    node: Node,
    status: TraceStatus,
}

impl From<Node> for TraceNode {
    fn from(node: Node) -> TraceNode {
        TraceNode {
            node,
            status: TraceStatus::Start,
        }
    }
}

impl TraceNode {
    fn advance(&mut self) {
        self.status = match &self.status {
            TraceStatus::Start => TraceStatus::Doing,
            TraceStatus::Doing => match self.node {
                Node::Branch(_) => TraceStatus::Child(0),
                _ => TraceStatus::End,
            },
            TraceStatus::Child(i) if *i < 15 => TraceStatus::Child(i + 1),
            _ => TraceStatus::End,
        }
    }
}

#[derive(Debug)]
pub struct TrieIterator<'a, D>
where
    D: Database,
{
    trie: &'a InnerTrie<D>,
    nibble: Nibbles,
    nodes: Vec<TraceNode>,
}

impl<'a, D> TrieIterator<'a, D>
where
    D: Database,
{
    pub fn new(trie: &InnerTrie<D>) -> TrieIterator<D> {
        let nodes = vec![trie.root().into()];

        TrieIterator {
            trie,
            nibble: Nibbles::from_raw(&[], false),
            nodes,
        }
    }
}

impl<'a, D> Iterator for TrieIterator<'a, D>
where
    D: Database,
{
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut now = self.nodes.last().cloned();
            if let Some(ref mut now) = now {
                self.nodes.last_mut().unwrap().advance();

                match (now.status.clone(), &now.node) {
                    (TraceStatus::End, node) => {
                        match *node {
                            Node::Leaf(ref leaf) => {
                                let cur_len = self.nibble.len();
                                self.nibble.truncate(cur_len - leaf.key.len());
                            }

                            Node::Extension(ref ext) => {
                                let cur_len = self.nibble.len();
                                self.nibble.truncate(cur_len - ext.prefix.len());
                            }

                            Node::Branch(_) => {
                                self.nibble.pop();
                            }
                            _ => {}
                        }
                        self.nodes.pop();
                    }

                    (TraceStatus::Doing, Node::Extension(ref ext)) => {
                        self.nibble.extend(&ext.prefix);
                        self.nodes.push((*ext.node.clone()).into());
                    }

                    (TraceStatus::Doing, Node::Leaf(ref leaf)) => {
                        self.nibble.extend(&leaf.key);
                        return Some((self.nibble.encode_raw().0, leaf.value.clone()));
                    }

                    (TraceStatus::Doing, Node::Branch(ref branch)) => {
                        let value_option = branch.value.clone();
                        if let Some(value) = value_option {
                            return Some((self.nibble.encode_raw().0, value));
                        } else {
                            continue;
                        }
                    }

                    (TraceStatus::Doing, Node::Hash(ref hash_node)) => {
                        let node_hash = hash_node.hash;
                        if let Ok(n) = self.trie.recover_from_db(node_hash) {
                            self.nodes.pop();
                            match n {
                                Some(node) => self.nodes.push(node.into()),
                                None => {
                                    // TODO: add proper instrumentation
                                    // warn!("Trie node with hash {:?} is missing from the database.
                                    // Skipping...", &node_hash);
                                    continue;
                                }
                            }
                        } else {
                            //error!();
                            return None;
                        }
                    }

                    (TraceStatus::Child(i), Node::Branch(ref branch)) => {
                        if i == 0 {
                            self.nibble.push(0);
                        } else {
                            self.nibble.pop();
                            self.nibble.push(i);
                        }
                        self.nodes
                            .push((*branch.children[i as usize].clone()).into());
                    }

                    (_, Node::Empty) => {
                        self.nodes.pop();
                    }
                    _ => {}
                }
            } else {
                return None;
            }
        }
    }
}

#[derive(Debug)]
pub struct OwnedTrieIterator<D>
where
    D: Database,
{
    trie: InnerTrie<D>,
    nibble: Nibbles,
    nodes: Vec<TraceNode>,
}

impl<D> OwnedTrieIterator<D>
where
    D: Database,
{
    pub fn new(trie: InnerTrie<D>) -> Self {
        let nodes = vec![trie.root().into()];

        Self {
            trie,
            nibble: Nibbles::from_raw(&[], false),
            nodes,
        }
    }
}

impl<D> Iterator for OwnedTrieIterator<D>
where
    D: Database,
{
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut now = self.nodes.last().cloned();
            if let Some(ref mut now) = now {
                self.nodes.last_mut().unwrap().advance();

                match (now.status.clone(), &now.node) {
                    (TraceStatus::End, node) => {
                        match *node {
                            Node::Leaf(ref leaf) => {
                                let cur_len = self.nibble.len();
                                self.nibble.truncate(cur_len - leaf.key.len());
                            }

                            Node::Extension(ref ext) => {
                                let cur_len = self.nibble.len();
                                self.nibble.truncate(cur_len - ext.prefix.len());
                            }

                            Node::Branch(_) => {
                                self.nibble.pop();
                            }
                            _ => {}
                        }
                        self.nodes.pop();
                    }

                    (TraceStatus::Doing, Node::Extension(ref ext)) => {
                        self.nibble.extend(&ext.prefix);
                        self.nodes.push((*ext.node.clone()).into());
                    }

                    (TraceStatus::Doing, Node::Leaf(ref leaf)) => {
                        self.nibble.extend(&leaf.key);
                        return Some((self.nibble.encode_raw().0, leaf.value.clone()));
                    }

                    (TraceStatus::Doing, Node::Branch(ref branch)) => {
                        let value_option = branch.value.clone();
                        if let Some(value) = value_option {
                            return Some((self.nibble.encode_raw().0, value));
                        } else {
                            continue;
                        }
                    }

                    (TraceStatus::Doing, Node::Hash(ref hash_node)) => {
                        let node_hash = hash_node.hash;
                        if let Ok(n) = self.trie.recover_from_db(node_hash) {
                            self.nodes.pop();
                            match n {
                                Some(node) => self.nodes.push(node.into()),
                                None => {
                                    // TODO: add proper instrumentation
                                    // warn!("Trie node with hash {:?} is missing from the database.
                                    // Skipping...", &node_hash);
                                    continue;
                                }
                            }
                        } else {
                            //error!();
                            return None;
                        }
                    }

                    (TraceStatus::Child(i), Node::Branch(ref branch)) => {
                        if i == 0 {
                            self.nibble.push(0);
                        } else {
                            self.nibble.pop();
                            self.nibble.push(i);
                        }
                        self.nodes
                            .push((*branch.children[i as usize].clone()).into());
                    }

                    (_, Node::Empty) => {
                        self.nodes.pop();
                    }
                    _ => {}
                }
            } else {
                return None;
            }
        }
    }
}
