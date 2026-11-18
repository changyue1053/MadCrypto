//! append-only Merkle 日志（RFC 6962 形态）：KT 的数学底座（架构 §11 L2）。
//!
//! 两条纪律：
//! - **域分隔**：叶 `H(0x00‖data)`、内部节点 `H(0x01‖L‖R)`——叶不可能伪装成节点（防第二原像拼接）。
//! - **验证器与生成器镜像同一递归**（同一棵切分树，一个生产证明、一个消费证明）——
//!   结构性一致，不靠背诵迭代式算法；证明格式与 RFC 6962 的 PATH/SUBPROOF 逐元素兼容。
//!
//! 规模假设：企业目录（十万级条目）。root/证明按需 O(n) 重算，正确性优先；
//! 若成为热点，再上增量节点缓存（接口不变）。

use madcrypto_prims::CipherSuite;

/// 叶哈希：`H(0x00 ‖ data)`。
pub fn leaf_hash<S: CipherSuite>(data: &[u8]) -> [u8; 32] {
    let mut v = Vec::with_capacity(1 + data.len());
    v.push(0x00);
    v.extend_from_slice(data);
    S::hash(&v)
}

fn node_hash<S: CipherSuite>(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut v = [0u8; 65];
    v[0] = 0x01;
    v[1..33].copy_from_slice(l);
    v[33..65].copy_from_slice(r);
    S::hash(&v)
}

/// 最大的严格小于 n 的 2 的幂（n ≥ 2）。RFC 6962 的子树切分点。
fn split_point(n: u64) -> u64 {
    let mut k = 1u64;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// append-only 叶哈希序列。历史不可改写——一致性证明保证这一点可被任何客户端验证。
#[derive(Default, Clone)]
pub struct MerkleLog {
    leaves: Vec<[u8; 32]>,
}

impl MerkleLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// 追加叶哈希，返回叶索引（0 起）。
    pub fn append(&mut self, leaf: [u8; 32]) -> u64 {
        self.leaves.push(leaf);
        self.leaves.len() as u64 - 1
    }

    /// 当前树根。空树 = `H("")`（RFC 6962 约定）。
    pub fn root<S: CipherSuite>(&self) -> [u8; 32] {
        Self::subtree_root::<S>(&self.leaves)
    }

    /// 历史快照树根（前 size 片叶）；越界返回 None。
    pub fn root_at<S: CipherSuite>(&self, size: u64) -> Option<[u8; 32]> {
        if size > self.size() {
            return None;
        }
        Some(Self::subtree_root::<S>(&self.leaves[..size as usize]))
    }

    fn subtree_root<S: CipherSuite>(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            0 => S::hash(b""),
            1 => leaves[0],
            n => {
                let k = split_point(n as u64) as usize;
                node_hash::<S>(
                    &Self::subtree_root::<S>(&leaves[..k]),
                    &Self::subtree_root::<S>(&leaves[k..]),
                )
            }
        }
    }

    /// 叶 index 相对当前树的包含证明（audit path，叶侧兄弟在前）。
    pub fn inclusion_proof<S: CipherSuite>(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        if index >= self.size() {
            return None;
        }
        let mut out = Vec::new();
        Self::path::<S>(&self.leaves, index as usize, &mut out);
        Some(out)
    }

    fn path<S: CipherSuite>(leaves: &[[u8; 32]], m: usize, out: &mut Vec<[u8; 32]>) {
        if leaves.len() <= 1 {
            return;
        }
        let k = split_point(leaves.len() as u64) as usize;
        if m < k {
            Self::path::<S>(&leaves[..k], m, out);
            out.push(Self::subtree_root::<S>(&leaves[k..]));
        } else {
            Self::path::<S>(&leaves[k..], m - k, out);
            out.push(Self::subtree_root::<S>(&leaves[..k]));
        }
    }

    /// 旧快照（前 old_size 叶）与当前树的一致性证明。
    /// old_size == 0（首次见树）或 == size（无增量）时为合法空证明。
    pub fn consistency_proof<S: CipherSuite>(&self, old_size: u64) -> Option<Vec<[u8; 32]>> {
        if old_size > self.size() {
            return None;
        }
        if old_size == 0 || old_size == self.size() {
            return Some(Vec::new());
        }
        let mut out = Vec::new();
        Self::subproof::<S>(&self.leaves, old_size as usize, true, &mut out);
        Some(out)
    }

    fn subproof<S: CipherSuite>(leaves: &[[u8; 32]], m: usize, complete: bool, out: &mut Vec<[u8; 32]>) {
        let n = leaves.len();
        if m == n {
            // complete=true 表示"这个子树整个就是旧树"——其根即验证方已持有的 old_root，无需入证明
            if !complete {
                out.push(Self::subtree_root::<S>(leaves));
            }
            return;
        }
        let k = split_point(n as u64) as usize;
        if m <= k {
            Self::subproof::<S>(&leaves[..k], m, complete, out);
            out.push(Self::subtree_root::<S>(&leaves[k..]));
        } else {
            Self::subproof::<S>(&leaves[k..], m - k, false, out);
            out.push(Self::subtree_root::<S>(&leaves[..k]));
        }
    }
}

// ---------------- 无账本验证（客户端侧：只凭 root/size/证明） ----------------

/// 验证叶包含于树：证明必须恰好耗尽（多一个少一个元素都拒绝）。
pub fn verify_inclusion<S: CipherSuite>(
    root: &[u8; 32],
    tree_size: u64,
    leaf_index: u64,
    leaf: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }
    let mut pos = 0usize;
    match root_from_path::<S>(leaf_index, tree_size, leaf, proof, &mut pos) {
        Some(r) => pos == proof.len() && &r == root,
        None => false,
    }
}

fn root_from_path<S: CipherSuite>(
    index: u64,
    size: u64,
    leaf: &[u8; 32],
    proof: &[[u8; 32]],
    pos: &mut usize,
) -> Option<[u8; 32]> {
    if size == 1 {
        return Some(*leaf);
    }
    let k = split_point(size);
    if index < k {
        let l = root_from_path::<S>(index, k, leaf, proof, pos)?;
        let r = *proof.get(*pos)?;
        *pos += 1;
        Some(node_hash::<S>(&l, &r))
    } else {
        let r = root_from_path::<S>(index - k, size - k, leaf, proof, pos)?;
        let l = *proof.get(*pos)?;
        *pos += 1;
        Some(node_hash::<S>(&l, &r))
    }
}

/// 验证新树是旧树的 append-only 延伸（改写任何历史叶都无法通过）。
pub fn verify_consistency<S: CipherSuite>(
    old_root: &[u8; 32],
    old_size: u64,
    new_root: &[u8; 32],
    new_size: u64,
    proof: &[[u8; 32]],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == 0 {
        return proof.is_empty(); // 无历史锚点：首次见树，接受并从此锚定
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    let mut pos = 0usize;
    match consistency_roots::<S>(old_size, new_size, true, old_root, proof, &mut pos) {
        Some((o, n)) => pos == proof.len() && &o == old_root && &n == new_root,
        None => false,
    }
}

/// 返回 (旧树根重建值, 新树根重建值)。complete 语义与生成侧 subproof 镜像。
fn consistency_roots<S: CipherSuite>(
    m: u64,
    n: u64,
    complete: bool,
    old_root: &[u8; 32],
    proof: &[[u8; 32]],
    pos: &mut usize,
) -> Option<([u8; 32], [u8; 32])> {
    if m == n {
        let h = if complete {
            *old_root // 该子树整体即旧树：锚点就是验证方持有的 old_root
        } else {
            let h = *proof.get(*pos)?;
            *pos += 1;
            h
        };
        return Some((h, h));
    }
    let k = split_point(n);
    if m <= k {
        let (old, left_new) = consistency_roots::<S>(m, k, complete, old_root, proof, pos)?;
        let right_new = *proof.get(*pos)?;
        *pos += 1;
        Some((old, node_hash::<S>(&left_new, &right_new)))
    } else {
        let (right_old, right_new) = consistency_roots::<S>(m - k, n - k, false, old_root, proof, pos)?;
        let left = *proof.get(*pos)?;
        *pos += 1;
        Some((node_hash::<S>(&left, &right_old), node_hash::<S>(&left, &right_new)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use madcrypto_prims::IntlSuite;

    type S = IntlSuite;

    fn log_of(n: u64) -> MerkleLog {
        let mut log = MerkleLog::new();
        for i in 0..n {
            log.append(leaf_hash::<S>(format!("entry-{i}").as_bytes()));
        }
        log
    }

    #[test]
    fn empty_tree_root_is_hash_of_empty() {
        assert_eq!(MerkleLog::new().root::<S>(), S::hash(b""));
    }

    #[test]
    fn inclusion_exhaustive_sizes_1_to_32() {
        for n in 1..=32u64 {
            let log = log_of(n);
            let root = log.root::<S>();
            for i in 0..n {
                let leaf = leaf_hash::<S>(format!("entry-{i}").as_bytes());
                let proof = log.inclusion_proof::<S>(i).unwrap();
                assert!(
                    verify_inclusion::<S>(&root, n, i, &leaf, &proof),
                    "inclusion failed at n={n} i={i}"
                );
                // 错叶 / 错索引 / 错根 全拒
                let wrong_leaf = leaf_hash::<S>(b"forged");
                assert!(!verify_inclusion::<S>(&root, n, i, &wrong_leaf, &proof));
                if n > 1 {
                    assert!(!verify_inclusion::<S>(&root, n, (i + 1) % n, &leaf, &proof));
                }
                let mut wrong_root = root;
                wrong_root[0] ^= 1;
                assert!(!verify_inclusion::<S>(&wrong_root, n, i, &leaf, &proof));
            }
        }
    }

    #[test]
    fn inclusion_rejects_tampered_or_resized_proof() {
        let log = log_of(11);
        let root = log.root::<S>();
        let leaf = leaf_hash::<S>(b"entry-6");
        let proof = log.inclusion_proof::<S>(6).unwrap();
        // 篡改任一证明元素
        for j in 0..proof.len() {
            let mut p = proof.clone();
            p[j][0] ^= 1;
            assert!(!verify_inclusion::<S>(&root, 11, 6, &leaf, &p));
        }
        // 多一个 / 少一个元素（证明必须恰好耗尽）
        let mut longer = proof.clone();
        longer.push([0u8; 32]);
        assert!(!verify_inclusion::<S>(&root, 11, 6, &leaf, &longer));
        let shorter = &proof[..proof.len() - 1];
        assert!(!verify_inclusion::<S>(&root, 11, 6, &leaf, shorter));
    }

    #[test]
    fn consistency_exhaustive_pairs_to_32() {
        for n in 1..=32u64 {
            let log = log_of(n);
            let new_root = log.root::<S>();
            for m in 0..=n {
                let old_root = log.root_at::<S>(m).unwrap();
                let proof = log.consistency_proof::<S>(m).unwrap();
                assert!(
                    verify_consistency::<S>(&old_root, m, &new_root, n, &proof),
                    "consistency failed at m={m} n={n}"
                );
            }
        }
    }

    #[test]
    fn rewriting_history_breaks_consistency() {
        // 客户端锚定 size=8 的根；日志方改写历史叶后再增长——一致性证明必然失败
        let honest = log_of(8);
        let pinned_root = honest.root::<S>();

        let mut rewritten = MerkleLog::new();
        for i in 0..8u64 {
            let data = if i == 3 { "entry-3-SWAPPED".to_string() } else { format!("entry-{i}") };
            rewritten.append(leaf_hash::<S>(data.as_bytes()));
        }
        for i in 8..12u64 {
            rewritten.append(leaf_hash::<S>(format!("entry-{i}").as_bytes()));
        }
        let proof = rewritten.consistency_proof::<S>(8).unwrap();
        assert!(
            !verify_consistency::<S>(&pinned_root, 8, &rewritten.root::<S>(), 12, &proof),
            "改写历史必须被锚定客户端识破——KT 的核心承诺"
        );
        // 对照：诚实延伸同样 4 条则通过
        let mut grown = honest.clone();
        for i in 8..12u64 {
            grown.append(leaf_hash::<S>(format!("entry-{i}").as_bytes()));
        }
        let ok = grown.consistency_proof::<S>(8).unwrap();
        assert!(verify_consistency::<S>(&pinned_root, 8, &grown.root::<S>(), 12, &ok));
    }

    #[test]
    fn leaf_cannot_masquerade_as_node() {
        // 域分隔：把内部节点字节当叶提交，哈希域不同 → 与真实树根不一致
        let log = log_of(2);
        let l0 = leaf_hash::<S>(b"entry-0");
        let l1 = leaf_hash::<S>(b"entry-1");
        let mut node_bytes = Vec::new();
        node_bytes.extend_from_slice(&l0);
        node_bytes.extend_from_slice(&l1);
        assert_ne!(leaf_hash::<S>(&node_bytes), log.root::<S>());
    }
}

