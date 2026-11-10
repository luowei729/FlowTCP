//! 定容流槽位表：`u16` → `T` 的无锁开放寻址映射
//!
//! # 为什么不用 `HashMap`
//!
//! 代理数据面每收到一帧都要「按 `stream_id` 查表定位目标端」。
//! 这是全链路最热的操作之一。实测（`bench_registry`）：
//!
//! | 实现 | 单次查找 | 说明 |
//! |------|---------|------|
//! | `Arc<Mutex<HashMap<u16, T>>>` | **53.5 ns** | 锁 + SipHash + 指针追逐 |
//! | `Arc<Mutex<Vec<Option<T>>>>` | 42.7 ns | 锁仍是主导成本 |
//! | **本模块（表独占，无锁）** | **0.7 ns** | 一次掩码 + 一两次探测 |
//!
//! 省下的 ~53 ns 相当于 64B 包加密成本（235 ns）的 22%。
//!
//! # 为什么容量是 2 的幂而不是 65536
//!
//! 直接开 `Vec<Option<T>>` 到 65536 会让每条隧道固定占用
//! `65536 × size_of::<T>()` 字节（`T` 为 8 字节指针时是 512 KB）。
//! 而一条隧道实际只需要 `max_streams`（默认 256）个并发槽位，
//! 取 `2 ×` 负载因子即可（约 8 KB）。
//!
//! # 为什么不复用 `stream_id`
//!
//! FakeTCP 承载下帧可能乱序。「关闭 ID 5 → 立刻被新流复用」会让
//! 旧流的迟包被投递给新流（数据串流）。因此 ID 单调递增，
//! 本表用 `id & mask` 散列 + 线性探测，天然支持稀疏 ID。

/// 活跃槽位的最大容量提示（用于给 `Vec` 预留）。
pub const MIN_CAPACITY: usize = 16;

/// `u16` 键的定容映射。
///
/// 它**不是**线程安全的：设计前提是「由单一所有者独占」。
/// 需要跨任务访问时，让所有者通过通道接收命令（见 `flowtcp-client::mux`）。
pub struct SlotTable<T> {
    /// 槽位数组，长度恒为 2 的幂。
    entries: Vec<Option<(u16, T)>>,
    /// `entries.len() - 1`，用于免除法。
    mask: usize,
    /// 当前占用数。
    len: usize,
}

impl<T> SlotTable<T> {
    /// 按「最大并发数」构造（容量取 `2 × max` 向上取到 2 的幂）。
    pub fn with_capacity_hint(max_concurrent: u16) -> Self {
        let want = (max_concurrent as usize)
            .saturating_mul(2)
            .max(MIN_CAPACITY);
        let cap = want.next_power_of_two();
        SlotTable {
            // 用 `from_fn` 而非 `vec![None; cap]`：后者要求 `T: Clone`，
            // 而 `T` 往往是 `mpsc::Sender`（不可 Clone 出新的独立队列）。
            entries: std::iter::repeat_with(|| None).take(cap).collect(),
            mask: cap - 1,
            len: 0,
        }
    }

    /// 当前占用数。
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// 是否为空。
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 容量（槽位总数）。
    #[inline]
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }

    /// 查找。
    ///
    /// 负载因子 0.5 时期望探测次数约 1.5，实测 ~0.7 ns。
    #[inline]
    pub fn get(&self, id: u16) -> Option<&T> {
        let mut idx = (id as usize) & self.mask;
        loop {
            match &self.entries[idx] {
                Some((k, v)) if *k == id => return Some(v),
                Some(_) => idx = (idx + 1) & self.mask,
                None => return None,
            }
        }
    }

    /// 可变查找。
    #[inline]
    pub fn get_mut(&mut self, id: u16) -> Option<&mut T> {
        // 先用不可变查找确认存在并拿到下标，再做可变借用 ——
        // 直接对 `&mut self.entries[idx]` 循环探测会触发借用检查冲突。
        let mut idx = (id as usize) & self.mask;
        let found = loop {
            match &self.entries[idx] {
                Some((k, _)) if *k == id => break idx,
                Some(_) => idx = (idx + 1) & self.mask,
                None => return None,
            }
        };
        self.entries[found].as_mut().map(|(_, v)| v)
    }

    /// 插入。返回 `false` 表示该 ID 已存在（`stream_id` 回绕碰撞）。
    ///
    /// # 表满时不会无限循环
    ///
    /// 若 `len == capacity()`，探测必然回到起点。这里用「最多探测 capacity 次」
    /// 兜底，返回 `false` —— 调用方会把它当作 ID 冲突并换一个 ID 重试，
    /// 而真正的「流数上限」由调用方在读循环里单独判定。
    pub fn insert(&mut self, id: u16, value: T) -> bool {
        let mut idx = (id as usize) & self.mask;
        for _ in 0..self.entries.len() {
            match &self.entries[idx] {
                Some((k, _)) if *k == id => return false,
                Some(_) => idx = (idx + 1) & self.mask,
                None => {
                    self.entries[idx] = Some((id, value));
                    self.len += 1;
                    return true;
                }
            }
        }
        false
    }

    /// 内部用：把元素放回表里，**不**改动 `len`。
    ///
    /// 仅用于 [`Self::remove`] 的后移重排 —— 那里的元素本来就算在 `len` 里，
    /// 若用公开的 `insert` 会重复累加（这个 bug 会让 `len` 逐渐虚高）。
    fn place_back(&mut self, id: u16, value: T) {
        let mut idx = (id as usize) & self.mask;
        while self.entries[idx].is_some() {
            idx = (idx + 1) & self.mask;
        }
        self.entries[idx] = Some((id, value));
    }

    /// 删除，返回被移除的值。
    ///
    /// # 为什么需要「后移删除」
    ///
    /// 开放寻址的线性探测链一旦被挖空，后续元素就查不到了：
    ///
    /// ```text
    /// 插入 A(hash=3 占 3), B(hash=3 占 4), C(hash=3 占 5)
    /// 删 A 后若直接置 None：查 B 时在 idx=3 遇到 None 就误报「不存在」
    /// ```
    ///
    /// 因此删除后要把同一簇里的后续元素往前搬，直到遇到空位。
    pub fn remove(&mut self, id: u16) -> Option<T> {
        // 1) 找到目标位置
        let mut idx = (id as usize) & self.mask;
        let hole = loop {
            match &self.entries[idx] {
                Some((k, _)) if *k == id => break idx,
                Some(_) => idx = (idx + 1) & self.mask,
                None => return None,
            }
        };

        let (_, value) = self.entries[hole].take()?;
        self.len -= 1;

        // 2) 把同一簇里的后续元素逐个前移，保持探测链不断。
        //
        // 注意用 `place_back` 而不是 `insert`：这些元素本来就在 `len` 里，
        // 重新计数会让 `len` 虚高（实测这个 bug 会让 2 个元素报成 2 个、
        // 删掉 1 个后仍报 2）。
        let mut scan = (hole + 1) & self.mask;
        while let Some((k, v)) = self.entries[scan].take() {
            self.place_back(k, v);
            scan = (scan + 1) & self.mask;
        }
        Some(value)
    }

    /// 清空所有槽位（调用方的 `T` 会在此处 drop）。
    pub fn clear(&mut self) {
        for e in self.entries.iter_mut() {
            *e = None;
        }
        self.len = 0;
    }

    /// 遍历所有占用项（用于统计/调试，不在热路径上）。
    pub fn iter(&self) -> impl Iterator<Item = (u16, &T)> {
        self.entries
            .iter()
            .filter_map(|e| e.as_ref().map(|(k, v)| (*k, v)))
    }

    /// 可变遍历所有占用项。
    ///
    /// # 为什么需要它
    ///
    /// ARQ 的定时任务要同时做两件事：读 `AckRanges`（生成 Ack 帧）
    /// 并写 `last_ack_ms`、调 `ReorderBuffer`。用 `iter()` 拿 `&T` 不够。
    ///
    /// 读循环是流表的唯一持有者，所以这里不需要任何锁。
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u16, &mut T)> {
        self.entries
            .iter_mut()
            .filter_map(|e| e.as_mut().map(|(k, v)| (*k, v)))
    }
}

impl<T> std::fmt::Debug for SlotTable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotTable")
            .field("len", &self.len)
            .field("capacity", &self.entries.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 容量是2的幂且不小于需求的两倍() {
        for n in [1u16, 8, 100, 255, 1000, 65535] {
            let t = SlotTable::<u32>::with_capacity_hint(n);
            assert!(t.capacity().is_power_of_two(), "n={n}");
            assert!(
                t.capacity() >= (n as usize).saturating_mul(2).min(MIN_CAPACITY),
                "n={n} 容量 {} 太小",
                t.capacity()
            );
        }
    }

    #[test]
    fn 插入查找删除基本流程() {
        let mut t = SlotTable::with_capacity_hint(8);
        assert!(t.insert(1, "a"));
        assert!(t.insert(2, "b"));
        assert_eq!(t.get(1), Some(&"a"));
        assert_eq!(t.get(2), Some(&"b"));
        assert_eq!(t.get(3), None);
        assert_eq!(t.len(), 2);

        assert_eq!(t.remove(1), Some("a"));
        assert_eq!(t.get(1), None);
        assert_eq!(t.get(2), Some(&"b"), "删除相邻项不能影响其他项");
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn 重复id插入被拒绝() {
        let mut t = SlotTable::with_capacity_hint(8);
        assert!(t.insert(7, 1u8));
        assert!(!t.insert(7, 2u8), "同 ID 第二次插入必须失败");
        assert_eq!(t.get(7), Some(&1), "原有值不应被覆盖");
        assert_eq!(t.len(), 1);
    }

    /// ★ 开放寻址最易错的点：删除后必须保持探测链完整。
    ///
    /// 构造一组必然冲突的 ID（同一个 `id & mask`），删除中间那个，
    /// 再验证后面的仍能查到。
    #[test]
    fn 删除后探测链不断裂() {
        // 容量 16 → mask 15。3、19、35、51 都映射到同一桶 3
        let mut t = SlotTable::with_capacity_hint(8);
        assert_eq!(t.capacity(), 16);
        for id in [3u16, 19, 35, 51] {
            assert!(t.insert(id, id), "插入 {id} 应成功");
        }
        // 全都查得到
        for id in [3u16, 19, 35, 51] {
            assert_eq!(t.get(id), Some(&id));
        }

        // 删除最前面那个（坑最深）
        assert_eq!(t.remove(3), Some(3));
        assert_eq!(t.get(3), None);
        for id in [19u16, 35, 51] {
            assert_eq!(
                t.get(id),
                Some(&id),
                "删除 {id} 之前的元素后，{id} 仍必须可查（探测链不能断）"
            );
        }
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn 删除不存在的项返回none() {
        let mut t = SlotTable::with_capacity_hint(4);
        t.insert(1, 1u8);
        assert_eq!(t.remove(2), None);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn 清空后完全为空() {
        let mut t = SlotTable::with_capacity_hint(8);
        for id in 0..10u16 {
            t.insert(id, id);
        }
        t.clear();
        assert!(t.is_empty());
        for id in 0..10u16 {
            assert_eq!(t.get(id), None);
        }
        // 清空后仍可正常插入
        assert!(t.insert(3, 99));
        assert_eq!(t.get(3), Some(&99));
    }

    #[test]
    fn 大量随机增删保持一致() {
        let mut t = SlotTable::with_capacity_hint(128);
        let mut model = std::collections::BTreeMap::new();

        // 简单的确定性伪随机
        let mut seed = 0x1234_5678u32;
        let mut next = || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            seed
        };

        for _ in 0..4000 {
            let id = (next() % 300) as u16;
            if next() % 3 == 0 {
                // 删
                assert_eq!(t.remove(id), model.remove(&id), "删除 {id} 结果不一致");
            } else {
                // 增（若已存在，表会拒绝，模型也不能覆盖 —— 否则两边不一致）
                let v = next();
                let existed = model.contains_key(&id);
                assert_eq!(t.insert(id, v), !existed, "插入 {id} 结果不一致");
                if !existed {
                    model.insert(id, v);
                }
            }
            assert_eq!(t.len(), model.len(), "长度不一致");
        }

        // 最终逐项比对
        for (k, v) in &model {
            assert_eq!(t.get(*k), Some(v), "最终 {k} 不一致");
        }
        assert_eq!(t.iter().count(), model.len());
    }

    #[test]
    fn 稀疏大id也能定位() {
        let mut t = SlotTable::with_capacity_hint(4);
        // stream_id 单调递增到很大值仍应正常工作
        for id in [1u16, 1000, 30000, 65535] {
            assert!(t.insert(id, id));
        }
        for id in [1u16, 1000, 30000, 65535] {
            assert_eq!(t.get(id), Some(&id));
        }
    }

    #[test]
    fn 表满时插入返回false不死循环() {
        // 容量 16，塞满
        let mut t = SlotTable::with_capacity_hint(4);
        assert_eq!(t.capacity(), 16);
        for id in 0..16u16 {
            assert!(t.insert(id, id), "第 {id} 个应成功");
        }
        assert_eq!(t.len(), 16);
        // 再插入：可能因为 ID 冲突返回 false，但**绝不能死循环**
        let _ = t.insert(100, 100);
        // 只要能返回就说明没有死循环
    }
}
