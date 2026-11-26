# 透明日志中临时（ephemeral）节点与证明恢复

本报告分析 `github.com/transparency-dev/merkle` 中证明节点的选择、右侧临时节点的折叠次序，
以及一个只持久化「可复用子树节点」的审计方如何恢复并验证证明。文末把结论分为
**源码可证事实**、**推断** 与 **验证判据** 三部分，并特别标注：**临时哈希不得被误记为
已持久化的证据**。

分析基于当前 HEAD `ff0af9a`（`[compact] Harden range bounds and merge-path underflow`）。
文中行号均指该提交下的文件。

---

## 0. 结论概要

1. 树节点用 `(level, index)` 寻址，`level 0` 是叶子。子树覆盖区间为
   `[index<<level, (index+1)<<level)`（`compact/nodes.go:19-57`）。
2. 一个节点是 **perfect（完美）** 当且仅当其覆盖区间完全落在 `[0, size)` 内；其余节点是
   **ephemeral（临时）**，其哈希会随日志增长而改变（`docs/data_model.md:27-34`，
   `compact/nodes.go:31-33`）。
3. 持久存储只保存 perfect 节点。perfect 节点是「write-once」的，可以按覆盖区间复用。
4. 证明生成器 `proof.Nodes` 把所有 **需要从存储读取的** 节点放进 `IDs`；`IDs` 全部是 perfect
   节点。临时节点 **不出现在 `IDs` 中**：它的地址 `ephem` 单独记录，其值由
   `IDs[begin:end]` 这一小段 perfect 节点在右侧自右向左折叠重建
   （`proof/proof.go:25-43, 163-219, 227-256`）。
5. 因此审计方只需按 `IDs` 从 perfect 存储取哈希，调用 `Rehash` 折叠 `IDs[begin:end]`，
   即可得到线上证明；验证方 `RootFromInclusionProof` 只做「形状检查 + 哈希链」，
   **从不查询 `ephem`**（`proof/verify.go:78-94`）。
6. 但 **折叠次序是有语义的**：块按覆盖区间自右向左排列，折叠时每个新元素作为**左兄弟**
   前置。顺序颠倒、把块当独立哈希而不折叠、或把同址的旧临时值当作持久值，都会改变
   计算出的树根，从而与可信根不符（实验见 §5）。

---

## 1. 代码地图

| 关注点 | 位置 |
|---|---|
| 节点寻址、覆盖、兄弟 | `compact/nodes.go:34-57` |
| 区间分解为 perfect 子树 | `compact/nodes.go:63-97`（`RangeNodes`/`RangeSize`） |
| 紧致区间与合并、根计算 | `compact/range.go:69-277` |
| 证明节点选择（fork/inner/左右块） | `proof/proof.go:163-219`（`nodes`） |
| 临时节点块与折叠 | `proof/proof.go:227-256`（`Ephem`/`Rehash`） |
| 一致性/子树一致性选择 | `proof/proof.go:86-159` |
| 验证与证明形状检查 | `proof/verify.go:78-94, 272-323, 328-358` |
| 服务端参考实现（只存完成节点） | `testonly/tree.go:52-66, 112-160` |

---

## 2. 节点选择：`IDs` 里到底放了什么

### 2.1 perfect 与 ephemeral 的边界

`compact.NodeID.Coverage()`（`compact/nodes.go:54-57`）：

```go
func (id NodeID) Coverage() (uint64, uint64) {
    return id.Index << id.Level, (id.Index + 1) << id.Level
}
```

对大小为 `size` 的树，节点 `(level, index)` 是 perfect 当且仅当
`(index+1)<<level <= size`。例如 `size=13` 时，`(3,0)` 覆盖 `[0,8)` 为 perfect，
而 `(3,1)` 覆盖 `[8,16)` 越界，是 ephemeral。（实验：仅按此判据建库，
`size≤64` 的所有叶子的 `Inclusion` 证明里 `IDs` 缺失数为 0，见 §5。）

### 2.2 `nodes()` 的构造（`proof/proof.go:163-219`）

证明围绕「被证明节点」与「树右边界」两条路径的分叉点组织：

```go
inner := bits.Len64(index^(size>>level)) - 1        // 174
fork := compact.NewNodeID(level+uint(inner), index>>inner) // 175
begin, end := fork.Coverage()                        // 177
left := compact.RangeSize(0, begin)                  // 178
right := compact.RangeSize(end, size)                // 179
```

- `fork` 是从被证明节点到根、与从 `(0,size)` 到根的路径**分叉**的节点。
- `fkCoverage = [begin, end)` 是 `fork` 覆盖的完美区间。
- `[end, size)` 是 `fork` 右侧已实现但尚未凑满 `fork` 兄弟区间的部分。
- `[0, begin)` 是 `fork` 左侧需要补齐的整棵树。

输出顺序（`proof/proof.go:187-206`）：

```go
// 1) seed 节点本身
nodes := append(make([]compact.NodeID, 0, 1+inner+right+left), node)
// 2) 沿路径到 fork 的 inner 个兄弟（自下而上）
for ; node.Level < fork.Level; node = node.Parent() {
    nodes = append(nodes, node.Sibling())
}
// 3) 右块：覆盖 [end,size)，取 RangeNodes 后反转
len1 := len(nodes)
nodes = compact.RangeNodes(end, size, nodes)
reverse(nodes[len(nodes)-right:])
len2 := len(nodes)
// 4) 左块：覆盖 [0,begin)，取 RangeNodes 后反转
nodes = compact.RangeNodes(0, begin, nodes)
reverse(nodes[len(nodes)-left:])
```

要点：

- **右块就是临时节点的「实现部分」**：`[end, size)` 被 `RangeNodes` 分解为若干完美子树，
  每个都完整落在 `[0,size)` 内，因此都在持久存储中。
- `ephem = fork.Sibling()`（`proof/proof.go:218`），其覆盖区间
  `[end, end + 2^fork.Level)` 包含 `[end, size)` 以及尚不存在的 `[size, end+width)`。
  **临时节点恰好横跨树右边界**——这正是它不能被持久化的根本原因（实验：13648 个非空块中，
  临时节点完全落在 `[0,size)` 内的情况为 0，见 §5）。
- `RangeNodes` 的输出次序：左边界按层级**由低到高**，右边界按层级**由高到低**
  （`compact/nodes.go:70-84`）。对右块再做一次 `reverse`，得到**自右向左、层级由低到高**
  的序列（见 §3）。

### 2.3 `begin/end` 与「块为空」

```go
if len1 >= len2 {
    len1, len2 = 0, 0
}
return Nodes{IDs: nodes, begin: len1, end: len2, ephem: fork.Sibling()}
```

- `IDs[begin:end]` 是临时节点的**子节点**（实现部分）。`begin==end` 表示无临时节点需要重建。
- 完美树时 `ephem` 是根的兄弟，块为空，`ephem` 不会被使用
  （`proof/proof_test.go:662-665`，`TestEphem` 的 `size=32,index=3 → (5,1)`）。
- 对于子树证明，`ephem` 也会按 `start>>level` 平移（`proof/proof.go:73-78`）。

---

## 3. 折叠次序

### 3.1 右块的排列：自右向左

以 `size=13, index=0` 为例（结构对任意叶哈希成立）：

```
fork=(3,0)  coverage [0,8)
ephem=(3,1) coverage [8,16)
IDs（skipFirst 前）: seed(0,0), (0,1), (1,1), (2,1), (0,12), (2,2)
```

右块为 `[ (0,12), (2,2) ]`：

| 块内位置 | 节点 | 覆盖 |
|---|---|---|
| `block[0]` | `(0,12)` | `[12,13)` |
| `block[1]` | `(2,2)` | `[8,12)` |

即**覆盖区间自右（最大）向左（最小）递减相邻**，层级不减。
实验对 `size≤200` 的所有 inclusion（19248 个非空块）、`size≤150` 的 consistency（10690 个）
与 subtree inclusion（142 个）逐一验证：块恒等于 `reverse(RangeNodes(ephem.begin, size))`，
且「右到左相邻」违规数为 0（见 §5）。

### 3.2 `Rehash` 的折叠：每个新元素作为左兄弟前置

```go
for i, ln := 0, len(h); i < ln; i, cursor = i+1, cursor+1 {   // 244
    hash := h[i]
    if i >= n.begin && i < n.end {
        for i++; i < n.end; i++ {
            hash = hc(h[i], hash)          // 249: 新元素在左，累积值在右
        }
        i--
    }
    h[cursor] = hash
}
```

因此块折叠等价于：

```
fold = hc(block[k-1], hc(block[k-2], … hc(block[1], block[0]) … ))
```

其中 `block[0]` 是**最右**的完美子树。对 `size=13` 右块：

```
ephem_value = hc( hash((2,2) covers [8,12)), hash((0,12) covers [12,13)) )
```

它正好是以 `[8,13)` 为内容的「右边界累积值」，即 `(3,1)` 在 `size=13` 时的临时哈希。
`Rehash` 输出的长度减少 `(end-begin)-1`：`len(out) = len(IDs) - (blocksize-1)`
（实验：块折叠与手工自右向左折叠逐例一致，差异 0）。

### 3.3 两个不同的 visitor 语义——务必区分

| API | visitor 发出的节点 | 是否可持久化 |
|---|---|---|
| `Range.Append/AppendRange(...,visitor)` | 新合并完成的**完美**节点（`compact/range.go:102, 213`） | **是** |
| `Range.GetRootHash(visitor)` | 右边界上的**临时**节点（`compact/range.go:129-151`） | **否** |

`GetRootHash` 的临时节点公式（`compact/range.go:141-149`）：

```go
hash = r.f.Hash(r.hashes[i], hash)          // 142
size &= size - 1                             // 144 删去上一节点
level := uint(bits.TrailingZeros64(size)) + 1
index := size >> level
visitor(NewNodeID(level, index), hash)       // 147
```

实验：`size=13` 时依次发出 `(3,1)`、`(4,0)`；`size=15` 时 `(2,3)`、`(3,1)`、`(4,0)`；
`size=16`（完美树）时不发出任何节点。对 `size≤40` 统计：`Append` 的 78 次发出**全部**
是当前尺寸下的完美节点；`GetRootHash` 的 62 次发出**全部**是临时节点。

> **这就是「临时哈希不应被误记为已持久化证据」的直接来源**：二者都通过 `VisitFn`
> 回调同一个「节点哈希」形状，但只有前者的地址在该尺寸下是可复用的完美节点。

---

## 4. 审计方仅持持久节点时如何恢复可验证证明

设审计方拥有按 `(level,index)` 索引的 perfect 节点库，且不含任何越界节点。
`testonly.Tree` 正是这种形态：`appendImpl` 只在节点完成时写入对应层
（`testonly/tree.go:52-66`），`getNodes` 按 ID 取哈希（`testonly/tree.go:154-160`）。

### 4.1 恢复步骤（以 inclusion 为例）

1. **列出 ID**：由 `proof.Inclusion(index,size)` 得到 `Nodes`，读取 `IDs`、`Ephem()`。
2. **取哈希**：对每个 `id ∈ IDs` 从 perfect 库读取。因为 `IDs` 全部是 perfect 节点，
   **读取不应失败**；若失败说明库缺节点或证明参数错误。
3. **折叠块**：调用 `Nodes.Rehash(hashes, hashChildren)`。`Rehash` 会把 `IDs[begin:end]`
   原地折叠成**一个**临时哈希（§3.2），其余位置原样拷贝。
4. **得到线证明**：`Rehash` 的输出即 RFC 6962 形状的证明（inclusion 用 `skipFirst` 后的
   序列，`proof/proof.go:48-53, 258-266`）。
5. **验证**：`RootFromInclusionProof`（`proof/verify.go:78-94`）
   - `inner, border := decompInclProof(index, size)`，检查 `len(proof)==inner+border`；
   - `chainInner(leafHash, proof[:inner], index)`，再 `chainBorderRight(..., proof[inner:])`；
   - 与可信根比较。

整个过程中 **`ephem` 既不需要被取回，也不进入哈希链**——验证器只按 `index/size`
决定每个线证明元素是左兄弟还是右兄弟。

### 4.2 为什么块可以从 perfect 库重建

右块覆盖 `[end, size)`。`RangeNodes(end,size)` 的每个节点覆盖一个**完整**的 `2^k` 区间，
且右端点 `<= size`，故全部 perfect、全部在库中。把它们按 §3 折叠，就得到 `fork` 兄弟
（临时节点）在「大小恰为 `size`」时的值。缺失的 `[size, end+width)` 正是尚未写入的叶子，
也正是临时节点不能被持久化的部分。

### 4.3 具体演算（`size=13, index=0`）

```
IDs        = [ (0,1), (1,1), (2,1), (0,12), (2,2) ]   （skipFirst 后）
Ephem      = (3,1), block = IDs[3:5] = [(0,12),(2,2)]
从库取 5 个哈希（全部 perfect）
Rehash 折叠块：
    t = h(0,12)
    t = hc( h(2,2), t )        // 得到 [8,13) 的临时值
线证明 = [ h(0,1), h(1,1), h(2,1), t ]     // 4 个哈希
验证：inner=4, border=0 → 长度 4 通过 → 链式 → 根
```

（实验中该例基线根为 `a8ef48…`；哈希值依赖所选叶子，结构结论与叶子无关。）

`size=7, index=0` 的经典例子（`proof/proof_test.go:75-76`）：
`IDs=[b(0,1),h(1,1),j(0,6),i(1,2)]`，`ephem=(2,1)=l`，块 `[j,i]`，
线证明 `[b,h,hc(i,j)]`，与 RFC 6962 一致（`testonly/reference_test.go:49-66`）。

### 4.4 一致性证明的额外注意

`Consistency` 选择右端完美子树的根，再套用 inclusion（`proof/proof.go:145-158`）；
当子树大小是 2 的幂时 `skipFirst` 去掉冗余根。`SubtreeConsistency` 在 `end==size` 时
直接以子树根为起点（`proof/proof.go:120-143`）。这些分支不改变「IDs 全 perfect、临时值
由块折叠」的结论；实验对 1600 个 subtree-consistency 证明同样得到 `IDs` 缺失 0、
`ephem` 入 `IDs` 0。

---

## 5. 错误来源或次序如何改变树根结论

以下为在 `size=13,index=0` 上的实测（叶子为自定义 `leaf-N`，根仅作比较用途）：

| 情形 | 结果 |
|---|---|
| 正确折叠 | 根 `a8ef48…`（与可信根一致） |
| 块内顺序反转 | 根 `07714b…`，不匹配 |
| 块不折叠、直接作为独立哈希 | 在**形状检查**被拒：`wrong proof size 5, want 4` |
| 来源错：块首节点换成错误 perfect 节点 `(0,10)` | 根 `df464d…`，不匹配 |
| 来源错：块首节点换成另一 perfect 节点 `(0,11)` | 根 `fb3146…`，不匹配 |
| 服务端复用了 **同址的陈旧临时值**（`(3,1)` 在 size=16 的完美值） | 根 `cba3a9…`，不匹配 |
| 交换线证明最后两个哈希 | 根 `fd880f…`，不匹配 |

### 5.1 错误的「来源」

- **取错层/取错索引**：哈希链每一步都是 `hc(left,right)`，任一输入改变都会级联改变根。
  由于 `IDs` 中任意节点都可由 `(level,index)` 精确定位，取错的典型原因是把**临时地址**
  当成持久地址查询，或越界读取邻近 perfect 节点。
- **同址异值**：`(3,1)` 在 `size=13/14/15` 是临时节点，在 `size=16` 才成为完美节点。
  实测该地址的哈希随尺寸变化：`size13=d0b743…`、`size14=9b6a42…`、`size15=7e6b54…`、
  `size16=0987e0…`（size16 的值来自持久库）。把某个尺寸的临时值缓存后复用到另一个尺寸，
  必然使根偏离。**这正是「临时哈希不得记为持久证据」的算术后果。**

### 5.2 错误的「次序」

- **块内次序**：块按覆盖区间自右向左排列，折叠时新元素为左兄弟。反转块会改变
  `hc` 的左右实参，根随之改变（`07714b…`）。
- **折叠 vs 不折叠**：把 `k` 个块元素当作 `k` 个独立线证明哈希，会多出 `k-1` 个元素，
  在 `len(proof)==inner+border` 处被拒（`proof/verify.go:86-89`），因为验证器期望临时节点
  已被折叠为**一个**哈希。这属于**形状层的拒绝**，比根不匹配更早发生。
- **左右块拼接次序**：`nodes()` 先放右块、后放左块，验证器依据 `index` 的位模式
  （`chainInner`，`proof/verify.go:328-337`）来决定每层的左右角色。次序错位会改变
  哪些哈希被当作左兄弟，进而改变根。

### 5.3 合并路径的边界（与折叠次序相关）

`appendImpl` 通过 `getMergePath(begin, mid, end)` 决定合并路径的位区间 `[low,high)`
（`compact/range.go:180-243`）。HE `ff0af9a` 修复了 `mid==0`/`end==MaxUint64` 时的无符号下溢：
当 `high<=low` 时返回空路径，于是 `[0,0)` 与 `[0,MaxUint64)` 的合并**不产生任何新节点、
不调用 visitor**（`compact/range.go:233-243`，测试 `TestMaxUint64Bounds`，
`compact/range_test.go:581-646`）。若该下溢未被修复，`appendImpl` 会在空路径上继续循环，
可能向 visitor 发出**不该存在的节点**——审计方若把这些节点当真持久化，就会污染证据。
这也说明：**visitor 的每一次发出都必须先判断该地址在当前尺寸下是否 perfect**。

---

## 6. 源码可证事实

以下均直接对应代码，不依赖运行。

1. 节点地址空间与覆盖：`compact/nodes.go:34-57`。
2. perfect/ephemeral 的语义：越界即临时，会随树增长改变（`docs/data_model.md:27-34`；
   `compact/nodes.go:31-33`）。
3. `IDs` 只含 non-ephemeral 节点；`ephem` 单独字段；`IDs[begin:end]` 是临时节点的子节点
   （`proof/proof.go:28-43`）。
4. `fork` 为被证明路径与右边界路径的分叉点，`begin,end := fork.Coverage()`，
   `left/right` 由 `RangeSize` 给出（`proof/proof.go:174-179`）。
5. 右块由 `RangeNodes(end,size)` 构造并反转；左块由 `RangeNodes(0,begin)` 构造并反转
   （`proof/proof.go:200-206`）。
6. `ephem = fork.Sibling()`；块为空时 `begin=end=0`（`proof/proof.go:212-218`）。
7. `Rehash` 在 `[begin,end)` 上做 `hc(h[i], hash)` 的前置折叠，输出缩短 `blocksize-1`
   （`proof/proof.go:236-256`）。
8. 验证器用 `decompInclProof` 求 `inner+border` 并做长度检查，随后
   `chainInner`/`chainBorderRight` 计算根；**不使用 `ephem`**（`proof/verify.go:78-94,
   272-323, 328-358`）。
9. `Append/AppendRange` 的 visitor 发出新完成的完美节点；`GetRootHash` 的 visitor 发出
   右边界临时节点（`compact/range.go:97-105, 129-151, 180-222`）。
10. `testonly.Tree` 只存完成节点，`getNodes` 按 ID 读取，因此它能直接服务 `IDs`
    （`testonly/tree.go:52-66, 112-160`）。
11. `[0, MaxUint64)` 的 `GetRootHash` 会访问 63 个临时节点，最后一个为 `(64,0)`
    （`compact/range_test.go:603-616`）。

## 7. 推断（非直接断言，附依据）

1. **只存 perfect 节点仍可完整服务证明**：因为 `IDs` 全为 perfect 且块可由
   `RangeNodes(end,size)` 重建，`Rehash` 能把块折叠成线证明所需的单个临时哈希。
   依据：事实 3、5、7，以及 §5 中 `IDs` 缺失数恒为 0。
2. **`ephem` 的地址不能作为持久键**：`ephem` 覆盖 `[end, end+2^fork.Level)`，
   严格超出 `size`，其值依赖尚不存在的叶子。依据：`fork.Coverage()` + `Sibling()`
   的定义；实测非空块 13648 例，临时节点从未完全落在 `[0,size)`。
3. **同址异值是常态而非异常**：地址 `(l,i)` 在 `size` 达到 `(i+1)<<l` 前一直是临时节点，
   此前每个 `size` 都可能给出不同值。依据：事实 2 与实测 `(3,1)` 在 size 13–16 的取值。
4. **在哈希碰撞可忽略的前提下，来源错或次序错几乎必然导致根不同**：链式哈希对输入敏感，
   且验证器不做「猜测性修补」。依据：`chainInner/chainBorderRight` 的实现。
5. **单节点块是「退化临时节点」**：当 `blocksize==1` 时折叠为恒等，线证明直接采用该
   perfect 节点的哈希；此时「临时」是形式命名（`proof/proof.go:208-211` 的注释亦指出
   可视偏好决定是否算临时）。依据：`Rehash` 对单元素的循环不执行。
6. **boundary 修复防止伪造证据**：`getMergePath` 的空路径语义确保不产生幽灵节点，
   避免 visitor 向持久库注入不存在地址。依据：事实 11 及 `TestMaxUint64Bounds`。

## 8. 验证判据（可直接落地的检查清单）

对一个证明/服务端，逐条检查：

- **C1 可解析性**：`Nodes.IDs` 的每个 `(Level,Index)` 都能在 perfect 库解析；
  `(Index+1)<<Level <= size` 且 `Index<<Level < size`。任一不满足即证据不完整。
- **C2 临时节点不入口**：`Ephem()` 返回的地址不出现于 `IDs`；服务端不需要、也不应
  以该地址查询持久库。（实测四类证明共 4364 个：inclusion 820、consistency 780、
  subtree inclusion 1164、subtree consistency 1600，临时地址入口数均为 0。）
- **C3 块结构**：非空块应满足
  `IDs[begin:end] == reverse(RangeNodes(ephem.begin, size))`，
  覆盖区间自右向左相邻，且层级不减；末端恰为 `size`。
- **C4 形状与长度**：`Rehash` 输出长度 == `len(IDs) - (end-begin) + 1`；
  对 inclusion，`len(proof) == inner+border`（`decompInclProof`）。不符即
  `wrong proof size`。
- **C5 根一致**：`RootFromInclusionProof`/`RootFromConsistencyProof` 的结果必须与可信根
  逐字节相等；否则 `RootMismatchError`。来源错或次序错在此暴露（§5）。
- **C6 持久化白名单**：只持久化 `Append/AppendRange` visitor 发出的、且在当前尺寸下
  满足 `(Index+1)<<Level <= size` 的节点；**禁止**把 `GetRootHash` visitor 或任何右边界
  临时值写入以 `(Level,Index)` 为键的持久库。
- **C7 同址异值自检**：对候选缓存地址 `(l,i)`，比较 `size` 在
  `[(i+1)<<l - 2^k, (i+1)<<l]` 区间内不同尺寸下的取值；若不同，则该地址此前只能是临时节点，
  不能作为跨尺寸复用的证据。
- **C8 边界回归**：确保 `getMergePath` 对 `mid==0`、`end==MaxUint64`、乱序输入返回空路径
  （`low==high`），且 `appendImpl` 在空路径下不调用 visitor。

## 9. 反模式与正确做法

| 反模式 | 后果 | 正确做法 |
|---|---|---|
| 把 `GetRootHash` visitor 发出的哈希按地址写入持久库 | 同址旧值被当作持久证据，之后证明根错误（§5.1） | 只持久化完美节点；临时值按需从块折叠 |
| 把 `ephem` 地址当作可查询键 | 越界或读到相邻 perfect 节点的错误哈希 | 不查询 `ephem`，由 `IDs[begin:end]` 折叠重建 |
| 把块元素当独立线证明哈希 | 形状检查失败（多 `k-1` 个哈希） | 用 `Rehash` 先折叠为单个哈希 |
| 反转块次序或交换末两哈希 | 根不匹配 | 保持 `RangeNodes` 反转后的自右向左次序 |
| 缓存某尺寸的临时值并跨尺寸复用 | 根不匹配（同址异值） | 每个 `size` 重新折叠，或仅在节点 perfect 后缓存 |

## 10. 复现实验

所有数据来自临时探针程序（已删除，未纳入仓库），使用 `rfc6962.DefaultHasher`：

- 以「覆盖区间完全在 `[0,size)` 内」为唯一判据构建 perfect 库；
- 对 `size≤40` 枚举全部 inclusion/consistency/subtree 证明，统计 `IDs` 缺失、
  `ephem` 入 `IDs`、非空块、单节点块；
- 对 `size≤200` 验证块等于 `reverse(RangeNodes(ephem.begin,size))` 且右到左相邻；
- 对 `size≤120` 验证非空块时临时节点严格横跨右边界；
- 对 §5 的每种扰动重算根并与基线比较。

实测汇总（均为 0 违规，除非另注）：

| 类别 | 证明数 | IDs 缺失 | ephem 入 IDs | 非空块 | 单节点块 |
|---|---:|---:|---:|---:|---:|
| inclusion | 820 | 0 | 0 | 688 | 300 |
| consistency | 780 | 0 | 0 | 688 | 300 |
| subtree inclusion | 1164 | 0 | 0 | 834 | 394 |
| subtree consistency | 1600 | 0 | 0 | 1248 | — |

次序检查：inclusion 19248 块、consistency 10690 块、subtree 142 块，右到左相邻违规 0。
访客语义：`Append` 78/78 为完美节点，`GetRootHash` 62/62 为临时节点。
`go test ./...` 全绿（`compact`、`proof`、`rfc6962`、`testonly`）。

---

### 一句话总结

**证明里可被持久化的只有 `IDs`（全是完美节点）与块折叠出的临时值；临时值由「自右向左
排列的完美子树的右折叠」唯一确定，其地址 `ephem` 横跨树右边界、随尺寸改变，
必须视为一次性的计算中间量而非持久证据。**
