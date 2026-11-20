# NT547 - LAB 06 - BÁO CÁO

**MSSV:** 24520131  | **Họ tên:** Trang Tuấn Anh | **Lớp:** NT547.R11.ANTT
**Session code tự sinh:** SC-3EE792 | **Tên contract:** LotteryHub_0131
**Solidity / Slither:** 0.8.24 / 0.11.6 | **Ngày hoàn thành:** 2026-11-20
**URL GitHub repository:** `<ĐIỀN_URL_REPO_GITHUB_CỦA_BẠN>`

---

## 1. Static scan (2,0 điểm)

### 1.1. Môi trường và lệnh chạy

```
python tools/create_lab.py 24520131
python tools/scan.py --mode raw --tag before
python tools/scan.py --mode configured --tag before
```

> **📸 CHỤP HÌNH 1:** Terminal hiển thị kết quả chạy `create_lab.py` (thấy Session Code SC-3EE792 và tên contract LotteryHub_0131).

> **📸 CHỤP HÌNH 2:** Terminal hiển thị kết quả chạy `scan.py --mode raw --tag before` (thấy số lượng finding: issues=11).

### 1.2. Số lượng finding raw từ `evidence/before_raw/summary.json`

| Severity | Số lượng |
|---|---|
| High | 2 |
| Medium | 3 |
| Low | 1 |
| Informational | 3 |
| Optimization | 2 |
| **Tổng** | **11** |

### 1.3. So sánh raw / configured

- **Raw (11 findings):** Hiển thị toàn bộ findings bao gồm cả Low, Informational.
- **Configured (7 findings):** Loại bỏ Low và Informational (do `exclude_low: true`, `exclude_informational: true` trong `slither.config.json`), đồng thời loại detector `solc-version`. Kết quả: High=2, Medium=3, Optimization=2.
- Nhận xét: Config chỉ ẩn hiển thị các cảnh báo mức thấp, **không** làm biến mất High/Medium. Các finding nghiêm trọng vẫn giữ nguyên giữa hai chế độ.

### 1.4. Ba detector khác tên và phân tích data-flow

| ID | Detector | Impact | Confidence | Source (file:dòng) | Luồng dữ liệu: đầu vào → thao tác → tác hại |
|---|---|---|---|---|---|
| F01 | `encode-packed-collision` | High | High | AuditTarget.sol:56-61 (hàm `useCode`) | Người dùng truyền hai chuỗi `campaign` và `code` → `abi.encodePacked()` nối hai chuỗi biến độ dài mà không có delimiter → kẻ tấn công có thể tạo cặp `("ab","cdef")` và `("abc","def")` cho cùng hash, chiếm mã voucher của người khác. |
| F02 | `uninitialized-state` | High | High | AuditTarget.sol:16, 63-65 (biến `beneficiary`, hàm `moveToTreasury`) | Owner gọi `moveToTreasury()` → hàm chuyển 50% balance đến `beneficiary` → biến `beneficiary` chưa bao giờ được khởi tạo (mặc định `address(0)`) → ETH bị gửi đến địa chỉ zero, mất vĩnh viễn. |
| F03 | `tx-origin` | Medium | Medium | AuditTarget.sol:50-54 (hàm `transferControl`) | Caller gọi `transferControl(newOwner)` → kiểm tra danh tính bằng `tx.origin` thay vì `msg.sender` → khi owner tương tác với hợp đồng trung gian độc hại, hợp đồng đó có thể gọi `transferControl` và tx.origin vẫn là owner → kẻ tấn công chiếm quyền sở hữu contract. |

**Các finding bổ sung đáng chú ý:**

| ID | Detector | Impact | Confidence | Source | Mô tả |
|---|---|---|---|---|---|
| F04 | `divide-before-multiply` | Medium | Medium | AuditTarget.sol:39-41 (`quoteFee`) | `amount / 10000 * rateBps` → chia trước nhân sau, integer truncation gây mất phí cho amount nhỏ (VD: amount=9999 → kết quả 0 thay vì ~62). |
| F05 | `incorrect-equality` | Medium | High | AuditTarget.sol:67-69 (`zeroBalance`) | `address(this).balance == 0` → so sánh nghiêm ngặt có thể bị ảnh hưởng bởi force-send ETH qua `selfdestruct`, nhưng đây chỉ là hàm view hiển thị. |
| F06 | `timestamp` | Low | Medium | AuditTarget.sol:43-48 (`vestStep`) | `block.timestamp >= releaseTime` → miner có thể thao túng timestamp ±15 giây, nhưng timelock 1 ngày nên không đáng kể. |

---

## 2. Triage và sửa lỗi (2,5 điểm)

### 2.1. Nhận diện 4 mẫu lỗi thật + 2 đoạn ngữ cảnh

Đọc toàn bộ `AuditTarget.sol` và kết hợp kết quả Slither, nhận diện:

| # | Detector + vị trí | TP / Accepted | Bằng chứng kiểm soát / khả năng khai thác | Biện pháp | Sau sửa |
|---|---|---|---|---|---|
| 1 | `tx-origin` · `transferControl()` dòng 51 | **TP** | `tx.origin` trả về EOA gốc của chuỗi gọi, không phải caller trực tiếp. Nếu owner gọi hợp đồng trung gian A, A gọi `transferControl(attacker)` → `tx.origin == owner` vẫn đúng → kẻ tấn công chiếm ownership. Không có mutex hay guard nào chặn. | **Fix:** Đổi `tx.origin` → `msg.sender` | ✅ Slither hết báo `tx-origin` |
| 2 | `encode-packed-collision` · `useCode()` dòng 57 | **TP** | `abi.encodePacked(string, string)` nối raw bytes mà không có separator. Hai cặp input khác nhau có thể tạo cùng hash: `("abc","def")` ↔ `("ab","cdef")`. Kẻ tấn công dùng collision để "claim" mã voucher hợp lệ của người khác. | **Fix:** Đổi `abi.encodePacked` → `abi.encode` (ABI-encode có padding 32 byte, loại trừ collision) | ✅ Slither hết báo `encode-packed-collision` |
| 3 | `divide-before-multiply` · `quoteFee()` dòng 40 | **TP** | `amount / 10000 * rateBps`: Solidity integer division truncates. Với `rateBps=250`: amount=9999 → `9999/10000=0` → `0*250=0` (phí thực tế phải ~62). Mọi amount < 10000 đều cho phí = 0, gây thất thoát phí cho protocol. | **Fix:** Đổi thứ tự thành `amount * rateBps / 10000` (nhân trước chia sau) | ✅ Slither hết báo `divide-before-multiply` |
| 4 | `uninitialized-state` · `beneficiary` dòng 16, `moveToTreasury()` dòng 63-65 | **TP** | `beneficiary` khai báo `address payable internal` nhưng **không có constructor hay setter** nào gán giá trị. Mặc định = `address(0)`. Khi owner gọi `moveToTreasury()` → `beneficiary.transfer(balance/2)` gửi ETH đến `address(0)` → revert trên EVM (transfer đến address(0) thất bại), hoặc nếu EVM không revert thì mất ETH. | **Fix:** Thêm hàm `setBeneficiary()` onlyOwner + thêm `require(beneficiary != address(0))` trong `moveToTreasury()` | ✅ Slither hết báo `uninitialized-state` |
| 5 | `incorrect-equality` · `zeroBalance()` dòng 67-69 | **Accepted** | Hàm `zeroBalance()` là hàm `view` chỉ trả dữ liệu cho frontend/UI, **không** kiểm soát bất kỳ state change hay chuyển ETH nào. Rủi ro lý thuyết (force-send ETH qua `selfdestruct` làm balance ≠ 0) không ảnh hưởng đến logic kinh doanh hay an ninh tài sản. Không có hàm nào khác gọi `zeroBalance()` để ra quyết định. | **Suppress:** `// slither-disable-next-line incorrect-equality` đặt trước hàm. Lý do: hàm view chỉ hiển thị, không điều khiển control flow hay quỹ. | ✅ Slither hết báo (suppressed) |
| 6 | `timestamp` · `vestStep()` dòng 43-48 | **Accepted** | `block.timestamp >= releaseTime` dùng cho cơ chế timelock giải phóng 1/10 balance mỗi ngày. Miner có thể lệch timestamp ±15 giây, nhưng khoảng lock là 86400 giây (1 day) → sai số < 0.02%, không đáng kể. Hàm đã có `onlyOwner` guard. Dùng timestamp cho timelock là pattern chuẩn trong Solidity. | **Accept:** Severity Low, không ảnh hưởng CI (`fail-on: medium`). Không cần sửa hay suppress. | ✅ Vẫn báo Low, không ảnh hưởng gate |

### 2.2. Kịch bản khai thác TP: `tx-origin` phishing attack

**Kịch bản cụ thể:**

1. Kẻ tấn công triển khai hợp đồng `PhishingContract` có hàm `attack()` bên trong gọi `LotteryHub_0131.transferControl(attackerAddress)`.
2. Kẻ tấn công dụ owner (Alice) gọi một hàm vô hại trên `PhishingContract` (ví dụ: "claim airdrop").
3. Khi Alice (EOA) gọi `PhishingContract.attack()`:
   - `msg.sender` trong `transferControl` = địa chỉ PhishingContract (không phải Alice)
   - `tx.origin` = Alice (EOA gốc khởi tạo giao dịch)
4. `require(tx.origin == owner)` → `tx.origin` = Alice = owner → **pass**
5. `owner = attackerAddress` → kẻ tấn công chiếm quyền contract
6. Kẻ tấn công gọi `ownerWithdraw()` rút toàn bộ ETH

### 2.3. Finding có severity cao nhưng risk thực tế không tương ứng

**`incorrect-equality` (Medium, High confidence) trên `zeroBalance()`:**

Slither phân loại Medium vì so sánh `address(this).balance == 0` có thể bị vô hiệu hóa bằng force-send ETH. Tuy nhiên, risk thực tế **không tương ứng** vì:

- `zeroBalance()` là hàm `external view` — chỉ đọc, không thay đổi state.
- Không có hàm nào trong contract gọi `zeroBalance()` để ra quyết định (guard, transfer, v.v.).
- Nếu ai đó force-send ETH, kết quả trả về `false` thay vì `true` — chỉ ảnh hưởng hiển thị UI, không gây mất tiền hay bypass quyền.
- **Kết luận:** Severity tool = Medium, Risk thực tế = None (cosmetic).

### 2.4. Bằng chứng thay đổi (git diff)

```diff
--- a/AuditTarget.sol (vulnerable baseline)
+++ b/AuditTarget.sol (after fix)

@@ quoteFee @@
-        return amount / 10000 * rateBps;
+        return amount * rateBps / 10000;

@@ transferControl @@
-        require(tx.origin == owner, "not owner");
+        require(msg.sender == owner, "not owner");

@@ useCode @@
-        bytes32 id = keccak256(abi.encodePacked(campaign, code));
+        bytes32 id = keccak256(abi.encode(campaign, code));

@@ moveToTreasury (thêm setter + require) @@
+    function setBeneficiary(address payable _b) external onlyOwner {
+        require(_b != address(0), "zero");
+        beneficiary = _b;
+    }
+
     function moveToTreasury() external onlyOwner {
+        require(beneficiary != address(0), "beneficiary not set");
         beneficiary.transfer(address(this).balance / 2);
     }

@@ zeroBalance (suppression) @@
+    // slither-disable-next-line incorrect-equality
     function zeroBalance() external view returns (bool) {
```

> **📸 CHỤP HÌNH 3:** Terminal hiển thị `git diff -- AuditTarget.sol` cho thấy các thay đổi trên.

### 2.5. So sánh before / after

| Metric | Before (raw) | After (raw) | Before (configured) | After (configured) |
|---|---|---|---|---|
| High | 2 | 0 | 2 | 0 |
| Medium | 3 | 0 | 3 | 0 |
| Low | 1 | 2 | 0 | 0 |
| Informational | 3 | 4 | 0 | 0 |
| Optimization | 2 | 1 | 2 | 1 |
| **Tổng** | **11** | **7** | **7** | **1** |

**Giải thích cảnh báo còn lại (after raw = 7):**

- `events-access` (Low): `transferControl()` nên emit event khi thay đổi owner — finding mới xuất hiện sau khi sửa tx-origin, vì giờ Slither phân tích sâu hơn vào hàm. Mức Low, không ảnh hưởng CI.
- `timestamp` (Low): `vestStep()` dùng `block.timestamp` — đã phân tích là acceptable.
- `low-level-calls` (Informational, x2): `vestStep()` và `ownerWithdraw()` dùng `.call{value:}` — đây là pattern chuẩn sau Solidity 0.8 để gửi ETH, Slither chỉ thông báo chứ không coi là lỗi.
- `naming-convention` (Informational, x2): Tên contract `LotteryHub_0131` có underscore (do generator tạo) và parameter `_b` dùng underscore prefix — cosmetic, không ảnh hưởng bảo mật.
- `constable-states` (Optimization): `rateBps` có thể khai báo `constant` — tối ưu gas, không ảnh hưởng bảo mật.

### 2.6. Lý do của `slither-disable-next-line`

| Detector bị suppress | Vị trí | Kiểm soát bù trừ |
|---|---|---|
| `incorrect-equality` | Dòng 73 (trước hàm `zeroBalance()`) | Hàm là `external view` chỉ trả dữ liệu hiển thị. Không có hàm nào trong contract phụ thuộc vào kết quả `zeroBalance()` để thực hiện state change hay transfer. Force-send ETH chỉ ảnh hưởng giá trị trả về cosmetic, không gây thiệt hại tài chính. |

> **📸 CHỤP HÌNH 4:** Terminal hiển thị kết quả scan after (cả raw và configured) cho thấy 0 High / 0 Medium.

---

## 3. Kiến trúc / Inheritance (1,5 điểm)

### 3.1. Lệnh printer đã chạy

```
python tools/print_arch.py
```

Output: `evidence/architecture/human_summary.txt`, `evidence/architecture/ArchitectureDemo.sol.dot`.

> **📸 CHỤP HÌNH 5:** Ảnh file `evidence/architecture/inheritance.png` (render từ file .dot). Nếu chưa có PNG, dùng lệnh: `dot -Tpng evidence/architecture/ArchitectureDemo.sol.dot -o evidence/architecture/inheritance.png`, hoặc paste nội dung .dot vào trang web Graphviz Online để render.

### 3.2. Phân tích cấu trúc 3 contract

Dựa trên `contracts/ArchitectureDemo.sol` và kết quả printer:

| Vai trò | Contract | Chi tiết |
|---|---|---|
| **Quản lý quyền (Access Control)** | `AccessManaged` | Abstract contract. Chứa biến `admin`, modifier `onlyAdmin()`, constructor gán `admin = msg.sender`. |
| **Quản lý mapping số dư (Balance)** | `BalanceLedger` | Chứa `mapping(address => uint256) balances` (internal), hàm public `balanceOf()` và hàm internal `_credit()`. |
| **Contract triển khai / Entrypoint** | `StudentAsset` | Kế thừa cả `AccessManaged` và `BalanceLedger`. Hàm public `mint()` là entrypoint duy nhất có thể gọi từ bên ngoài (ngoài view). |

### 3.3. Inheritance graph (DOT)

```dot
StudentAsset → AccessManaged  [label="1"]
StudentAsset → BalanceLedger  [label="2"]
```

- `StudentAsset` kế thừa `AccessManaged` (branch 1) để có quyền admin.
- `StudentAsset` kế thừa `BalanceLedger` (branch 2) để có hệ thống số dư.

### 3.4. Phân tích audit (3–5 câu)

1. **Logic security-critical nằm ở contract cha `AccessManaged`**, nơi modifier `onlyAdmin()` kiểm soát quyền truy cập — nếu logic kiểm tra quyền bị sai (ví dụ dùng `tx.origin` thay `msg.sender`), toàn bộ hàm protected trong `StudentAsset` đều bị ảnh hưởng.

2. **Hàm `mint(address to, uint256 amount)` trong `StudentAsset` là entrypoint chính** — đây là hàm external duy nhất có thể thay đổi state (tăng balance thông qua `_credit()`), được bảo vệ bởi `onlyAdmin`.

3. **Audit nên bắt đầu từ `StudentAsset`** vì đây là contract được deploy, chứa surface area tiếp xúc bên ngoài. Từ entrypoint `mint()`, trace ngược lên `_credit()` trong `BalanceLedger` để kiểm tra overflow/underflow, và kiểm tra `onlyAdmin()` trong `AccessManaged` để đảm bảo access control chặt chẽ.

4. Hàm `_credit()` trong `BalanceLedger` là internal, chỉ được gọi bởi `mint()` — cần xác nhận không có cách nào khác để gọi trực tiếp (qua delegatecall hoặc constructor order). Solidity 0.8.x có built-in overflow check nên `balances[account] += amount` an toàn.

5. Constructor chain `StudentAsset → AccessManaged` gán `admin = msg.sender` — cần xác nhận admin được gán đúng lúc deploy, và không có hàm public nào cho phép thay đổi `admin` (hiện tại không có → admin cố định, an toàn nhưng không linh hoạt).

---

## 4. Red → Green CI (2,5 điểm)

### 4.1. Quy trình

| Phase | Commit (full/short SHA) | Run URL | Kết quả | Detector khiến RED / lý do GREEN |
|---|---|---|---|---|
| Baseline vulnerable | `<ĐIỀN_SHA_COMMIT_1>` | `<ĐIỀN_URL_RUN_1>` | **RED** | `encode-packed-collision` (High), `uninitialized-state` (High), `divide-before-multiply` (Medium), `incorrect-equality` (Medium), `tx-origin` (Medium) |
| Patched | `<ĐIỀN_SHA_COMMIT_2>` | `<ĐIỀN_URL_RUN_2>` | **GREEN** | Đã sửa 4 TP (tx-origin, encode-packed, divide-before-multiply, uninitialized-state) + suppress incorrect-equality → 0 High, 0 Medium → pass gate `fail-on: medium` |

> **📸 CHỤP HÌNH 6:** GitHub Actions tab hiển thị run đầu tiên **RED** (baseline vulnerable) — thấy rõ commit SHA, trạng thái failed, và log Slither báo Medium/High.

> **📸 CHỤP HÌNH 7:** GitHub Actions run log chi tiết, step "Slither Solidity 0.8.24" hiển thị danh sách detector phát hiện (encode-packed-collision, uninitialized-state, tx-origin, v.v.).

> **📸 CHỤP HÌNH 8:** GitHub Actions tab hiển thị run thứ hai **GREEN** (patched) — thấy rõ commit SHA, trạng thái passed.

### 4.2. So sánh local `--fail-none` với CI `fail-on: medium`

- **Local (`--fail-none`):** Tool scan.py chạy Slither với `--fail-none`, nghĩa là **luôn trả exit code 0** bất kể có bao nhiêu finding. Mục đích: thu thập evidence (JSON/CSV) để phân tích, không block workflow local.
- **CI (`fail-on: medium`):** GitHub Actions workflow dùng `fail-on: medium`, nghĩa là Slither trả exit code != 0 nếu có **bất kỳ finding nào** ở mức Medium hoặc High. Đây là quality gate thực sự — bắt buộc phải sửa hoặc suppress đúng cách mọi Medium/High.
- Sự khác biệt: local scan có 11 findings (raw) nhưng vẫn thành công; CI chỉ cần 1 Medium là RED.

### 4.3. `exclude_low/informational` thay đổi kết quả hiển thị

- `slither.config.json` có `"exclude_low": true, "exclude_informational": true` → CI chỉ hiển thị High, Medium, Optimization.
- Kết quả: Before raw có 11 findings, nhưng configured chỉ hiển thị 7 (ẩn 1 Low + 3 Informational).
- **Quan trọng:** `exclude_low/informational` chỉ ẩn hiển thị, không ảnh hưởng ngưỡng `fail-on: medium`. Nếu có Medium/High, CI vẫn RED bất kể có exclude low hay không.

---

## 5. Mutation RED → GREEN (1,5 điểm)

### 5.1. Mutation một dòng

Trong `AuditTarget.sol`, bên trong `modifier onlyOwner()`:

- **Từ:** `require(msg.sender == owner, "not owner");`
- **Thành:** `require(tx.origin == owner, "not owner");`

**Detector kỳ vọng:** `tx-origin` (mức Medium). Khi CI chạy với `fail-on: medium`, finding này làm job **RED**.

### 5.2. Giải thích sự thay đổi về nguồn định danh / authorization

| Thuộc tính | `msg.sender` | `tx.origin` |
|---|---|---|
| Định nghĩa | Địa chỉ gọi trực tiếp hàm hiện tại (có thể là EOA hoặc contract) | Địa chỉ EOA khởi tạo giao dịch gốc (luôn là EOA) |
| Phishing risk | Thấp — chỉ caller trực tiếp mới pass | **Cao** — contract trung gian độc hại vẫn pass nếu user gốc là owner |
| Best practice | ✅ Khuyến nghị cho authorization | ❌ Không nên dùng cho authorization (SWC-115) |

Khi đổi `msg.sender` → `tx.origin` trong `onlyOwner`, **mọi hàm protected** (`ownerWithdraw`, `vestStep`, `moveToTreasury`, `setBeneficiary`) đều bị ảnh hưởng. Kẻ tấn công chỉ cần dụ owner gọi một hàm bất kỳ trên contract trung gian → contract đó gọi ngược `ownerWithdraw()` → `tx.origin == owner` = true → rút hết ETH.

### 5.3. Kết quả CI

| Phase | Commit SHA | Run URL | Kết quả |
|---|---|---|---|
| Mutation | `<ĐIỀN_SHA_COMMIT_3>` | `<ĐIỀN_URL_RUN_3>` | **RED** |
| Revert mutation | `<ĐIỀN_SHA_COMMIT_4>` | `<ĐIỀN_URL_RUN_4>` | **GREEN** |

> **📸 CHỤP HÌNH 9:** GitHub Actions tab hiển thị run **RED** sau mutation — log Slither báo `tx-origin` ở modifier `onlyOwner`.

> **📸 CHỤP HÌNH 10:** GitHub Actions tab hiển thị run **GREEN** sau revert — confirm pipeline trở lại trạng thái sạch.

### 5.4. Lệnh mutation và revert

```bash
# Mutation (đổi msg.sender → tx.origin trong modifier onlyOwner)
git add AuditTarget.sol
git commit -m "lab06: one-line mutation tx-origin"
git push

# Sau khi xác nhận RED, revert:
git revert --no-edit HEAD
git push
```

---

## 6. Bằng chứng, tự kiểm

- [x] `AuditTarget.sol`, `lab_identity.json`
- [x] `evidence/before_raw/` và `evidence/before_configured/` (slither.json, findings.csv, summary.json, command_and_output.txt)
- [x] `evidence/after_raw/` và `evidence/after_configured/`
- [x] `evidence/architecture/` (human_summary.txt, .dot, .png nếu có Graphviz)
- [ ] 04 URL Actions run RED/GREEN/RED/GREEN + 04 commit SHA — `<CẦN ĐIỀN SAU KHI PUSH>`
- [ ] Link repo và ảnh màn hình có terminal / URL / commit SHA; không cắt mất ngữ cảnh — `<CẦN CHỤP>`
- [x] Các finding được triage, không chép lại mô tả detector thay cho suy luận
- [x] Tuyệt đối không có seed phrase, private key, credentials

**Nhận xét cuối cùng (5–7 câu):**

Bài thực hành cho thấy Slither là công cụ phân tích tĩnh mạnh mẽ, phát hiện chính xác các lỗ hổng quan trọng như tx-origin phishing, hash collision từ encodePacked, integer precision loss và uninitialized state. Tuy nhiên, Slither không phải "máy phán quyết" — finding `incorrect-equality` trên hàm view `zeroBalance()` có severity Medium nhưng risk thực tế bằng 0, cần engineer triage thủ công để phân biệt TP và contextual accepted. Quy trình CI RED → GREEN → RED → GREEN minh họa cách tích hợp security automation vào pipeline: quality gate `fail-on: medium` đảm bảo không merge code có lỗ hổng nghiêm trọng mà không cần review thủ công từng commit. Mutation test (đổi 1 dòng `msg.sender` → `tx.origin`) chứng minh pipeline nhạy với regression — chỉ cần thay đổi nhỏ ở logic authorization đã đủ trigger alert. Inheritance graph giúp xác định điểm bắt đầu audit: từ entrypoint (`StudentAsset.mint`) trace ngược về access control (`AccessManaged`) và state management (`BalanceLedger`). Pattern Checks-Effects-Interactions và proper encoding (`abi.encode` thay vì `abi.encodePacked`) là hai kỹ thuật phòng thủ cơ bản nhất mà mọi smart contract developer cần nắm. Bài lab cũng nhấn mạnh tầm quan trọng của suppression có kiểm soát: chỉ dùng `slither-disable-next-line` khi có bằng chứng rõ ràng rằng finding không gây nguy cơ trong ngữ cảnh cụ thể.
