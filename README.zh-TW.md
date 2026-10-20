# reverse-engineering-carve

**把調查過的軟體功能，抽成可重用的本機功能。**

reverse-engineering-carve（說明簡稱 RECarve）是 [REA](https://github.com/morluto/rea) 的獨立附加 MCP。Agent 用 REA 調查軟體，再用 `carve` 界定功能、抽離或重建、驗證行為，存成能直接引用的功能資料夾。REA 與 carve 分別啟動，不需要合併。

[English](README.md) · [Release 與完整功能說明](https://github.com/LuckyFishOno/reverse-engineering-carve/releases/latest)

## 安裝

需要 Node22.19（22系列）或 Node24.11 以上。在 clone 下來的專案目錄執行：

```sh
npm ci
npm run build
node dist/cli.js --version
```

CLI 與 MCP 設定名稱都是 `carve`；專案與套件名稱是 `reverse-engineering-carve`。RECarve 只用於說明中的簡稱。GitHub Release 提供安裝套件，尚未發佈至 npm。

## 加入既有 REA 環境

保留原本的 REA 安裝與 MCP 設定。將以下項目加入客戶端既有的 `mcpServers`，絕對路徑換成實際位置：

```json
{
  "carve": {
    "command": "node",
    "args": ["/absolute/path/to/reverse-engineering-carve/dist/cli.js", "serve", "--root", "/absolute/path/to/workspace"]
  }
}
```

重新載入 MCP 連線，agent 應分別看到 REA 與 carve。不需要重裝 REA、額外的 LLM API key 或網站。[詳細接法](docs/REA_COMPANION.md)。

## 使用

> 用 REA 調查這個軟體，再用 carve 列出可能抽離的功能，附上證據與未知項目。選定後確認範圍，抽出或重建，以具體行為比對，最後存成能重用的本機功能資料夾。

補充功能在哪裡觸發、輸入與預期輸出，agent 仍需追查依賴。原生／行動程式支援仍屬實驗性質，建置成功不代表還原成功；執行程式的操作需要可信任的程式碼與授權。

[Release 更新、完整功能與驗證範圍](https://github.com/LuckyFishOno/reverse-engineering-carve/releases/latest) · [MIT 授權](LICENSE)
