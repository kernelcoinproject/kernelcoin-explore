package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// Config - Kernelcoin
const (
	MAIN_ENDPOINT   = "http://127.0.0.1:9332/"  // Kernelcoin mainnet port
	TEST_ENDPOINT   = "http://127.0.0.1:19332/" // Kernelcoin testnet port (if applicable)
	BASE_URL        = "/explorer/"
	USE_MOD_REWRITE = false
	RPC_USER        = "mike" // Default RPC user for Kernelcoin
	RPC_PASS        = "x"
	BLOCK_TXDETAILS = true
	MAX_BLOCKS_CALL = 15

	// Kernelcoin-specific parameters
	NETWORK_ID    = "kcn" // Network identifier
	NETWORK_NAME  = "Kernelcoin"
	BECH32_HRP    = "kcn" // Bech32 HRP for SegWit addresses
	MWEB_HRP      = "kcnmweb"
	SYMBOL        = "KCN"
	GENESIS_BLOCK = "0x396cd7f9b5025069e328602e5d459a891091c7aac214713124558d05698872e7"
	GENESIS_TIME  = "Nov 13 2025 NYSE GME Closes 20.96"

	// Template directory
	TEMPLATES_DIR = "./templates"
)

// ViewType constants
const (
	ViewOverview = iota
	ViewBlock
	ViewTransaction
	ViewNotFound
	ViewNodeInfo
	ViewAddrSearch
	ViewTxHistory
)

// RPC Response structures
type RPCResponse struct {
	Result interface{} `json:"result"`
	Error  interface{} `json:"error"`
	ID     string      `json:"id"`
}

type BlockchainInfo struct {
	Chain                string  `json:"chain"`
	Blocks               int     `json:"blocks"`
	BestBlockHash        string  `json:"bestblockhash"`
	Difficulty           float64 `json:"difficulty"`
	MedianTime           int64   `json:"mediantime"`
	VerificationProgress float64 `json:"verificationprogress"`
}

type NetworkInfo struct {
	Version     int           `json:"version"`
	Subversion  string        `json:"subversion"`
	Connections int           `json:"connections"`
	Networks    []interface{} `json:"networks"`
}

type Block struct {
	Hash              string        `json:"hash"`
	Height            int           `json:"height"`
	Version           int           `json:"version"`
	VersionHex        string        `json:"versionHex"`
	Merkleroot        string        `json:"merkleroot"`
	Time              int64         `json:"time"`
	Mediantime        int64         `json:"mediantime"`
	Nonce             int           `json:"nonce"`
	Bits              string        `json:"bits"`
	Difficulty        float64       `json:"difficulty"`
	Chainwork         string        `json:"chainwork"`
	NTx               int           `json:"nTx"`
	PreviousBlockHash string        `json:"previousblockhash"`
	NextBlockHash     string        `json:"nextblockhash"`
	Size              int           `json:"size"`
	Weight            int           `json:"weight"`
	Tx                []interface{} `json:"tx"`
	Stats             *BlockStats   `json:"stats,omitempty"`
	Age               string        `json:"-"`
}

type BlockStats struct {
	AverageFee     int64 `json:"avgfee"`
	AverageFeeRate int64 `json:"avgfeerate"`
	MaxFee         int64 `json:"maxfee"`
	MaxFeeRate     int64 `json:"maxfeerate"`
	MinFee         int64 `json:"minfee"`
	MinFeeRate     int64 `json:"minfeerate"`
	MedianFee      int64 `json:"medianfee"`
	MedianFeeRate  int64 `json:"medianfeerate"`
	TotalFee       int64 `json:"totalfee"`
	TotalOut       int64 `json:"total_out"`
	Subsidy        int64 `json:"subsidy"`
	Ins            int   `json:"ins"`
	Outs           int   `json:"outs"`
	Txs            int   `json:"txs"`
}

type Transaction struct {
	TxID          string        `json:"txid"`
	Hash          string        `json:"hash"`
	Version       int           `json:"version"`
	Size          int           `json:"size"`
	Vsize         int           `json:"vsize"`
	Weight        int           `json:"weight"`
	Locktime      int64         `json:"locktime"`
	Vin           []TxIn        `json:"vin"`
	Vout          []TxOut       `json:"vout"`
	Hex           string        `json:"hex"`
	Time          int64         `json:"time"`
	Blocktime     int64         `json:"blocktime"`
	Blockhash     string        `json:"blockhash"`
	Confirmations int           `json:"confirmations"`
	Fee           float64       `json:"-"`
	TotalIn       float64       `json:"-"`
	TotalOut      float64       `json:"-"`
	Mempool       *MempoolEntry `json:"-"`
}

type TxIn struct {
	TXID        string    `json:"txid"`
	Vout        int       `json:"vout"`
	ScriptSig   ScriptSig `json:"scriptSig"`
	Sequence    int64     `json:"sequence"`
	TxinWitness []string  `json:"txinwitness,omitempty"`
	Prevout     *TxOut    `json:"-"`
}

type TxOut struct {
	Value        float64      `json:"value"`
	N            int          `json:"n"`
	ScriptPubKey ScriptPubKey `json:"scriptPubKey"`
	IsUnspent    bool         `json:"-"`
}

type ScriptSig struct {
	Asm string `json:"asm"`
	Hex string `json:"hex"`
}

type ScriptPubKey struct {
	Asm       string   `json:"asm"`
	Hex       string   `json:"hex"`
	Type      string   `json:"type"`
	Address   string   `json:"address"`
	Addresses []string `json:"addresses"`
}

type MempoolEntry struct {
	Size            int      `json:"size"`
	Vsize           int      `json:"vsize"`
	Weight          int      `json:"weight"`
	Time            int64    `json:"time"`
	Fee             float64  `json:"fee"`
	Fees            FeesInfo `json:"fees"`
	ModifiedFee     float64  `json:"modifiedfee"`
	ModifiedFeeRate float64  `json:"modifiedfeeRate"`
}

type FeesInfo struct {
	Base       float64 `json:"base"`
	Modified   float64 `json:"modified"`
	Ancestor   float64 `json:"ancestor"`
	Descendant float64 `json:"descendant"`
}

type ValidateAddressResult struct {
	IsValid        bool   `json:"isvalid"`
	Address        string `json:"address"`
	ScriptPubKey   string `json:"scriptPubKey"`
	IsScript       bool   `json:"isscript"`
	IsWitness      bool   `json:"iswitness"`
	WitnessVersion int    `json:"witness_version"`
	WitnessProgram string `json:"witness_program"`
}

// Template data
type PageData struct {
	Title          string
	NetworkName    string
	HomeLink       string
	NodeInfoLink   string
	Blocks         []*Block
	Block          *Block
	Transaction    *Transaction
	Address        string
	AddressData    *ValidateAddressResult
	NetworkInfo    *NetworkInfo
	BlockchainInfo *BlockchainInfo
	ViewType       int
	Error          string
}

// App context
type App struct {
	endpoint  string
	title     string
	lineAdd   string
	templates *template.Template
}

func cleanHex(in string) string {
	re := regexp.MustCompile(`[^a-fA-F0-9]`)
	return html.EscapeString(re.ReplaceAllString(in, ""))
}

func cleanSearch(in string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9]`)
	return html.EscapeString(re.ReplaceAllString(in, ""))
}

func cleanNum(in string) string {
	re := regexp.MustCompile(`[^0-9]`)
	return html.EscapeString(re.ReplaceAllString(in, ""))
}

func shortHash(hash string) string {
	if len(hash) < 12 {
		return hash
	}
	return hash[:6] + "..." + hash[len(hash)-12:]
}

func shortAddr(addr string) string {
	if len(addr) <= 36 {
		return addr
	}
	return addr[:25] + "..." + addr[len(addr)-8:]
}

func btcAmount(amount float64) string {
	return fmt.Sprintf("%0.8f %s", amount, SYMBOL)
}

func hexToASCII(hexStr string) string {
	// Remove any whitespace
	hexStr = regexp.MustCompile(`\s`).ReplaceAllString(hexStr, "")

	// Convert hex string to bytes
	bytes := make([]byte, 0)
	for i := 0; i < len(hexStr); i += 2 {
		if i+1 < len(hexStr) {
			var b byte
			fmt.Sscanf(hexStr[i:i+2], "%x", &b)
			bytes = append(bytes, b)
		}
	}

	// Convert bytes to ASCII, replacing non-printable characters
	result := ""
	for _, b := range bytes {
		if b >= 32 && b <= 126 {
			result += string(b)
		} else {
			result += "."
		}
	}
	return result
}

func isOpReturn(scriptHex string) bool {
	// OP_RETURN is 0x6a
	return len(scriptHex) >= 2 && scriptHex[:2] == "6a"
}

func extractOpReturnData(scriptHex string) string {
	// OP_RETURN format: 6a [length] [data]
	if !isOpReturn(scriptHex) {
		return ""
	}

	// Skip the OP_RETURN opcode (6a)
	if len(scriptHex) < 4 {
		return ""
	}

	// The next byte(s) indicate the length
	// For simplicity, we'll just return everything after 6a
	return scriptHex[2:]
}

func (a *App) rpcFetch(method string, params string) (json.RawMessage, error) {
	payload := fmt.Sprintf(`{"jsonrpc":"1.0","method":"%s","params":%s}`, method, params)

	req, err := http.NewRequest("POST", a.endpoint, bytes.NewBufferString(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "text/plain")
	req.SetBasicAuth(RPC_USER, RPC_PASS)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp RPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, err
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: %v", rpcResp.Error)
	}

	result, _ := json.Marshal(rpcResp.Result)
	return result, nil
}

func (a *App) getBlockchainInfo() (*BlockchainInfo, error) {
	data, err := a.rpcFetch("getblockchaininfo", "[]")
	if err != nil {
		return nil, err
	}
	var info BlockchainInfo
	json.Unmarshal(data, &info)
	return &info, nil
}

func (a *App) getNetworkInfo() (*NetworkInfo, error) {
	data, err := a.rpcFetch("getnetworkinfo", "[]")
	if err != nil {
		return nil, err
	}
	var info NetworkInfo
	json.Unmarshal(data, &info)
	return &info, nil
}

func (a *App) getBlockJSON(hash string, verbose bool) (*Block, error) {
	verboseInt := 1
	if verbose {
		verboseInt = 2
	}
	data, err := a.rpcFetch("getblock", fmt.Sprintf(`["%s", %d]`, hash, verboseInt))
	if err != nil {
		return nil, err
	}

	var block Block
	if err := json.Unmarshal(data, &block); err != nil {
		return nil, err
	}
	return &block, nil
}

func (a *App) getTxJSON(hash string) (*Transaction, error) {
	data, err := a.rpcFetch("getrawtransaction", fmt.Sprintf(`["%s", true]`, hash))
	if err != nil {
		return nil, err
	}

	var tx Transaction
	if err := json.Unmarshal(data, &tx); err != nil {
		return nil, err
	}

	return &tx, nil
}

func (a *App) getLastBlocks(topHash string, count int) ([]*Block, error) {
	var blocks []*Block
	hash := topHash
	now := time.Now().Unix()

	for i := 0; i < count; i++ {
		block, err := a.getBlockJSON(hash, false)
		if err != nil {
			break
		}

		age := now - block.Time
		if age > 3600 {
			block.Age = fmt.Sprintf("%d hours, %d min", age/3600, (age%3600)/60)
		} else if age > 60 {
			block.Age = fmt.Sprintf("%d mins, %d secs", age/60, age%60)
		} else {
			block.Age = "New block"
		}

		blocks = append(blocks, block)
		if block.PreviousBlockHash == "" {
			break
		}
		hash = block.PreviousBlockHash
	}

	return blocks, nil
}

func (a *App) blockLink(hash string, txid string) string {
	link := BASE_URL + "?block=" + hash
	if txid != "" {
		link += "&txid=" + txid
	}
	return link
}

func (a *App) txLink(hash string, vout string) string {
	link := BASE_URL + "?tx=" + hash
	if vout != "" {
		link += "&n=" + vout
	}
	return link
}

func (a *App) addressLink(addr string) string {
	return BASE_URL + "?search=" + addr
}

func (a *App) nodeInfoLink() string {
	return BASE_URL + "?nodeinfo=1"
}

func (a *App) homeLink() string {
	return BASE_URL
}

func (a *App) overviewLink(testnet bool) string {
	if testnet {
		return BASE_URL + "?testnet=1"
	}
	return BASE_URL
}

// HTTP Handlers
func (a *App) handleRequest(w http.ResponseWriter, r *http.Request) {
	viewType := ViewOverview
	var htmlTitle string = a.title
	var pageData PageData

	pageData.Title = htmlTitle
	pageData.NetworkName = NETWORK_NAME
	pageData.HomeLink = a.homeLink()
	pageData.NodeInfoLink = a.nodeInfoLink()
	pageData.ViewType = viewType

	// Parse query parameters
	search := r.URL.Query().Get("search")
	blockHash := r.URL.Query().Get("block")
	txHash := r.URL.Query().Get("tx")
	nodeInfo := r.URL.Query().Get("nodeinfo")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Handle different views
	if search != "" {
		a.handleSearch(w, r, cleanSearch(search), &pageData)
	} else if blockHash != "" {
		viewType = ViewBlock
		a.handleBlockView(w, r, cleanHex(blockHash), &pageData)
	} else if txHash != "" {
		viewType = ViewTransaction
		a.handleTransactionView(w, r, cleanHex(txHash), &pageData)
	} else if nodeInfo != "" {
		viewType = ViewNodeInfo
		a.handleNodeInfo(w, r, &pageData)
	} else {
		viewType = ViewOverview
		a.handleOverview(w, r, &pageData)
	}
}

func (a *App) handleOverview(w http.ResponseWriter, r *http.Request, data *PageData) {
	info, err := a.getBlockchainInfo()
	if err != nil {
		data.Error = fmt.Sprintf("Error: %v", err)
		data.ViewType = ViewNotFound
		a.renderTemplate(w, "error.html", data)
		return
	}

	blocks, err := a.getLastBlocks(info.BestBlockHash, 12)
	if err != nil {
		data.Error = fmt.Sprintf("Error: %v", err)
		data.ViewType = ViewNotFound
		a.renderTemplate(w, "error.html", data)
		return
	}

	data.Blocks = blocks
	data.ViewType = ViewOverview
	a.renderTemplate(w, "overview.html", data)
}

func (a *App) handleSearch(w http.ResponseWriter, r *http.Request, search string, data *PageData) {
	// Check if address - support Kernelcoin address formats
	// SegWit addresses: kcn1, KCN1, bc1, BC1
	// Legacy addresses: 1, 3, m, t (Bitcoin), K, L (Kernelcoin)
	addrRegex := regexp.MustCompile(`^(kcn1|KCN1|[13mt])[a-zA-HJ-NP-Z0-9]{25,75}$|^(bc1|BC1|[13mt])[a-zA-HJ-NP-Z0-9]{25,75}$|^[KL][a-zA-HJ-NP-Z0-9]{33}$`)

	if addrRegex.MatchString(search) {
		a.handleAddressSearch(w, r, search, data)
		return
	}

	// Try as block or tx
	var block *Block
	var tx *Transaction
	var err error

	// Check if numeric (height)
	if height, err := strconv.Atoi(search); err == nil {
		blockData, _ := a.rpcFetch("getblockhash", fmt.Sprintf("[%d]", height))
		var blockhash string
		json.Unmarshal(blockData, &blockhash)
		if blockhash != "" {
			block, _ = a.getBlockJSON(blockhash, true)
		}
	}

	if block == nil {
		block, err = a.getBlockJSON(search, true)
	}

	if block != nil {
		data.Block = block
		data.ViewType = ViewBlock
		a.renderTemplate(w, "block.html", data)
		return
	}

	// Try transaction
	tx, err = a.getTxJSON(search)
	if err != nil || tx == nil {
		data.Error = "Object not found: " + search
		data.ViewType = ViewNotFound
		a.renderTemplate(w, "error.html", data)
		return
	}

	data.Transaction = tx
	data.ViewType = ViewTransaction
	a.renderTemplate(w, "transaction.html", data)
}

func (a *App) handleBlockView(w http.ResponseWriter, r *http.Request, hash string, data *PageData) {
	block, err := a.getBlockJSON(hash, true)
	if err != nil {
		data.Error = "Block not found"
		data.ViewType = ViewNotFound
		a.renderTemplate(w, "error.html", data)
		return
	}
	data.Block = block
	data.ViewType = ViewBlock
	a.renderTemplate(w, "block.html", data)
}

func (a *App) handleTransactionView(w http.ResponseWriter, r *http.Request, hash string, data *PageData) {
	tx, err := a.getTxJSON(hash)
	if err != nil {
		data.Error = "Transaction not found"
		data.ViewType = ViewNotFound
		a.renderTemplate(w, "error.html", data)
		return
	}
	data.Transaction = tx
	data.ViewType = ViewTransaction
	a.renderTemplate(w, "transaction.html", data)
}

func (a *App) handleAddressSearch(w http.ResponseWriter, r *http.Request, address string, data *PageData) {
	// Check for scan requests
	if r.URL.Query().Get("utxolookupstatus") != "" {
		a.handleUTXOLookupStatus(w, r, address)
		return
	}
	if r.URL.Query().Get("utxolookup") != "" {
		a.handleUTXOLookup(w, r, address)
		return
	}
	if r.URL.Query().Get("scanfiltersstatus") != "" {
		a.handleScanFiltersStatus(w, r, address)
		return
	}
	if r.URL.Query().Get("scanfilters") != "" {
		a.handleScanFilters(w, r, address)
		return
	}

	rpcData, err := a.rpcFetch("validateaddress", fmt.Sprintf(`["%s"]`, address))
	if err != nil {
		data.Error = fmt.Sprintf("Error: %v", err)
		data.ViewType = ViewNotFound
		a.renderTemplate(w, "error.html", data)
		return
	}

	var addrData ValidateAddressResult
	json.Unmarshal(rpcData, &addrData)

	data.Address = address
	data.AddressData = &addrData
	data.ViewType = ViewAddrSearch
	a.renderTemplate(w, "address.html", data)
}

func (a *App) handleUTXOLookupStatus(w http.ResponseWriter, r *http.Request, address string) {
	w.Header().Set("Content-Type", "text/plain")
	data, err := a.rpcFetch("scantxoutset", `["status"]`)
	if err != nil {
		fmt.Fprint(w, "")
		return
	}

	var result map[string]interface{}
	json.Unmarshal(data, &result)

	if result != nil {
		if progress, ok := result["progress"].(float64); ok {
			fmt.Fprintf(w, "%.0f", progress*100)
			return
		}
	}
	fmt.Fprint(w, "")
}

func (a *App) handleUTXOLookup(w http.ResponseWriter, r *http.Request, address string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Check if scan is already running
	statusData, _ := a.rpcFetch("scantxoutset", `["status"]`)
	var statusResult map[string]interface{}
	json.Unmarshal(statusData, &statusResult)

	if statusResult != nil {
		fmt.Fprint(w, "A scan is currently running. Please try again later. No concurrent scans are allowed.")
		return
	}

	// Start new scan
	scanData, err := a.rpcFetch("scantxoutset", fmt.Sprintf(`["start", ["addr(%s)"]]`, address))
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}

	var result map[string]interface{}
	json.Unmarshal(scanData, &result)

	if result == nil {
		fmt.Fprint(w, "Error: No result from scan")
		return
	}

	// Format output
	html := "<hr /><div class=\"alert alert-success\"><b>Total unspent BTC:</b> "
	if totalAmount, ok := result["total_amount"].(float64); ok {
		html += fmt.Sprintf("%.8f", totalAmount)
	}
	html += "</div><br>\n"
	html += "<h4 style=\"color: var(--primary); margin-top: 1.5rem; margin-bottom: 1rem;\">UTXOs (unspent transaction outputs)</h4>\n"
	html += "<div class=\"table-responsive\">\n"
	html += "<table class=\"table table-bordered table-hover table-striped\">\n"
	html += "<thead class=\"table-dark\"><tr><th>Amount</th><th>TXID</th><th>Vout</th></tr></thead>\n"
	html += "<tbody>\n"

	if unspents, ok := result["unspents"].([]interface{}); ok {
		for _, utxo := range unspents {
			if utxoMap, ok := utxo.(map[string]interface{}); ok {
				amount := ""
				if amt, ok := utxoMap["amount"].(float64); ok {
					amount = fmt.Sprintf("%.8f", amt)
				}
				txid := ""
				if t, ok := utxoMap["txid"].(string); ok {
					txid = t
				}
				vout := ""
				if v, ok := utxoMap["vout"].(float64); ok {
					vout = fmt.Sprintf("%.0f", v)
				}
				html += fmt.Sprintf("<tr><td>%s</td><td><a href=\"?tx=%s\">%s</a></td><td>%s</td></tr>\n", amount, txid, txid, vout)
			}
		}
	}
	html += "</tbody>\n</table>\n</div>\n"
	fmt.Fprint(w, html)
}

func (a *App) handleScanFiltersStatus(w http.ResponseWriter, r *http.Request, address string) {
	w.Header().Set("Content-Type", "text/plain")
	// For manual scanning, we store progress in a simple map
	// In production, this should use a database or cache
	fmt.Fprint(w, "")
}

func (a *App) handleScanFilters(w http.ResponseWriter, r *http.Request, address string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Get blockchain info to determine total blocks
	blockchainInfo, err := a.getBlockchainInfo()
	if err != nil {
		fmt.Fprintf(w, "<div class=\"alert alert-danger\">Error getting blockchain info: %v</div>", err)
		return
	}

	totalBlocks := blockchainInfo.Blocks
	startHeight := 0
	if sh := r.URL.Query().Get("startheight"); sh != "" {
		if h, err := strconv.Atoi(sh); err == nil {
			startHeight = h
		}
	}

	// Scan all blocks for transactions related to the address
	relevantBlocks := []string{}
	blocksProcessed := 0

	// Process blocks in batches to avoid timeout
	for height := startHeight; height < totalBlocks; height++ {
		// Get block hash by height
		blockHashData, err := a.rpcFetch("getblockhash", fmt.Sprintf("[%d]", height))
		if err != nil {
			continue
		}

		var blockHash string
		json.Unmarshal(blockHashData, &blockHash)
		if blockHash == "" {
			continue
		}

		// Get block with transactions
		block, err := a.getBlockJSON(blockHash, true)
		if err != nil {
			continue
		}

		// Check if any transaction involves the address
		found := false
		for _, tx := range block.Tx {
			if txStr, ok := tx.(string); ok {
				// Get transaction details
				txData, err := a.getTxJSON(txStr)
				if err != nil {
					continue
				}

				// Check outputs for address
				for _, vout := range txData.Vout {
					if vout.ScriptPubKey.Address == address {
						found = true
						break
					}
				}

				// Check inputs for address (spent outputs)
				if !found {
					for _, vin := range txData.Vin {
						if vin.Prevout != nil && vin.Prevout.ScriptPubKey.Address == address {
							found = true
							break
						}
					}
				}

				if found {
					break
				}
			}
		}

		if found {
			relevantBlocks = append(relevantBlocks, blockHash)
		}

		blocksProcessed++
	}

	// Format output
	html := fmt.Sprintf("<hr /><div class=\"alert alert-success\"><b>Scan Complete!</b> Found %d relevant blocks out of %d total blocks</div><br>\n", len(relevantBlocks), totalBlocks)

	html += fmt.Sprintf("    <h4 style=\"color: var(--primary); margin-top: 1.5rem; margin-bottom: 1rem;\">Relevant blocks (%d found)</h4>\n", len(relevantBlocks))
	html += "    <div class=\"table-responsive\">\n"
	html += "    <table class=\"table table-bordered table-hover table-striped\">\n"
	html += "    <thead class=\"table-dark\"><tr><th style=\"color: #fff;\">Block Hash</th></tr></thead>\n"
	html += "    <tbody>\n"

	for _, blockHash := range relevantBlocks {
		html += fmt.Sprintf("    <tr><td style=\"color: var(--text-primary);\"><a href=\"?block=%s\" style=\"color: var(--primary);\">%s</a></td></tr>\n", blockHash, blockHash)
	}

	html += "    </tbody>\n"
	html += "    </table>\n"
	html += "    </div>\n"

	fmt.Fprint(w, html)
}

func (a *App) handleNodeInfo(w http.ResponseWriter, r *http.Request, data *PageData) {
	netInfo, _ := a.getNetworkInfo()
	blockInfo, _ := a.getBlockchainInfo()

	data.NetworkInfo = netInfo
	data.BlockchainInfo = blockInfo
	data.ViewType = ViewNodeInfo
	a.renderTemplate(w, "nodeinfo.html", data)
}

func (a *App) renderTemplate(w http.ResponseWriter, templateName string, data *PageData) {
	// Create a new template set with base and content
	tmpl := template.New("page")

	// Add all parsed templates
	for _, t := range a.templates.Templates() {
		tmpl.AddParseTree(t.Name(), t.Tree)
	}

	// Create content wrapper that includes the specific template
	contentDef := fmt.Sprintf(`{{define "content"}}{{template "%s" .}}{{end}}`, templateName)
	_, err := tmpl.Parse(contentDef)
	if err != nil {
		log.Printf("Template error: %v", err)
		fmt.Fprintf(w, "Template error: %v", err)
		return
	}

	// Execute base.html which will include content
	err = tmpl.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		log.Printf("Template execution error: %v", err)
		fmt.Fprintf(w, "Template error: %v", err)
	}
}

func (a *App) loadTemplates() error {
	// Parse all templates from the templates directory
	pattern := filepath.Join(TEMPLATES_DIR, "*.html")
	tmpl, err := template.ParseGlob(pattern)
	if err != nil {
		return fmt.Errorf("error loading templates: %w", err)
	}

	a.templates = tmpl
	return nil
}

// Static file server
func serveStatic(w http.ResponseWriter, r *http.Request) {
	// Serve static files (CSS, JS, etc.)
	filePath := filepath.Join("static", r.URL.Path[len("/static/"):])
	http.ServeFile(w, r, filePath)
}

func main() {
	app := &App{
		endpoint: MAIN_ENDPOINT,
		title:    "Kernelcoin Block Explorer",
		lineAdd:  "?",
	}

	// Load templates
	err := app.loadTemplates()
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}

	http.HandleFunc("/", app.handleRequest)
	http.HandleFunc("/explorer/", app.handleRequest)
	http.HandleFunc("/static/", serveStatic)

	log.Printf("Kernelcoin Block Explorer starting on http://localhost:8080")
	log.Printf("Templates loaded from: %s", TEMPLATES_DIR)
	log.Printf("Static files served from: static/")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
