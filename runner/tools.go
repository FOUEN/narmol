package runner

import (
	gau_cmd "github.com/lc/gau/v2/cmd/gau"
	dnsx_cmd "github.com/projectdiscovery/dnsx/cmd/dnsx"
	httpx_cmd "github.com/projectdiscovery/httpx/cmd/httpx"
	katana_cmd "github.com/projectdiscovery/katana/cmd/katana"
	nuclei_cmd "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
	subfinder_cmd "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
)

func init() {
	Register(Tool{Name: "nuclei", Description: "Run nuclei scanner", Main: nuclei_cmd.Main})
	Register(Tool{Name: "httpx", Description: "Run httpx prober", Main: httpx_cmd.Main})
	Register(Tool{Name: "katana", Description: "Run katana crawler", Main: katana_cmd.Main})
	Register(Tool{Name: "dnsx", Description: "Run dnsx resolver", Main: dnsx_cmd.Main})
	Register(Tool{Name: "subfinder", Description: "Run subfinder enumerator", Main: subfinder_cmd.Main})
	Register(Tool{Name: "gau", Description: "Run gau URL fetcher", Main: gau_cmd.Main})
}
