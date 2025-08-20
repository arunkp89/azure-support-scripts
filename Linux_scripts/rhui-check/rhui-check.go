// rhuicheck.go
//
// A single-file Go translation of the provided Python script.
// Behavior parity goals:
// - Root check
// - Colored console logging + file logging to /var/log/rhuicheck.log
// - --debug flag
// - Validate ca-certificates via `rpm -V`
// - Discover RHUI RPMs and extract client cert/key and repo file paths
// - Check client cert expiry via `openssl x509 -checkend 0`
// - Enforce DEFAULT crypto policy (EL8/EL9) via `update-crypto-policies --show`
// - Read yum/dnf config for proxy and build an HTTP client that honors it
// - Parse .repo file, detect EUS/non-EUS configuration
// - Verify enabled repos, resolve hosts to known IP ranges, and fetch repodata/repomd.xml
//
// NOTE: This is self-contained in one file; it uses gopkg.in/ini.v1 for INI parsing.
// You can install it with:  go get gopkg.in/ini.v1
//
// Build:   go build -o rhuicheck rhuicheck.go
// Run:     sudo ./rhuicheck [--debug]
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/ini.v1"
)

/* ===========================
   Logging (console + file)
   =========================== */

var (
	colorBlack  = "\x1b[30;1m"
	colorGreen  = "\x1b[32;1m"
	colorYellow = "\x1b[33;1m"
	colorRed    = "\x1b[31;1m"
	colorBRed   = "\x1b[91;1m"
	colorReset  = "\x1b[0m"

	debugEnabled bool
	logger       *log.Logger
	fileOnlyLog  *log.Logger // plain (no color) to file
)

func setupLogging(debug bool) (*os.File, error) {
	debugEnabled = debug

	// Log file
	logFile := "/var/log/rhuicheck.log"
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, colorBRed+"CRITICAL: Unable to create %s; ensure root privileges, enough space, and not read-only.\n"+colorReset, logFile)
		return nil, err
	}

	// Console (colored) + file (plain)
	mw := io.MultiWriter(os.Stdout, f)
	logger = log.New(mw, "", log.LstdFlags)
	fileOnlyLog = log.New(f, "", log.LstdFlags)
	return f, nil
}

func logDebug(format string, a ...any) {
	if debugEnabled {
		logger.Printf(colorBlack+format+colorReset, a...)
	}
}
func logInfo(format string, a ...any)  { logger.Printf(colorGreen+format+colorReset, a...) }
func logWarn(format string, a ...any)  { logger.Printf(colorYellow+format+colorReset, a...) }
func logErr(format string, a ...any)   { logger.Printf(colorBRed+format+colorReset, a...) }
func logCrit(format string, a ...any)  { logger.Printf(colorRed+format+colorReset, a...) }
func logPlain(format string, a ...any) { fileOnlyLog.Printf(format, a...) }

/* ===========================
   Shell helpers
   =========================== */

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func checkCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

/* ===========================
   Globals & Patterns
   =========================== */

var (
	// RHUI infrastructure IP lists
	rhui3  = []string{"13.91.47.76", "40.85.190.91", "52.187.75.218"}
	rhui4  = []string{"52.136.197.163", "20.225.226.182", "52.142.4.99", "20.248.180.252", "20.24.186.80"}
	rhuius = []string{"13.72.186.193", "13.72.14.155", "52.224.249.194"}

	// repo file patterns
	pClientCert = regexp.MustCompile(`^/[/a-zA-Z0-9_\-]+\.(crt)$`)
	pClientKey  = regexp.MustCompile(`^/[/a-zA-Z0-9_\-]+\.(pem)$`)
	pRepoFile   = regexp.MustCompile(`^/[/a-zA-Z0-9_\-\.]+\.(repo)$`)

	// computed state
	systemProxyURL *url.URL
	eus            = false
	badHosts       = map[string]bool{} // host -> bad

	// issues map to track failures
	issues = map[string]bool{}
)

/* ===========================
   Utilities
   =========================== */

func mustRoot() {
	if os.Geteuid() != 0 {
		logCrit("This script needs to execute with root privileges.")
		logCrit("You could leverage the sudo tool to gain administrative privileges.")
		os.Exit(1)
	}
}

func validateCACerts() bool {
	_, err := runCmd("rpm", "-V", "ca-certificates")
	if err != nil {
		logErr("The ca-certificate package is invalid. Reinstall it.")
		logErr("Follow: https://learn.microsoft.com/troubleshoot/azure/virtual-machines/linux/troubleshoot-linux-rhui-certificate-issues?tabs=rhel7-eus%%2Crhel7-noneus%%2Crhel7-rhel-sap-apps%%2Crhel8-rhel-sap-apps%%2Crhel9-rhel-sap-apps#solution-4-update-or-reinstall-the-ca-certificates-package")
		return false
	}
	return true
}

func getHostFromURL(u string) (string, error) {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		// fallback to regex if necessary (keeps parity with Python)
		re := regexp.MustCompile(`[^:]*://([^/]*)/.*`)
		m := re.FindStringSubmatch(u)
		if len(m) >= 2 {
			return m[1], nil
		}
		return "", fmt.Errorf("invalid URL: %s", u)
	}
	return parsed.Host, nil
}

func unameReleaseAndArch() (release, arch string) {
	// We need OS release (kernel) and arch. Go doesn't expose uname directly but runtime.GOARCH works for arch.
	arch = runtime.GOARCH
	// Use `uname -r` for kernel release
	out, err := runCmd("uname", "-r")
	if err != nil {
		logCrit("Unable to identify OS version.")
		os.Exit(1)
	}
	release = strings.TrimSpace(out)
	return
}

func computeReleaseVer() string {
	// If EUS and no 'eus_missing', read /etc/yum/vars/releasever
	if eus && !issues["eus_missing"] {
		b, err := os.ReadFile("/etc/yum/vars/releasever")
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	rel, _ := unameReleaseAndArch()
	// Extract elN from release (e.g., 4.18.0-477.13.1.el8.x86_64)
	re := regexp.MustCompile(`^.*el([0-9][0-9]*).*`)
	m := re.FindStringSubmatch(rel)
	if len(m) >= 2 {
		if m[1] == "7" {
			return "7Server"
		}
		return m[1]
	}
	return "" // fallback (unlikely)
}

func substituteRepoURL(urlTmpl string) string {
	// Python used Template with ${releasever}, ${basearch}, ${arch}
	release := computeReleaseVer()
	_, arch := unameReleaseAndArch()
	replacer := strings.NewReplacer(
		"${releasever}", release,
		"$releasever", release,
		"${basearch}", arch,
		"$basearch", arch,
		"${arch}", arch,
		"$arch", arch,
	)
	return replacer.Replace(urlTmpl)
}

/* ===========================
   Proxy handling
   =========================== */

type proxyInfo struct {
	URL *url.URL
}

func parseProxyFromSection(cfg *ini.File, section string) *proxyInfo {
	sec := cfg.Section(section)
	if sec == nil {
		return nil
	}
	raw := strings.TrimSpace(sec.Key("proxy").String())
	if raw == "" {
		return nil
	}

	pu := strings.TrimSpace(sec.Key("proxy_user").String())
	pp := strings.TrimSpace(sec.Key("proxy_password").String())

	// If the proxy already contains creds, warn if also set separately
	if strings.Contains(raw, "@") && pu != "" {
		logWarn("proxy definition in section [%s] already has a username and proxy_user is also defined; there might be conflicts.", section)
	}
	if strings.Contains(raw, ":") && strings.Contains(raw, "@") && pp != "" {
		logWarn("proxy definition in section [%s] already has a password and proxy_password is also defined; there might be conflicts.", section)
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		logCrit("Invalid proxy configuration in section [%s]. Please fix your settings.", section)
		os.Exit(1)
	}

	// Force https scheme as Python does (sets scheme to https)
	parsed.Scheme = "https"

	// If no creds in URL and proxy_user is set, inject creds
	if pu != "" && parsed.User == nil {
		if pp != "" {
			parsed.User = url.UserPassword(pu, pp)
		} else {
			parsed.User = url.User(pu)
		}
	}
	logCrit("Found proxy information in config files; make sure connectivity works through the proxy.")
	return &proxyInfo{URL: parsed}
}

func loadSystemProxyFromYumConf() *url.URL {
	// read /etc/yum.conf (RHEL8+ often symlinked to /etc/dnf/dnf.conf)
	cfg, err := ini.Load("/etc/yum.conf")
	if err != nil {
		logWarn("Problems reading /etc/yum.conf (on RHEL8+ it's a symlink to /etc/dnf/dnf.conf). Error: %v", err)
		return nil
	}
	pi := parseProxyFromSection(cfg, "main")
	if pi != nil {
		return pi.URL
	}
	return nil
}

/* ===========================
   HTTP with optional client cert and proxy
   =========================== */

func httpClientForRepo(cfg *ini.File, repoSection string, sectionProxy *url.URL) (*http.Client, error) {
	sec := cfg.Section(repoSection)
	var certPath, keyPath string
	if sec != nil {
		certPath = strings.TrimSpace(sec.Key("sslclientcert").String())
		keyPath = strings.TrimSpace(sec.Key("sslclientkey").String())
	}
	var tlsConfig *tls.Config
	if certPath != "" && keyPath != "" {
		// Load client cert pair
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert/key for [%s]: %w", repoSection, err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	} else {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Proxy order: repo section proxy -> system proxy -> env (none here)
	if sectionProxy != nil {
		transport.Proxy = http.ProxyURL(sectionProxy)
	} else if systemProxyURL != nil {
		transport.Proxy = http.ProxyURL(systemProxyURL)
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	return client, nil
}

func connectToHost(baseURL string, reposCfg *ini.File, repoSection string) bool {
	// Substitute vars and append /repodata/repomd.xml
	newURL := substituteRepoURL(baseURL)
	target := strings.TrimRight(newURL, "/") + "/repodata/repomd.xml"

	logDebug("baseurl for repo %s is %s", repoSection, target)

	// repo-level proxy (may be absent)
	var sectionProxy *url.URL
	if reposCfg != nil {
		if pi := parseProxyFromSection(reposCfg, repoSection); pi != nil {
			sectionProxy = pi.URL
		}
	}
	client, err := httpClientForRepo(reposCfg, repoSection, sectionProxy)
	if err != nil {
		// replicate Python behavior: try to hint at CA or proxy problems
		if !validateCACerts() {
			logWarn("PROBLEM: MITM proxy misconfiguration or CA issues for %s", target)
		}
		badHostsForURL(target)
		return false
	}

	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("content-type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// attempt to categorize
		if errors.Is(err, http.ErrHandlerTimeout) {
			logWarn("TIMEOUT: Unable to reach RHUI URI %s", target)
		} else {
			logWarn("PROBLEM: Unable to establish connectivity to RHUI server %s", target)
			logErr("%v", err)
		}
		badHostsForURL(target)
		return false
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		logDebug("The RC for this %s link is %d", target, resp.StatusCode)
		return true
	case 404:
		logErr("Unable to find the contents for repo %s; ensure correct version lock if using EUS repositories", repoSection)
		logErr("See: https://access.redhat.com/support/policy/updates/errata#RHEL8_and_9_Life_Cycle")
		badHostsForURL(target)
		return false
	default:
		logWarn("The RC for this %s link is %d", target, resp.StatusCode)
		badHostsForURL(target)
		return false
	}
}

func badHostsForURL(raw string) {
	h, err := getHostFromURL(raw)
	if err == nil {
		badHosts[h] = true
	}
}

/* ===========================
   RPM info
   =========================== */

func rpmNames() []string {
	out, err := runCmd("bash", "-lc", "rpm -qa 'rhui-*'")
	if err != nil {
		logCrit("Could not find a specific RHUI package installed. Install the appropriate one.")
		logCrit("See: https://learn.microsoft.com/troubleshoot/azure/virtual-machines/troubleshoot-linux-rhui-certificate-issues#cause-3-rhui-package-is-missing")
		os.Exit(1)
	}
	var rpms []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		name := strings.TrimSpace(sc.Text())
		if name != "" {
			logDebug("Server has this RHUI pkg: %s", name)
			rpms = append(rpms, name)
		}
	}
	if len(rpms) == 0 {
		logCrit("Could not find a specific RHUI package installed. Install the appropriate one.")
		logCrit("See: https://learn.microsoft.com/troubleshoot/azure/virtual-machines/troubleshoot-linux-rhui-certificate-issues#cause-3-rhui-package-is-missing")
		os.Exit(1)
	}
	return rpms
}

type pkgInfo struct {
	ClientCert string
	ClientKey  string
	RepoFile   string
}

func getPkgInfo(pkg string) (*pkgInfo, error) {
	out, err := runCmd("rpm", "-q", "--list", pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to query RPM %s: %w", pkg, err)
	}
	lines := strings.Split(out, "\n")
	info := &pkgInfo{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		logDebug("checking path in %s: %s", pkg, line)
		if info.ClientCert == "" && pClientCert.MatchString(line) {
			info.ClientCert = line
		}
		if info.ClientKey == "" && pClientKey.MatchString(line) {
			info.ClientKey = line
		}
		if info.RepoFile == "" && pRepoFile.MatchString(line) {
			info.RepoFile = line
		}
		if info.ClientCert != "" && info.ClientKey != "" && info.RepoFile != "" {
			break
		}
	}
	return info, nil
}

func verifyPkgInfo(pkg string, pi *pkgInfo) bool {
	errors := 0
	if pi.ClientCert == "" || !fileExists(pi.ClientCert) {
		logCrit("clientcert file not found in server or RPM metadata; %s rpm needs to be reinstalled.", pkg)
		errors++
	}
	if pi.ClientKey == "" || !fileExists(pi.ClientKey) {
		logCrit("clientkey file not found in server or RPM metadata; %s rpm needs to be reinstalled.", pkg)
		errors++
	}
	if pi.RepoFile == "" || !fileExists(pi.RepoFile) {
		logCrit("repofile not found in server or RPM metadata; %s rpm needs to be reinstalled.", pkg)
		errors++
	}
	if errors > 0 {
		dataLink := "https://learn.microsoft.com/troubleshoot/azure/virtual-machines/troubleshoot-linux-rhui-certificate-issues#cause-2-rhui-certificate-is-missing"
		logCrit("follow %s for information to install the RHUI package", dataLink)
		os.Exit(1)
	}
	return true
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

/* ===========================
   Crypto policy & cert expiry
   =========================== */

func defaultPolicy() bool {
	rel, _ := unameReleaseAndArch()
	re := regexp.MustCompile(`^.*el([0-9][0-9]*).*`)
	m := re.FindStringSubmatch(rel)
	if len(m) >= 2 && m[1] == "7" {
		return true
	}
	out, err := runCmd("/bin/update-crypto-policies", "--show")
	if err != nil {
		return true // Python returns True if it cannot test
	}
	if strings.TrimSpace(out) != "DEFAULT" {
		return false
	}
	return true
}

func expirationTime(certPath string) bool {
	// openssl x509 -in cert -checkend 0
	err := checkCmd("bash", "-lc", fmt.Sprintf("openssl x509 -in %s -checkend 0 > /dev/null 2>&1", shellEscape(certPath)))
	if err != nil {
		logCrit("Client RHUI Certificate has expired, please update the RHUI rpm.")
		logCrit("Refer to: https://learn.microsoft.com/troubleshoot/azure/virtual-machines/troubleshoot-linux-rhui-certificate-issues#cause-1-rhui-client-certificate-is-expired")
		return false
	}
	if !defaultPolicy() {
		logCrit("Client crypto policies not set to DEFAULT.")
		logCrit("Refer to: https://learn.microsoft.com/troubleshoot/azure/virtual-machines/linux/troubleshoot-linux-rhui-certificate-issues?tabs=rhel7-eus%%2Crhel7-noneus%%2Crhel7-rhel-sap-apps%%2Crhel8-rhel-sap-apps%%2Crhel9-rhel-sap-apps#cause-5-verification-error-in-rhel-version-8-or-9-ca-certificate-key-too-weak")
		return false
	}
	return true
}

func shellEscape(s string) string {
	if s == "" {
		return ""
	}
	// minimal shell escaping for file path
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

/* ===========================
   Repo file parsing & checks
   =========================== */

func checkRepoFile(path string) (*ini.File, error) {
	logDebug("RHUI repo file is %s", path)
	cfg, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("%s does not follow standard REPO config format; reinstall RHUI rpm: %w", path, err)
	}
	return cfg, nil
}

func checkRepos(reposcfg *ini.File) ([]string, map[string]bool) {
	logDebug("Entering check_repos()")
	rhuirepo := regexp.MustCompile(`^(rhui-)?microsoft.*`)
	eusrepo := regexp.MustCompile(`.*-(eus|e4s)-.*`)

	microsoftRepo := ""
	enabled := []string{}
	localIssues := map[string]bool{}

	for _, sec := range reposcfg.Sections() {
		name := sec.Name()
		if name == "DEFAULT" {
			continue
		}
		enabledVal := 1
		if sec.HasKey("enabled") {
			enabledStr := strings.TrimSpace(sec.Key("enabled").String())
			if enabledStr == "0" {
				enabledVal = 0
			}
		}
		if rhuirepo.MatchString(name) {
			microsoftRepo = name
			if enabledVal == 1 {
				logInfo("Using Microsoft RHUI repository %s", name)
			} else {
				logCrit("Microsoft RHUI repository not enabled; enable it:")
				logCrit("yum-config-manager --enable %s", name)
				enabled = append(enabled, name)
				localIssues["rhuirepo_not_enabled"] = true
			}
		}
		if enabledVal == 1 {
			enabled = append(enabled, name)
		} else {
			continue
		}
		if eusrepo.MatchString(name) {
			eus = true
		}
	}

	if microsoftRepo == "" {
		reinstallLink := "https://learn.microsoft.com/troubleshoot/azure/virtual-machines/linux/troubleshoot-linux-rhui-certificate-issues?source=recommendations&tabs=rhel7-eus%2Crhel7-noneus%2Crhel7-rhel-sap-apps%2Crhel8-rhel-sap-apps%2Crhel9-rhel-sap-apps#solution-2-reinstall-the-eus-non-eus-or-sap-rhui-package"
		logCrit("Microsoft RHUI repository not found, reinstall the RHUI package following %s", reinstallLink)
		localIssues["rhuirepo_missing"] = true
	}

	if eus {
		if !fileExists("/etc/yum/vars/releasever") && !fileExists("/etc/dnf/vars/releasever") {
			logCrit("Server is using EUS repositories but /etc/yum/vars/releasever file not found, please correct and test again.")
			logCrit("Refer to: https://learn.microsoft.com/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel7#rhel-eus-and-version-locking-rhel-vms")
			localIssues["eus_missing"] = true
		}
	} else {
		if fileExists("/etc/yum/vars/releasever") || fileExists("/etc/dnf/vars/releasever") {
			logCrit("Server is using non-EUS repos and /etc/yum/vars/releasever file found; correct and try again.")
			logCrit("Refer to: https://learn.microsoft.com/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel7#rhel-eus-and-version-locking-rhel-vms")
			localIssues["extra_eus"] = true
		}
	}

	return enabled, localIssues
}

func ipAddressCheck(host string) bool {
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		logWarn("Unable to resolve IP address for host %s.", host)
		logWarn("Please make sure your server can resolve %s to one of the IP addresses listed in:", host)
		logWarn("https://learn.microsoft.com/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel7#the-ips-for-the-rhui-content-delivery-servers")
		return false
	}
	ip := addrs[0]
	in := func(list []string, val string) bool {
		for _, x := range list {
			if x == val {
				return true
			}
		}
		return false
	}
	if in(rhui4, ip) {
		logDebug("RHUI host %s points to RHUI4 infrastructure.", host)
		return true
	} else if in(append(rhui3, rhuius...), ip) {
		reinstallLink := "https://learn.microsoft.com/troubleshoot/azure/virtual-machines/linux/troubleshoot-linux-rhui-certificate-issues?tabs=rhel7-eus%2Crhel7-noneus%2Crhel7-rhel-sap-apps%2Crhel8-rhel-sap-apps%2Crhel9-rhel-sap-apps#solution-2-reinstall-the-eus-non-eus-or-sap-rhui-package"
		logErr("RHUI server %s points to decommissioned infrastructure; reinstall the RHUI package", host)
		logErr("More info: %s", reinstallLink)
		badHosts[host] = true
		return false
	} else {
		logCrit("RHUI server %s points to an invalid destination. Validate /etc/hosts for invalid static RHUI IPs or reinstall the RHUI package.", host)
		logWarn("Please ensure your server resolves %s to a valid IP listed here:", host)
		logWarn("https://learn.microsoft.com/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel7#the-ips-for-the-rhui-content-delivery-servers")
		return false
	}
}

func connectToRepos(reposcfg *ini.File, repoNames []string) {
	logDebug("Entering connect_to_repos()")
	rhuirepo := regexp.MustCompile(`^(rhui-)?microsoft.*`)
	eusrepo := regexp.MustCompile(`.*-(eus|e4s)-.*`)

	for _, name := range repoNames {
		if strings.EqualFold(name, "DEFAULT") {
			continue
		}
		// skip if issues as in Python
		if (issues["invalid_cert"] && !rhuirepo.MatchString(name)) ||
			(issues["eus_missing"] && eusrepo.MatchString(name)) ||
			(issues["extra_eus"] && !eusrepo.MatchString(name)) {
			continue
		}

		sec := reposcfg.Section(name)
		if sec == nil {
			continue
		}
		baseurlRaw := strings.TrimSpace(sec.Key("baseurl").String())
		if baseurlRaw == "" {
			reinstallLink := "https://learn.microsoft.com/troubleshoot/azure/virtual-machines/linux/troubleshoot-linux-rhui-certificate-issues?source=recommendations&tabs=rhel7-eus%2Crhel7-noneus%2Crhel7-rhel-sap-apps%2Crhel8-rhel-sap-apps%2Crhel9-rhel-sap-apps#solution-2-reinstall-the-eus-non-eus-or-sap-rhui-package"
			logCrit("The baseurl is missing for repo %s", name)
			logCrit("Reinstall the Microsoft RHUI repo: %s", reinstallLink)
			issues["invalid_repoconfig"] = true
			continue
		}
		// baseurl may contain multiple lines
		var urlsList []string
		for _, ln := range strings.Split(baseurlRaw, "\n") {
			ln = strings.TrimSpace(ln)
			if ln != "" {
				urlsList = append(urlsList, ln)
			}
		}

		successes := 0
		logInfo("Testing connectivity to repository: %s", name)
		for _, u := range urlsList {
			host, err := getHostFromURL(substituteRepoURL(u))
			if err != nil {
				logWarn("Invalid baseurl %s for repo %s: %v", u, name, err)
				continue
			}
			if !ipAddressCheck(host) {
				badHosts[host] = true
				continue
			}
			if badHosts[host] {
				continue
			}
			if connectToHost(u, reposcfg, name) {
				successes++
			}
		}

		if successes == 0 {
			errorLink := "https://learn.microsoft.com/azure/virtual-machines/workloads/redhat/redhat-rhui?tabs=rhel9#the-ips-for-the-rhui-content-delivery-servers"
			logCrit("PROBLEM: Unable to download repository metadata from any configured RHUI server(s).")
			logCrit("         Ensure DNS resolves to a valid IP, allow communication to IPs listed here: %s", errorLink)
			logCrit("         If using EUS, ensure a valid /etc/dnf/vars/releasever (or /etc/yum/vars/releasever).")
			issues["unable_to_connect"] = true
		}
	}
}

/* ===========================
   Main
   =========================== */

func main() {
	debug := flag.Bool("debug", false, "Use DEBUG level")
	d := flag.Bool("d", false, "Use DEBUG level (short)")
	flag.Parse()
	if *d {
		*debug = true
	}

	mustRoot()

	logFile, err := setupLogging(*debug)
	if err != nil {
		os.Exit(1)
	}
	defer logFile.Close()

	// Reduce noise (parity: Python lowered requests/urllib3 log level); N/A in Go

	// Validate we can import/use "requests" equivalent: in Go we just validate CA certs package presence if needed
	if !validateCACerts() {
		os.Exit(1)
	}

	// Load system proxy from yum/dnf config
	systemProxyURL = loadSystemProxyFromYumConf()

	// Iterate RHUI packages
	rpms := rpmNames()
	var lastPkgData *pkgInfo

	for _, pkg := range rpms {
		data, err := getPkgInfo(pkg)
		if err != nil {
			logCrit("Failed to grab RHUI RPM details, rebuild RPM database. Err: %v", err)
			os.Exit(1)
		}
		if verifyPkgInfo(pkg, data) {
			// cert expiration
			if !expirationTime(data.ClientCert) {
				issues["invalid_cert"] = true
			}
			// read repo file
			reposCfg, err := checkRepoFile(data.RepoFile)
			if err != nil {
				logCrit("%v", err)
				os.Exit(1)
			}
			enabledRepos, newIssues := checkRepos(reposCfg)
			// merge issues
			for k, v := range newIssues {
				issues[k] = v
			}
			connectToRepos(reposCfg, enabledRepos)
			lastPkgData = data
		}
	}

	if len(issues) > 0 {
		os.Exit(1)
	} else {
		logInfo("All communication tests to the RHUI infrastructure have passed; if problems persist, remove third-party repositories and test again.")
		if lastPkgData != nil {
			logInfo("The RHUI repository configuration file is %s; move any other configuration file to a temporary location and test again.", lastPkgData.RepoFile)
		}
		os.Exit(0)
	}
}

/* ===========================
   Small helpers
   =========================== */

func absPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	wd, _ := os.Getwd()
	return filepath.Join(wd, path)
}
