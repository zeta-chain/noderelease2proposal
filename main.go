package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v61/github"
	"github.com/samber/lo"
)

const authority = "zeta10d07y265gmmuvt4z0w9aw880jnsr700jvxasvr"
const softwareUpgradeType = "/cosmos.upgrade.v1beta1.MsgSoftwareUpgrade"

type upgradeConfig struct {
	Binaries map[string]string `json:"binaries"`
}

type Proposal struct {
	Messages []Messages `json:"messages"`
	Metadata string     `json:"metadata"`
	Deposit  string     `json:"deposit"`
	Title    string     `json:"title"`
	Summary  string     `json:"summary"`
}
type Plan struct {
	Height              string    `json:"height"`
	Info                string    `json:"info"`
	Name                string    `json:"name"`
	Time                time.Time `json:"time"`
	UpgradedClientState any       `json:"upgraded_client_state"`
}
type Messages struct {
	Type      string `json:"@type"`
	Plan      Plan   `json:"plan"`
	Authority string `json:"authority"`
}

func downloadChecksums(url string) (map[string]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	checksums := make(map[string]string)

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			checksums[parts[1]] = parts[0]
		}
	}

	return checksums, nil
}

func release2Proposal(rawReleaseUrl string) (*Proposal, error) {
	client := github.NewClient(nil)
	// in case of private release
	if token, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
		client = client.WithAuthToken(token)
	}

	releaseUrl, err := url.Parse(rawReleaseUrl)
	if err != nil {
		return nil, fmt.Errorf("parse release url: %w", err)
	}
	// example: /zeta-chain/node/releases/tag/v14.0.1
	releaseUrlParts := strings.Split(releaseUrl.Path, "/")

	owner := releaseUrlParts[1]
	repo := releaseUrlParts[2]
	tag := releaseUrlParts[5]

	ctx := context.Background()

	release, _, err := client.Repositories.GetReleaseByTag(ctx, owner, repo, tag)
	if err != nil {
		return nil, fmt.Errorf("get release %s: %w", tag, err)
	}

	checksumsAsset, ok := lo.Find(release.Assets, func(a *github.ReleaseAsset) bool {
		return *a.Name == "checksums.txt"
	})

	if !ok {
		return nil, fmt.Errorf("unable to find checksusms asset")
	}

	checksums, err := downloadChecksums(*checksumsAsset.BrowserDownloadURL)
	if err != nil {
		return nil, fmt.Errorf("download checksums %s: %w", *checksumsAsset.BrowserDownloadURL, err)
	}

	uc := &upgradeConfig{
		Binaries: make(map[string]string),
	}

	for _, asset := range release.Assets {
		assetName := *asset.Name
		checksum := checksums[assetName]
		downloadUrl := fmt.Sprintf("%s?checksum=sha256:%s", *asset.BrowserDownloadURL, checksum)

		if strings.Contains(assetName, "windows") {
			continue
		}

		// cosmovisor uses / to separate os and arch not -
		// https://github.com/cosmos/cosmos-sdk/blob/c4308d2da05bd3943ab019e9903d6e36a81126fd/tools/cosmovisor/upgrade.go#L83
		assetName = strings.ReplaceAll(assetName, "-", "/")

		if plainName, ok := strings.CutPrefix(assetName, "zetacored/"); ok {
			uc.Binaries[plainName] = downloadUrl
		} else if plainName, ok := strings.CutPrefix(assetName, "zetaclientd/"); ok {
			name := fmt.Sprintf("zetaclientd-%s", plainName)
			uc.Binaries[name] = downloadUrl
		}
	}

	ucBytes, err := json.Marshal(uc)
	if err != nil {
		return nil, fmt.Errorf("marshal upgrade config: %w", err)
	}

	title := fmt.Sprintf("%s Upgrade", tag)

	return &Proposal{
		Messages: []Messages{
			{
				Type: softwareUpgradeType,
				Plan: Plan{
					Height: "1",
					Info:   string(ucBytes),
					Name:   tag,
				},
				Authority: authority,
			},
		},
		Metadata: rawReleaseUrl,
		Deposit:  "100000000azeta",
		Title:    title,
		Summary:  title,
	}, nil
}

func main() {
	proposal, err := release2Proposal(os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "deposit and block height are for example only and need to be configured correctly\n")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(proposal)
}
