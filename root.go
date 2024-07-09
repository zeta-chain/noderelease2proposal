package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v61/github"
	"github.com/samber/lo"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"

	cometbft_http_client "github.com/cometbft/cometbft/rpc/client/http"
)

func init() {
	rootCmd.Flags().String("rpc-url", "", "tendermint/cometbft rpc url to estimate block height")
	rootCmd.Flags().String("upgrade-time", "", "RFC3339 timestamp (with timezone) for the block height estimator")
	rootCmd.Flags().Bool("skip-attestation", false, "skip attestation verification")
	rootCmd.Flags().Bool("attest-org-only", false, "skip exact repo attestation verification")
}

var rootCmd = &cobra.Command{
	Use:          "noderelease2proposal <release url>",
	Short:        "convert a node release from github to a proposal, print proposal to stdout",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		rpcUrl, _ := cmd.Flags().GetString("rpc-url")

		upgradeHeight := int64(0)
		if rpcUrl != "" {
			upgradeTimeStr, _ := cmd.Flags().GetString("upgrade-time")
			upgradeTime, err := time.Parse(time.RFC3339, upgradeTimeStr)
			if err != nil {
				return fmt.Errorf("parsing upgrade-time (%s): %w", upgradeTimeStr, err)
			}
			upgradeHeight, err = estimateUpgradeHeight(rpcUrl, upgradeTime)
			if err != nil {
				return fmt.Errorf("estimating upgrade height: %w", err)
			}
		}
		skipAttestation, _ := cmd.Flags().GetBool("skip-attestation")
		attestOrgOnly, _ := cmd.Flags().GetBool("attest-org-only")
		proposal, err := release2Proposal(args[0], upgradeHeight, skipAttestation, attestOrgOnly)
		if err != nil {
			return err
		}
		if upgradeHeight == 0 {
			log.Print("WARN: upgrade height is for example only and need to be configured correctly")
		}
		log.Print("WARN: deposit is for example only and need to be configured correctly")
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(proposal)
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func estimateUpgradeHeight(rpcUrl string, targetTime time.Time) (int64, error) {
	// websocket url doesn't matter
	client, err := cometbft_http_client.New(rpcUrl, "/websocket")
	if err != nil {
		return 0, fmt.Errorf("new client: %w", err)
	}
	ctx := context.Background()

	// first estimate block time
	latestBlockResult, err := client.Block(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("getting latest block: %w", err)
	}
	latestBlockHeight := latestBlockResult.Block.Height
	log.Printf("got latest block height: %d", latestBlockHeight)

	// look across N blocks
	nBlocks := 10
	lastBlockResult := latestBlockResult
	var totalDurationDiff time.Duration
	for i := latestBlockHeight - 1; i >= latestBlockHeight-int64(nBlocks); i-- {
		iBlockResult, err := client.Block(ctx, &i)
		if err != nil {
			return 0, fmt.Errorf("getting block %d: %w", i, err)
		}
		totalDurationDiff += lastBlockResult.Block.Time.Sub(iBlockResult.Block.Time)
		lastBlockResult = iBlockResult
	}
	averageBlockDuration := totalDurationDiff / time.Duration(nBlocks)
	remainingDuration := time.Until(targetTime)
	neededBlocks := int64(remainingDuration) / int64(averageBlockDuration)
	log.Printf("calculated we to wait %d more blocks. %s per block. %s until target time.\n", neededBlocks, averageBlockDuration.String(), remainingDuration.String())
	return latestBlockHeight + neededBlocks, nil
}

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

const githubIssuer = "https://token.actions.githubusercontent.com"

func getTrustedRoot() (*root.TrustedRoot, error) {
	opts := tuf.DefaultOptions()
	fetcher := fetcher.DefaultFetcher{}
	opts.Fetcher = &fetcher

	client, err := tuf.New(opts)
	if err != nil {
		return nil, err
	}
	trustedRootJSON, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return nil, err
	}
	var trustedRoot *root.TrustedRoot
	trustedRoot, err = root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, err
	}
	return trustedRoot, nil
}

type validateAttestationParams struct {
	Owner         string
	Repo          string
	Release       *github.RepositoryRelease
	Checksums     map[string]string
	AttestOrgOnly bool
}

// validateAttestation validates the attestation produced by https://github.com/actions/attest
// mostly based on https://github.com/sigstore/sigstore-go/blob/main/cmd/sigstore-go/main.go
// but also some from the github cli https://github.com/cli/cli/blob/0df5596512ad44dec74ab3dc07a4e6ea3a7c78fc/pkg/cmd/attestation/verification/sigstore.go#L217
func validateAttestation(p validateAttestationParams) error {
	if len(p.Checksums) == 0 {
		return fmt.Errorf("no checksums?")
	}

	releaseCommit := *p.Release.TargetCommitish

	var flatChecksums []string
	var artifacts []verify.ArtifactPolicyOption
	for _, checksum := range p.Checksums {
		artifactDigestBytes, err := hex.DecodeString(checksum)
		if err != nil {
			return err
		}
		artifactPolicy := verify.WithArtifactDigest("sha256", artifactDigestBytes)
		flatChecksums = append(flatChecksums, checksum)
		artifacts = append(artifacts, artifactPolicy)
	}

	attestationAsset, ok := lo.Find(p.Release.Assets, func(a *github.ReleaseAsset) bool {
		return *a.Name == "attestation.jsonl"
	})
	if !ok {
		return fmt.Errorf("unable to find attestation asset")
	}

	resp, err := http.Get(*attestationAsset.BrowserDownloadURL)
	if err != nil {
		return fmt.Errorf("download attestation: %w", err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)

	var attestationBundles []bundle.ProtobufBundle

	for scanner.Scan() {
		pbBundle := bundle.ProtobufBundle{}
		err = pbBundle.UnmarshalJSON(scanner.Bytes())
		if err != nil {
			return fmt.Errorf("unmarshal attestation: %w", err)
		}

		attestationBundles = append(attestationBundles, pbBundle)
	}

	repoExpr := p.Repo
	if p.AttestOrgOnly {
		repoExpr = ".+"
	}
	// validate that the attestation is for the correct repository but don't check an exact workflow name
	sanRegex := fmt.Sprintf("^https://github.com/%s/%s/.github/workflows/.*", p.Owner, repoExpr)
	certID, err := verify.NewShortCertificateIdentity(githubIssuer, "", "", sanRegex)
	if err != nil {
		return err
	}

	verifierConfig := []verify.VerifierOption{
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}
	identityPolicies := []verify.PolicyOption{
		verify.WithCertificateIdentity(certID),
	}

	trustedMaterial, err := getTrustedRoot()
	if err != nil {
		return fmt.Errorf("get trusted roots: %w", err)
	}

	sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return err
	}

	repoMismatch := false
	expectedSourceRepositoryURI := fmt.Sprintf("https://github.com/%s/%s", p.Owner, p.Repo)
	gotSourceRepositoryURI := ""

	// for each artifact, verify that there is at least one matching attestation
	for i, artifact := range artifacts {
		ok := false
		for _, pbBundle := range attestationBundles {
			res, err := sev.Verify(&pbBundle, verify.NewPolicy(artifact, identityPolicies...))
			if err != nil {
				continue
			}
			sigCertCommit := res.Signature.Certificate.SourceRepositoryDigest
			if sigCertCommit != releaseCommit {
				return fmt.Errorf("attestation for checksum %s is for commit %s, not %s", flatChecksums[i], sigCertCommit, releaseCommit)
			}
			if res.Signature.Certificate.SourceRepositoryURI != expectedSourceRepositoryURI {
				gotSourceRepositoryURI = res.Signature.Certificate.SourceRepositoryURI
				repoMismatch = true
			}
			ok = true
			break
		}
		if !ok {
			return fmt.Errorf("no attestation for checksum %s", flatChecksums[i])
		}
	}

	if repoMismatch {
		log.Printf("WARN: attestation is for a different repository: %s", gotSourceRepositoryURI)
	}

	return nil
}

func release2Proposal(rawReleaseUrl string, upgradeHeight int64, skipAttestation bool, attestOrgOnly bool) (*Proposal, error) {
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

	err = validateAttestation(validateAttestationParams{
		Owner:         owner,
		Repo:          repo,
		Release:       release,
		Checksums:     checksums,
		AttestOrgOnly: attestOrgOnly,
	})
	if err != nil {
		if skipAttestation {
			log.Printf("WARN: attestation verification failed: %v", err)
		} else {
			return nil, fmt.Errorf("validate attestation: %w", err)
		}
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
					Height: strconv.FormatInt(upgradeHeight, 10),
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
