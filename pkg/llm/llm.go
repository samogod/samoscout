package llm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"samoscout/pkg/active"
)

type LLM struct {
	model     *Model
	validator *Validator
	config    *Config
	outputDir string
}

func New(cfg *Config) (*LLM, error) {
	if err := active.EnsurePureDns(cfg.Verbose); err != nil {
		return nil, fmt.Errorf("puredns setup failed: %w", err)
	}

	downloader := NewDownloader()
	modelPath, tokenizerPath, err := downloader.DownloadModel(false)
	if err != nil {
		return nil, fmt.Errorf("failed to download model: %w", err)
	}

	model, err := LoadModel(modelPath, tokenizerPath, cfg.Device)
	if err != nil {
		return nil, fmt.Errorf("failed to load model: %w", err)
	}

	return &LLM{
		model:     model,
		validator: NewValidator(),
		config:    cfg,
		outputDir: cfg.OutputDir,
	}, nil
}

func (l *LLM) Close() error {
	if l.model != nil {
		return l.model.Close()
	}
	return nil
}

func (l *LLM) Enumerate(
	ctx context.Context,
	inputDomains []string,
	apexDomain string,
) ([]string, error) {

	subdomains := []string{}
	for _, d := range inputDomains {
		sub, ok := l.validator.ExtractSubdomain(d, apexDomain)
		if ok && sub != "" {
			subdomains = append(subdomains, sub)
		}
	}

	if len(subdomains) == 0 {
		return nil, fmt.Errorf("no valid subdomains to seed")
	}

	blockedDomains := make(map[string]bool)
	for _, d := range inputDomains {
		blockedDomains[strings.ToLower(d)] = true
	}

	allPredictions := make(map[string]bool)
	currentDomains := inputDomains

	fmt.Printf("[LLM] Starting predictions with %d seed domains\n", len(currentDomains))
	if l.config.Verbose {
		fmt.Printf("[DBG] [LLM] Max recursion: %d, Predictions per iteration: %d\n",
			l.config.MaxRecursion, l.config.NumPredictions)
	}

	for i := 0; i < l.config.MaxRecursion; i++ {
		if !l.config.Verbose {
			fmt.Printf("[LLM] Iteration %d/%d ", i+1, l.config.MaxRecursion)
		} else {
			fmt.Printf("[DBG] [LLM] === Iteration %d/%d ===\n", i+1, l.config.MaxRecursion)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		predictions, err := l.runInference(
			ctx, currentDomains, apexDomain, blockedDomains,
		)
		if err != nil {
			return nil, err
		}

		if l.config.Verbose {
			fmt.Printf("[DBG] [LLM] Generated %d predictions\n", len(predictions))
		}

		if len(predictions) == 0 {
			if !l.config.Verbose {
				fmt.Println("- no new predictions")
			} else {
				fmt.Println("[DBG] [LLM] No new predictions, stopping")
			}
			break
		}

		resolved, err := l.resolvePredictions(predictions, apexDomain, i)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}

		if len(resolved) == 0 {
			if !l.config.Verbose {
				fmt.Println()
			} else {
				fmt.Println("[DBG] [LLM] No resolved domains, stopping")
			}
			break
		}

		for _, r := range resolved {
			allPredictions[r] = true
		}

		for _, p := range predictions {
			blockedDomains[strings.ToLower(p)] = true
		}
		currentDomains = append(currentDomains, resolved...)
	}

	result := []string{}
	for d := range allPredictions {
		result = append(result, d)
	}

	fmt.Printf("[LLM] Prediction complete: %d total new subdomains discovered\n", len(result))
	if l.config.Verbose {
		fmt.Printf("[DBG] [LLM] Across %d iterations\n", l.config.MaxRecursion)
	}

	return result, nil
}

func (l *LLM) resolvePredictions(predictions []string, domain string, iteration int) ([]string, error) {
	predictionFile := filepath.Join(
		l.outputDir,
		fmt.Sprintf("llm_predictions_iter_%d.txt", iteration),
	)

	if err := writePredictionsToFile(predictions, predictionFile); err != nil {
		return nil, err
	}

	resolved, err := active.ResolveDNS(
		predictions,
		l.outputDir,
		domain,
		l.config.Verbose,
	)
	if err != nil {
		return nil, fmt.Errorf("puredns resolution failed: %w", err)
	}

	return resolved, nil
}

func (l *LLM) runInference(
	ctx context.Context,
	domains []string,
	apex string,
	blocked map[string]bool,
) ([]string, error) {

	subs := []string{}
	for _, d := range domains {
		sub, ok := l.validator.ExtractSubdomain(d, apex)
		if ok && sub != "" {
			subs = append(subs, sub)
		}
	}

	if len(subs) == 0 {
		return nil, fmt.Errorf("no subdomains to encode")
	}

	blockedList := []string{}
	for d := range blocked {
		sub, ok := l.validator.ExtractSubdomain(d, apex)
		if ok && sub != "" {
			blockedList = append(blockedList, sub)
		}
	}

	if l.config.Verbose {
		fmt.Printf("[DBG] [LLM] Processing %d unique subdomains, %d blocked\n",
			len(subs), len(blockedList))
	}

	predictions, err := l.model.GenerateDomains(
		ctx,
		subs,
		apex,
		l.config.NumPredictions,
		l.config.MaxTokens,
		float64(l.config.Temperature),
		blockedList,
	)
	if err != nil {
		return nil, err
	}

	validPredictions := []string{}
	seen := make(map[string]bool)

	for _, fullDomain := range predictions {
		sub, ok := l.validator.ExtractSubdomain(fullDomain, apex)
		if ok && l.validator.IsValidSubdomain(sub) && !seen[fullDomain] {
			seen[fullDomain] = true
			validPredictions = append(validPredictions, fullDomain)
		}
	}

	return validPredictions, nil
}

func writePredictionsToFile(predictions []string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, p := range predictions {
		if _, err := fmt.Fprintln(file, p); err != nil {
			return err
		}
	}

	return nil
}
