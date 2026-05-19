package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/breakglass"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/config"
	"github.com/zafrem/bastion-vault/internal/kanon"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/server"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

var cfgFile string

func main() {
	root := &cobra.Command{
		Use:   "vault",
		Short: "Bastion Vault — privacy-preserving data anonymization service",
		Long:  "Bastion Vault implements PII detection, anonymization, k-anonymity validation,\nRBAC access control, and break-glass workflows for the Bastion RAG framework.",
	}

	root.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: ./configs/vault.yaml)")

	root.AddCommand(
		newServerCmd(),
		newAnonymizeCmd(),
		newDetectPIICmd(),
		newClassifyCmd(),
		newKAnonCheckCmd(),
		newAccessCmd(),
		newInteractiveCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadDeps(cfg *config.Config) (*kms.Manager, *audit.Logger, error) {
	local, err := kms.NewLocalProvider(cfg.KMS.Local.KeyDir, cfg.KMS.Local.MasterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("KMS init: %w", err)
	}
	mgr := kms.NewManager(local, cfg.KMS.DEKCacheTTL)

	// Derive a 32-byte signing key from the KMS master key for audit HMAC.
	// In production this would be a dedicated KMS-managed key.
	var signingKey []byte
	if cfg.Audit.SigningEnabled {
		sk, kerr := local.GenerateHMACKey(context.Background(), "audit-signing-key")
		if kerr != nil {
			return nil, nil, fmt.Errorf("audit signing key: %w", kerr)
		}
		signingKey = sk
	}

	aud, err := audit.NewLogger(cfg.Audit.OutputDir, cfg.Audit.SigningEnabled, signingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("audit logger init: %w", err)
	}
	return mgr, aud, nil
}

func newServerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "Start the REST API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			mgr, aud, err := loadDeps(cfg)
			if err != nil {
				return err
			}
			defer aud.Close()

			cls := classification.New()
			store := tokendb.NewMemoryStore()
			eng := anonymizer.NewEngine(mgr, cls, aud, store)
			ctrl := access.NewController(cfg.OPA.BundleServer)
			kv := kanon.New()
			bg := breakglass.NewManager(aud)

			httpSrv := server.New(eng, cls, ctrl, kv, bg, aud, cfg)

			httpAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.HTTPPort)
			grpcAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.GRPCPort)
			printBox("Bastion Vault Server", []string{
				"HTTP    : " + httpAddr,
				"gRPC    : " + grpcAddr,
				"KMS     : " + cfg.KMS.Provider,
				"OPA     : " + cfg.OPA.PolicyDir,
			})

			// Start HTTP server in background goroutine.
			netSrv := &http.Server{
				Addr:    httpAddr,
				Handler: httpSrv.Router(),
			}
			go func() {
				if err := netSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("HTTP server error: %v", err)
				}
			}()

			// Start gRPC server in background goroutine.
			grpcSrv := grpc.NewServer()
			grpcImpl := server.NewGRPCServer(eng, cls, kv, aud)
			grpcImpl.Register(grpcSrv)

			grpcLis, err := net.Listen("tcp", grpcAddr)
			if err != nil {
				return fmt.Errorf("gRPC listen: %w", err)
			}
			go func() {
				if err := grpcSrv.Serve(grpcLis); err != nil {
					log.Printf("gRPC server error: %v", err)
				}
			}()

			// Wait for termination signal.
			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
			<-quit

			// Graceful shutdown with 60-second timeout.
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			grpcSrv.GracefulStop()

			if err := netSrv.Shutdown(ctx); err != nil {
				log.Printf("HTTP shutdown error: %v", err)
			}

			log.Println("graceful shutdown complete")
			return nil
		},
	}
}

func newAnonymizeCmd() *cobra.Command {
	var (
		category    string
		requesterID string
		purpose     string
		inputFile   string
	)
	cmd := &cobra.Command{
		Use:   "anonymize",
		Short: "Anonymize records from a JSONL file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			mgr, aud, err := loadDeps(cfg)
			if err != nil {
				return err
			}
			defer aud.Close()

			records, err := readJSONL(inputFile)
			if err != nil {
				return err
			}

			eng := anonymizer.NewEngine(mgr, classification.New(), aud, tokendb.NewMemoryStore())
			req := &model.AnonymizeRequest{
				TenantID:    "cli",
				Category:    model.DataCategory(category),
				Records:     records,
				Purpose:     purpose,
				RequesterID: requesterID,
				AccessLevel: model.AccessAnonymized,
			}

			resp, err := eng.Anonymize(context.Background(), req)
			if err != nil {
				return err
			}

			printBox("Anonymization Result", []string{
				fmt.Sprintf("Records    : %d", resp.Metadata.RecordCount),
				fmt.Sprintf("Fields     : %d", resp.Metadata.FieldsAnonymized),
				fmt.Sprintf("Audit ID   : %s", resp.AuditID),
				fmt.Sprintf("Processed  : %s", resp.Metadata.ProcessedAt.Format(time.RFC3339)),
			})

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			for _, r := range resp.Records {
				enc.Encode(r) //nolint:errcheck
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&category, "category", "t", "DC-01", "data category (DC-01, DC-02, DC-03)")
	cmd.Flags().StringVarP(&requesterID, "requester", "r", "cli-user", "requester ID")
	cmd.Flags().StringVarP(&purpose, "purpose", "p", "testing", "access purpose")
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "JSONL input file (required)")
	cmd.MarkFlagRequired("input") //nolint:errcheck
	return cmd
}

func newDetectPIICmd() *cobra.Command {
	var inputFile string
	cmd := &cobra.Command{
		Use:   "detect-pii",
		Short: "Detect PII fields in a JSONL file",
		RunE: func(cmd *cobra.Command, args []string) error {
			records, err := readJSONL(inputFile)
			if err != nil {
				return err
			}
			cls := classification.New()
			for i, rec := range records {
				detections := cls.DetectPII(rec)
				printBox(fmt.Sprintf("Record %d PII Detections", i+1), func() []string {
					if len(detections) == 0 {
						return []string{"No PII detected"}
					}
					lines := make([]string, 0, len(detections))
					for _, d := range detections {
						lines = append(lines, fmt.Sprintf("%-20s %-30s L%d  %.0f%%",
							d.Field, d.PIIType, d.Sensitivity, d.Confidence*100))
					}
					return lines
				}())
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "JSONL input file (required)")
	cmd.MarkFlagRequired("input") //nolint:errcheck
	return cmd
}

func newClassifyCmd() *cobra.Command {
	var inputFile string
	cmd := &cobra.Command{
		Use:   "classify",
		Short: "Classify a JSONL dataset into a data category",
		RunE: func(cmd *cobra.Command, args []string) error {
			records, err := readJSONL(inputFile)
			if err != nil {
				return err
			}
			result := classification.New().Classify(records)
			printBox("Classification Result", []string{
				fmt.Sprintf("Category       : %s", result.Category),
				fmt.Sprintf("K-Threshold    : %d", result.KThreshold),
				fmt.Sprintf("PII Detections : %d", len(result.Detections)),
				"Recommendation : " + result.Recommendation,
			})
			return nil
		},
	}
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "JSONL input file (required)")
	cmd.MarkFlagRequired("input") //nolint:errcheck
	return cmd
}

func newKAnonCheckCmd() *cobra.Command {
	var (
		inputFile  string
		categoryS  string
		requiredK  int
		generalize bool
	)
	cmd := &cobra.Command{
		Use:   "k-anon-check",
		Short: "Validate k-anonymity of a JSONL dataset",
		RunE: func(cmd *cobra.Command, args []string) error {
			records, err := readJSONL(inputFile)
			if err != nil {
				return err
			}
			kv := kanon.New()
			cat := model.DataCategory(categoryS)

			if generalize {
				report, genRecords, err := kv.ValidateAndGeneralize(context.Background(), records, cat, requiredK)
				if err != nil {
					return err
				}
				printKAnonReport(report)
				if len(report.GeneralizationSteps) > 0 {
					fmt.Printf("\nGeneralized %d records\n", len(genRecords))
				}
				return nil
			}

			report, err := kv.Validate(context.Background(), records, cat, requiredK)
			if err != nil {
				return err
			}
			printKAnonReport(report)
			return nil
		},
	}
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "JSONL input file (required)")
	cmd.Flags().StringVarP(&categoryS, "category", "t", "DC-01", "data category")
	cmd.Flags().IntVarP(&requiredK, "k", "k", 5, "required K value")
	cmd.Flags().BoolVarP(&generalize, "generalize", "g", false, "auto-generalize until K-anonymous")
	cmd.MarkFlagRequired("input") //nolint:errcheck
	return cmd
}

func newAccessCmd() *cobra.Command {
	var (
		department string
		role       string
		categoryS  string
	)
	cmd := &cobra.Command{
		Use:   "access",
		Short: "Check access level for a role against a data category",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctrl := access.NewController("")
			user := &model.User{
				ID:         "cli-user",
				Department: department,
				Role:       role,
			}
			decision, err := ctrl.Decide(context.Background(), user, model.DataCategory(categoryS))
			if err != nil {
				return err
			}
			status := "DENIED"
			if decision.Allowed {
				status = "ALLOWED"
			}
			printBox("Access Decision", []string{
				fmt.Sprintf("Status       : %s", status),
				fmt.Sprintf("Access Level : %s", decision.AccessLevel),
				fmt.Sprintf("Reason       : %s", decision.Reason),
				fmt.Sprintf("Department   : %s", department),
				fmt.Sprintf("Role         : %s", role),
				fmt.Sprintf("Category     : %s", categoryS),
			})
			return nil
		},
	}
	cmd.Flags().StringVarP(&department, "department", "d", "marketing", "department name")
	cmd.Flags().StringVarP(&role, "role", "r", "analyst", "role name")
	cmd.Flags().StringVarP(&categoryS, "category", "t", "DC-01", "data category")
	return cmd
}

func newInteractiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "interactive",
		Short: "Start an interactive REPL session",
		RunE: func(cmd *cobra.Command, args []string) error {
			printBox("Bastion Vault Interactive REPL", []string{
				"Commands: detect-pii, classify, k-anon, access, quit",
				"Type a command name to begin.",
			})
			scanner := bufio.NewScanner(os.Stdin)
			for {
				fmt.Print("vault> ")
				if !scanner.Scan() {
					break
				}
				line := strings.TrimSpace(scanner.Text())
				switch line {
				case "quit", "exit", "q":
					fmt.Println("Goodbye.")
					return nil
				case "":
					continue
				default:
					fmt.Printf("Unknown command: %q. Try: detect-pii, classify, k-anon, access, quit\n", line)
				}
			}
			return nil
		},
	}
}

// readJSONL reads newline-delimited JSON objects from a file.
func readJSONL(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var records []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("parsing JSONL line: %w", err)
		}
		records = append(records, rec)
	}
	return records, scanner.Err()
}

// printBox renders the SRS-style boxed output with ═══ borders.
func printBox(title string, lines []string) {
	maxWidth := len(title)
	for _, l := range lines {
		if len(l) > maxWidth {
			maxWidth = len(l)
		}
	}
	width := maxWidth + 4

	top := "╔" + strings.Repeat("═", width) + "╗"
	bot := "╚" + strings.Repeat("═", width) + "╝"
	sep := "╠" + strings.Repeat("═", width) + "╣"
	titlePad := "  " + title + strings.Repeat(" ", width-len(title)-2)

	fmt.Println(top)
	fmt.Println("║" + titlePad + "║")
	fmt.Println(sep)
	for _, l := range lines {
		pad := strings.Repeat(" ", width-len(l)-2)
		fmt.Printf("║  %s%s║\n", l, pad)
	}
	fmt.Println(bot)
}

func printKAnonReport(report *model.KAnonymityReport) {
	validStr := "NO"
	if report.Valid {
		validStr = "YES"
	}
	lines := []string{
		fmt.Sprintf("Valid      : %s", validStr),
		fmt.Sprintf("K          : %d", report.K),
		fmt.Sprintf("Required K : %d", report.RequiredK),
		fmt.Sprintf("Violations : %d", len(report.Violations)),
	}
	for _, step := range report.GeneralizationSteps {
		lines = append(lines, fmt.Sprintf("  Generalized %s: %s → %s", step.Field, step.From, step.To))
	}
	printBox("K-Anonymity Report", lines)
}
