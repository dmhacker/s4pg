package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
    parts int
    threshold int
	rootCmd     = &cobra.Command{
		Use:   "s4pg",
		Short: "Shamir's secret sharing scheme privacy guard",
		Long: `s4pg functions similarily to the ssss program, providing a way
to split a secret into shares, which can then be distributed across a variety
of devices. s4pg can split files of any size and requires password protection
across all shares.`,
	}
	splitCmd = &cobra.Command{
		Use:   "split [secret_file]",
		Args:  cobra.ExactArgs(1),
		Short: "Splits a secret file into separate share files",
		Long: `Reads the secret file, password protects it, and then securely
splits the file into several different shares, each of which is written as a
separate output file. The default share count is 5, and the default threshold is 3.`,
		Run: runSplit,
	}
	combineCmd = &cobra.Command{
		Use:   "combine [share_files...]",
		Args:  cobra.MinimumNArgs(1),
		Short: "Combines separate share files into the original file",
		Long: `Reads all share files, recombines the shares into the password
protected secret, and then, using a user-supplied password, decrypts that into
the original secret and writes it to a file.`,
		Run: runCombine,
	}
)

func runSplit(cmd *cobra.Command, args []string) {
    // TODO: Implement
}

func runCombine(cmd *cobra.Command, args []string) {
    // TODO: Implement
}

func er(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	splitCmd.Flags().IntVarP(&threshold, "threshold", "t", 3, "Minimum shares needed for reconstruction")
	splitCmd.Flags().IntVarP(&parts, "number", "n", 5, "Number of shares to be produced")

	rootCmd.AddCommand(splitCmd)
	rootCmd.AddCommand(combineCmd)

	rootCmd.Execute()
}
