package cmd

import (
	"github.com/SUNET/sunet-cdn-agent/pkg/runner"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the agent",
	Long:  `This is the main mode of running the agent.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		err := runner.Run(agentLogger)
		return err
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// runCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
