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
	RunE: func(cmd *cobra.Command, _ []string) error {
		cacheNode, err := cmd.Flags().GetBool("cache-node")
		if err != nil {
			return err
		}

		l4lbNode, err := cmd.Flags().GetBool("l4lb-node")
		if err != nil {
			return err
		}

		err = runner.Run(agentLogger, cacheNode, l4lbNode)
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

	runCmd.Flags().Bool("cache-node", false, "Handle cache node config")
	runCmd.Flags().Bool("l4lb-node", false, "Handle l4lb node config")
	runCmd.MarkFlagsOneRequired("cache-node", "l4lb-node")
}
