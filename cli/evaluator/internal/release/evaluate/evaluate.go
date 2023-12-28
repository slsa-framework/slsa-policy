package evaluate

import (
	"fmt"
	"os"
)

func usage(cli string) {
	msg := "" +
		"Usage: %s release evaluate orgPath projectsPath packageURI\n" +
		"\n" +
		"Example:\n" +
		"%s release validate ./path/to/policy/org ./path/to/policy/projects laurentsimon/echo-server\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli, cli)
	os.Exit(1)
}

func Run(cli string, args []string) {

}
