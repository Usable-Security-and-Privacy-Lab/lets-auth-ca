package errorHandler

// We should probably look into using a logger. See here for suggestions:
// https://github.com/sirupsen/logrus

import (
	"fmt"
	"os"
)

func Fatal(err error) {
	fmt.Println(err.Error())
	os.Exit(2)
}
