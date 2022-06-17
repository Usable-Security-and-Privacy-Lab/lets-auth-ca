package errorHandler

import (
	"fmt"
	"os"
)

// Fatal will automatically exit the calling program, logging the given error.
func Fatal(err error) {
	fmt.Println(err.Error())
	os.Exit(2)
}
