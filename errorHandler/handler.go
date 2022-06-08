package errorHandler

import (
	"fmt"
	"os"
)

func Fatal(err error) {
	fmt.Println(err.Error())
	os.Exit(2)
}
